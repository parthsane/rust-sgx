use std::{mem, ptr};
use std::sync::Arc;
use std::io::{Error as IoError, Result as IoResult, ErrorKind};
use winapi::um::memoryapi::{VirtualFree, VirtualProtect};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{HANDLE, ENCLAVE_INIT_INFO_SGX, MEM_RELEASE, PAGE_ENCLAVE_THREAD_CONTROL, PAGE_ENCLAVE_UNVALIDATED,
                        PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, ENCLAVE_TYPE_SGX};
use winapi::um::enclaveapi::{CreateEnclave, InitializeEnclave, IsEnclaveTypeSupported, LoadEnclaveData};
use winapi::_core::ffi::c_void;
use abi::{Attributes, Einittoken, ErrorCode, Miscselect, PageType, SecinfoFlags, Secs, Sigstruct};
use sgxs_crate::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};
use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use generic::{self, EinittokenError, EnclaveLoad, Mapping};
use crate::{MappingInfo, Tcs};

#[derive(Fail, Debug)]
pub enum SgxIoctlError {
    #[fail(display = "I/O ctl failed.")]
    Io(#[cause] IoError),
    #[fail(display = "The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to call CreateEnclave.")]
    Create(#[cause] IoError),
    #[fail(display = "Failed to call LoadEnclaveData.")]
    Add(#[cause] IoError),
    #[fail(display = "Failed to call InitializeEnclave.")]
    Init(#[cause] SgxIoctlError),
}

impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        use self::Error::Init;
        use self::SgxIoctlError::Ret;
        match self {
            &Init(Ret(ErrorCode::InvalidEinitToken)) |
            &Init(Ret(ErrorCode::InvalidCpusvn)) |
            &Init(Ret(ErrorCode::InvalidAttribute)) | // InvalidEinitAttribute according to PR, but does not exist.
            &Init(Ret(ErrorCode::InvalidMeasurement)) => true,
            _ => false,
        }
    }
}

impl EnclaveLoad for WinInnerLibrary {
    type Error = Error;

    fn new(
        device: Arc<WinInnerLibrary>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let secs = Secs {
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };

        let curhandle: HANDLE = unsafe {GetCurrentProcess()};
        let base = unsafe {
            CreateEnclave(
                curhandle,
                ptr::null_mut(),
                ecreate.size as _,
                0,
                ENCLAVE_TYPE_SGX,
                &secs as *const _ as *const c_void,
                mem::size_of::<Secs>() as _,
                ptr::null_mut()
            )
        };

        if base.is_null() {
            Err(Error::Create(IoError::last_os_error()))
        } else {
            Ok(Mapping {
                device,
                tcss: vec![],
                base: base as _,
                size: ecreate.size,
            })
        }
    }
    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {

        let (eadd, chunks, data) = page;

        if eadd
            .secinfo
            .flags
            .intersects(SecinfoFlags::PENDING | SecinfoFlags::MODIFIED | SecinfoFlags::PR)
        {
            return Err(Error::Add(ErrorKind::InvalidInput.into()));
        }
        let mut flags : winapi::shared::minwindef::DWORD = 0;
        match (eadd.secinfo.flags & (SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X)).bits() as u8 {
            0b000 => {},
            0b001 => flags = PAGE_READONLY,
            0b010 => {return Err(Error::Add(ErrorKind::InvalidInput.into()))},
            0b011 => flags = PAGE_READWRITE,
            0b100 => flags = PAGE_EXECUTE,
            0b101 => flags = PAGE_EXECUTE_READ,
            0b110 => {return Err(Error::Add(ErrorKind::InvalidInput.into()))},
            0b111 => flags = PAGE_EXECUTE_READWRITE,
            0b1000...255 => unreachable!(),
        }

        match PageType::from_repr(eadd.secinfo.flags.page_type()) {
            Some(PageType::Reg) => {}
            Some(PageType::Tcs) => {
                if eadd.secinfo.flags.contains(SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X) {
                    return Err(Error::Add(ErrorKind::InvalidInput.into()))
                }
                // NOTE: For some reason the windows API needs the Read flag set but then removes it
                flags = PAGE_ENCLAVE_THREAD_CONTROL|PAGE_READWRITE;
            },
            _ => return Err(Error::Add(ErrorKind::InvalidInput.into())),
        }
        match chunks.0 {
            0 => flags = flags | PAGE_ENCLAVE_UNVALIDATED,
            0xffff => {}
            _ => return Err(Error::Add(ErrorKind::InvalidInput.into())),
        }
        unsafe {
            let mut data_loaded : usize = 0;
            let curhandle: HANDLE = GetCurrentProcess();
            let ret = LoadEnclaveData(
                curhandle,
                (mapping.base + eadd.offset) as _,

                data.as_ptr() as  *const c_void,
                data.len(),
                flags,
                ptr::null(),
                0,
                &mut data_loaded,
                ptr::null_mut()
            );
            if ret == 0 {
                return Err(Error::Add(IoError::last_os_error()));
            }
            assert_eq!(data_loaded, data.len());
        }
        Ok(())
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        let mut init_info : ENCLAVE_INIT_INFO_SGX = ENCLAVE_INIT_INFO_SGX {
            SigStruct : [0 ; 1808],
            Reserved1 : [0 ; 240],
            EInitToken: [0 ; 304],
            Reserved2 : [0 ; 1744],
        };
        init_info.SigStruct.clone_from_slice(&sigstruct.as_ref());
        if let Some(e) = einittoken {
            init_info.EInitToken.clone_from_slice(e.as_ref());
        }
        unsafe {
            let mut error = 0;
            let curhandle: HANDLE = GetCurrentProcess();
            if InitializeEnclave(
                curhandle,
                mapping.base as _,
                &init_info as *const _ as *const c_void,
                mem::size_of::<ENCLAVE_INIT_INFO_SGX>() as _,
                &mut error
            ) == 0 {
                if let Some(e) = ErrorCode::from_repr(error) {
                    return Err(Error::Init(SgxIoctlError::Ret(e)));
                }
            }

            Ok(())
        }
    }
    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe {
            // This returns a boolean
            // Need to do error checking using boolean
            if VirtualFree(
                mapping.base  as _,
                0,
                MEM_RELEASE
            ) == 0 {
                panic!("Failed to destroy enclave: {}", IoError::last_os_error())
            }
        }
    }
}

#[derive(Debug)]
struct WinInnerLibrary {}

#[derive(Debug)]
pub struct Sgx {
    inner: generic::Device<WinInnerLibrary>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<WinInnerLibrary>,
}

impl Sgx {
    pub fn open() -> IoResult<DeviceBuilder> {
        let issupported = unsafe {IsEnclaveTypeSupported(ENCLAVE_TYPE_SGX)};
        if issupported == 0 {
            return Err(IoError::last_os_error());
        }

        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(WinInnerLibrary {}),
                    einittoken_provider: None,
                },
            },
        })
    }
}

impl loader::Load for Sgx {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}

impl DeviceBuilder {
    pub fn einittoken_provider<P: Into<Box<EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Sgx {
        Sgx {
            inner: self.inner.build(),
        }
    }
}
