use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ptr;

use winapi::_core::ffi::c_void;
use winapi::shared::basetsd::UINT32;
use winapi::shared::guiddef::{CLSID, IID};
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::HRESULT;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL};
use winapi::um::objbase::{COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED};

use error::{Error, Result};
use {QuoteInfo, QuoteResult, QuoteType};

type AesmError = UINT32;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct AesmInterface {
    vtbl: *mut AesmInterfaceVtbl,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AesmInterfaceVtbl {
    query_interface: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            riid: *const IID,
            object: *mut *mut ::std::os::raw::c_void,
        ) -> HRESULT,
    >,
    add_ref: Option<unsafe extern "system" fn(this: *mut AesmInterface) -> ULONG>,
    release: Option<unsafe extern "system" fn(this: *mut AesmInterface) -> ULONG>,
    get_license_token: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            mrenclave: *const u8,
            mrenclave_size: u32,
            public_key: *const u8,
            public_key_size: u32,
            se_attributes: *const u8,
            se_attributes_size: u32,
            lictoken: *mut u8,
            lictoken_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    init_quote: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            target_info: *mut u8,
            target_info_size: u32,
            gid: *mut u8,
            gid_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_quote: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            report: *const u8,
            report_size: u32,
            type_: u32,
            spid: *const u8,
            spid_size: u32,
            nonce: *const u8,
            nonce_size: u32,
            sig_rl: *const u8,
            sig_rl_size: u32,
            qe_report: *mut u8,
            qe_report_size: u32,
            quote: *mut u8,
            buf_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    create_session: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            session_id: *mut u32,
            se_dh_msg1: *mut u8,
            se_dh_msg1_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    exchange_report: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            session_id: u32,
            se_dh_msg2: *mut u8,
            se_dh_msg2_size: u32,
            se_dh_msg3: *mut u8,
            se_dh_msg3_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    close_session: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            session_id: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    invoke_service: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            pse_message_req: *mut u8,
            pse_message_req_size: u32,
            pse_message_resp: *mut u8,
            pse_message_resp_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    report_attestation_status: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            platform_info: *mut u8,
            platform_info_size: u32,
            attestation_status: u32,
            update_info: *mut u8,
            update_info_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_ps_cap: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            ps_cap: *mut u64,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    sgx_register: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            white_list_cert: *mut u8,
            white_list_cert_size: u32,
            registration_data_type: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    proxy_setting_assist: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            proxy_info: *mut u8,
            proxy_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    query_sgx_status: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            sgx_status: *mut u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_whitelist_size: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            white_list_size: *mut u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_white_list: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            white_list: *mut u8,
            buf_size: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_sec_domain_id: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            sec_domain_id: *mut u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    switch_sec_domain: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            sec_domain_id: u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_epid_provision_status: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            epid_pr_status: *mut u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
    get_platform_service_status: Option<
        unsafe extern "system" fn(
            this: *mut AesmInterface,
            pse_status: *mut u32,
            result: *mut AesmError,
        ) -> HRESULT,
    >,
}

const CLSID_AESMINTERFACE: CLSID = CLSID {
    Data1: 0x82367CAB,
    Data2: 0xF2B9,
    Data3: 0x461A,
    Data4: [0xB6, 0xC6, 0x88, 0x9D, 0x13, 0xEF, 0xC6, 0xCA],
};
const IID_IAESMINTERFACE: IID = IID {
    Data1: 0x50AFD900,
    Data2: 0xF309,
    Data3: 0x4557,
    Data4: [0x8F, 0xCB, 0x10, 0xCF, 0xAB, 0x80, 0x2C, 0xDD],
};

trait HresultExt:Sized {
    fn into_io_error(self) -> IoResult<Self>;
}

impl HresultExt for HRESULT {
    fn into_io_error(self) -> IoResult<HRESULT> {
        if SUCCEEDED(self) {
            Ok(self)
        } else {
            Err(IoError::from_raw_os_error(self))
        }
    }
}

#[derive(Debug, Clone)]
pub struct AesmClient {
    interface: *mut AesmInterface,
}

impl Drop for AesmClient {
    fn drop(&mut self) {
        unsafe {
            if let Some(release) = (*(*self.interface).vtbl).release {
                release(self.interface);
            }
            CoUninitialize();
        }
    }
}

impl AesmClient {
    pub fn new() -> Result<Self> {
        AesmClient::create_instance()
    }

    fn initialize_com() -> Result<HRESULT> {
        unsafe {
            CoInitializeEx(
                ptr::null_mut(),
                COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE,
            )
                .into_io_error()
                .map_err(|e| IoError::new(ErrorKind::Other, format!("Failed to initialize COM: {}", e)))?
        }
    }

    pub fn try_connect(&self) -> Result<()> {
        initialize_com().map(|_| ())
    }

    fn create_instance() -> Result<Self> {
        let mut instance: *mut AesmInterface = std::ptr::null_mut();
        unsafe {
            initialize_com()?;

            CoCreateInstance(
                &CLSID_AESMINTERFACE,
                ptr::null_mut(),
                CLSCTX_ALL,
                &IID_IAESMINTERFACE,
                &mut instance as *mut _ as *mut *mut c_void,
            )
                .into_io_error()
                .map_err(|e|
                    IoError::new(ErrorKind::Other, format!("Fail to create Aesm Interface {}", e)) )?;
        }
        Ok(AesmClient {
            interface: instance,
        })
    }

    pub fn init_quote(&self) -> Result<QuoteInfo> {
        let mut target_info: Vec<u8> = vec![0; sgx_isa::Targetinfo::UNPADDED_SIZE];
        let mut gid: Vec<u8> = vec![0; 4];
        let mut error: AesmError = 0;
        unsafe {
            if let Some(init_quote) = (*(*self.interface).vtbl).init_quote {
                init_quote(
                    self.interface,
                    target_info.as_mut_ptr(),
                    target_info.len() as _,
                    gid.as_mut_ptr(),
                    gid.len() as _,
                    &mut error as _,
                ).into_io_error().
                    map_err(|e| IoError::new(ErrorKind::Other,
                                             format!("Fail to init Quote. init_quote returned {}", e)) )?;
                if error != 0 {
                    return Err(Error::AesmCommunication(IoError::new(ErrorKind::Other,
                                             format!("Fail to init Quote with error {}", error))));
                }
            }
        }
        let quote_info: QuoteInfo = QuoteInfo { target_info, gid };
        return Ok(quote_info);
    }

    pub fn get_quote(
        &self,
        session: &QuoteInfo,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> Result<QuoteResult> {
        use sgx_isa::Report;
        let nonce = [0u8; 64];
        let quote_buffer_size = session.quote_buffer_size(&sig_rl);
        let mut qe_report: Vec<u8> = vec![0; Report::UNPADDED_SIZE];
        let mut quote: Vec<u8> = vec![0; quote_buffer_size as usize];
        let mut error: AesmError = 0;

        unsafe {
            if let Some(get_quote) = (*(*self.interface).vtbl).get_quote {
                get_quote(
                    self.interface,
                    report.as_ptr(),
                    report.len() as _,
                    QuoteType::Linkable.into(),
                    spid.as_ptr(),
                    spid.len() as _,
                    nonce.as_ptr(),
                    nonce.len() as _,
                    sig_rl.as_ptr(),
                    sig_rl.len() as _,
                    qe_report.as_mut_ptr(),
                    qe_report.len() as _,
                    quote.as_mut_ptr(),
                    quote_buffer_size,
                    &mut error as _,
                ).into_io_error().
                    map_err(|e| IoError::new(ErrorKind::Other,
                                             format!("Fail to get Quote. get_quote returned {}", e)) )?;
                if error != 0 {
                    return Err(Error::AesmCommunication(IoError::new(ErrorKind::Other,
                                        format!("Fail to get Quote with error {}", error))));
                }
            }
        }
        return Ok(QuoteResult::new(quote, qe_report));
    }
    pub fn get_launch_token(
        &self,
        mr_enclave: Vec<u8>,
        signer_modulus: Vec<u8>,
        attributes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut licence_token = vec![0; sgx_isa::Einittoken::UNPADDED_SIZE];
        let mut error: AesmError = 0;
        unsafe {
            if let Some(get_license_token) = (*(*self.interface).vtbl).get_license_token {
                get_license_token(
                    self.interface,
                    mr_enclave.as_ptr(),
                    mr_enclave.len() as _,
                    signer_modulus.as_ptr(),
                    signer_modulus.len() as _,
                    attributes.as_ptr(),
                    attributes.len() as _,
                    licence_token.as_mut_ptr(),
                    licence_token.len() as _,
                    &mut error as _,
                ).into_io_error().
                    map_err(|e| IoError::new(ErrorKind::Other,
                                             format!("Fail to get Launch Token. get_launch_token returned {}", e)) )?;
                if error != 0 {
                    return Err(Error::AesmCommunication(IoError::new(ErrorKind::Other,
                                        format!("Fail to get launch token with error {}", error))));
                }
            }
        }
        return Ok(licence_token);
    }
}
