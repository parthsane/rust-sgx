use std::ptr;
use winapi::_core::ffi::c_void;
use winapi::shared::basetsd::UINT32;
use winapi::shared::guiddef::{CLSID, IID};
use winapi::shared::ntdef::HRESULT;
use winapi::shared::minwindef::ULONG;
use winapi::shared::winerror::{S_OK, S_FALSE};
use winapi::um::combaseapi::{CoInitializeEx, CoCreateInstance, CoUninitialize, CLSCTX_ALL};
use winapi::um::objbase::{COINIT_MULTITHREADED, COINIT_DISABLE_OLE1DDE};
pub type AesmErrorT = UINT32;
pub type AesmInterfaceT = _aesm_interface;
pub use error::{AesmError, Error, Result};
use {QuoteResult, QuoteType, QuoteInfo, AesmClient};
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aesm_interface {
    pub vtbl: *mut aesm_interface_vtbl,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct aesm_interface_vtbl {
    pub query_interface: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            riid: *const IID,
            object: *mut *mut ::std::os::raw::c_void,
        ) -> HRESULT,
    >,
    pub add_ref: ::std::option::Option<unsafe extern "system" fn(this: *mut AesmInterfaceT) -> ULONG>,
    pub release: ::std::option::Option<unsafe extern "system" fn(this: *mut AesmInterfaceT) -> ULONG>,
    pub get_license_token: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            mrenclave: *const u8,
            mrenclave_size: u32,
            public_key: *const u8,
            public_key_size: u32,
            se_attributes: *const u8,
            se_attributes_size: u32,
            lictoken: *mut u8,
            lictoken_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub init_quote: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            target_info: *mut u8,
            target_info_size: u32,
            gid: *mut u8,
            gid_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_quote: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
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
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub create_session: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            session_id: *mut u32,
            se_dh_msg1: *mut u8,
            se_dh_msg1_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub exchange_report: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            session_id: u32,
            se_dh_msg2: *mut u8,
            se_dh_msg2_size: u32,
            se_dh_msg3: *mut u8,
            se_dh_msg3_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub close_session: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            session_id: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub invoke_service: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            pse_message_req: *mut u8,
            pse_message_req_size: u32,
            pse_message_resp: *mut u8,
            pse_message_resp_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub report_attestation_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            platform_info: *mut u8,
            platform_info_size: u32,
            attestation_status: u32,
            update_info: *mut u8,
            update_info_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_ps_cap: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            ps_cap: *mut u64,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub sgx_register: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            white_list_cert: *mut u8,
            white_list_cert_size: u32,
            registration_data_type: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub proxy_setting_assist: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            proxy_info: *mut u8,
            proxy_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub query_sgx_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            sgx_status: *mut u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_whitelist_size: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            white_list_size: *mut u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_white_list: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            white_list: *mut u8,
            buf_size: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_sec_domain_id: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            sec_domain_id: *mut u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub switch_sec_domain: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            sec_domain_id: u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_epid_provision_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            epid_pr_status: *mut u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
    pub get_platform_service_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *mut AesmInterfaceT,
            pse_status: *mut u32,
            result: *mut AesmErrorT,
        ) -> HRESULT,
    >,
}

#[cfg(windows)] impl Drop for AesmClient {
    fn drop (&mut self ) {
        unsafe {
            if let Some(release) = (*(*self.interface).vtbl).release {
                release(self.interface);
            }
            CoUninitialize();
        }
    }
}

#[cfg(windows)]
impl AesmClient {
    pub fn new () -> Result<Self> {
        let aesm_client = AesmClient::create_instance()?;
        Ok(aesm_client)
    }

    fn create_instance() -> Result<Self> {
        let mut instance : *mut AesmInterfaceT = std::ptr::null_mut();
        let clsid_aesminterface : CLSID = CLSID {
            Data1: 0x82367CAB,
            Data2: 0xF2B9,
            Data3: 0x461A,
            Data4: [0xB6, 0xC6, 0x88, 0x9D, 0x13, 0xEF, 0xC6, 0xCA]
        };
        let iid_iaesminterface : IID = IID {
            Data1: 0x50AFD900,
            Data2: 0xF309,
            Data3: 0x4557,
            Data4: [0x8F, 0xCB, 0x10, 0xCF, 0xAB, 0x80, 0x2C, 0xDD]
        };
        unsafe {
            let res = CoInitializeEx(
                ptr::null_mut(),
                COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE
            );
            if res != S_OK && res != S_FALSE {
                return Err(Error::AesmBadResponse(("Fail to initialize Com interface").to_string()));
            }
            let res = CoCreateInstance(
                &clsid_aesminterface,
                ptr::null_mut(),
                CLSCTX_ALL,
                &iid_iaesminterface,
                &mut instance as *mut _ as *mut *mut c_void);
            if res < 0 {
                return Err(Error::AesmBadResponse(("Fail to create Aesm Interface").to_string()));
            }
        }
        Ok(AesmClient {
            interface: instance
        })
    }

    pub fn init_quote(&self) -> Result<QuoteInfo> {
        let mut target_info : Vec<u8> = vec![0; sgx_isa::Targetinfo::UNPADDED_SIZE];
        let mut gid: Vec<u8> = vec![0; 4usize];
        let mut error : AesmErrorT = 0;
        unsafe {
            if let Some(init_quote) = (*(*self.interface).vtbl).init_quote {
                let ret = init_quote(
                    self.interface,
                    target_info.as_mut_ptr(),
                    target_info.len() as _,
                    gid.as_mut_ptr(),
                    gid.len() as _,
                    &mut error as _
                );
                if ret < 0 || error!=0 {
                    return Err(Error::AesmCode(error.into()));
                }
            }
        }
        let quote_info : QuoteInfo = QuoteInfo {
            target_info ,
            gid
        };
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
        let nonce : Vec<u8> = vec![0; 64];
        let quote_buffer_size = session.quote_buffer_size(&sig_rl);
        let mut qe_report:Vec<u8> = vec![0; Report::UNPADDED_SIZE as usize];
        let mut quote :Vec<u8> = vec![0; quote_buffer_size as usize];
        let mut error : AesmErrorT = 0;

        unsafe {
            if let Some(get_quote) = (*(*self.interface).vtbl).get_quote {
                let ret = get_quote(
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
                    &mut error as _
                );
                if error != 0 || ret < 0 {
                    return Err(Error::AesmCode(error.into()));
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
        let mut licence_token = vec![0; sgx_isa::Einittoken::UNPADDED_SIZE ];
        let mut error : AesmErrorT = 0;
        unsafe {
            if let Some(get_license_token) = (*(*self.interface).vtbl).get_license_token {
                let ret = get_license_token(
                    self.interface,
                    mr_enclave.as_ptr(),
                    mr_enclave.len() as _,
                    signer_modulus.as_ptr(),
                    signer_modulus.len() as _,
                    attributes.as_ptr(),
                    attributes.len() as _,
                    licence_token.as_mut_ptr(),
                    licence_token.len() as _,
                    &mut error as _
                );
                if ret<0 || error!=0 {
                    return Err(Error::AesmCode(error.into()));
                }
            }
        }
        return Ok(licence_token);
    }
}
