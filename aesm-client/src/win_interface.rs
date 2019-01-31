use winapi::shared::guiddef::IID;
use winapi::shared::ntdef::HRESULT;
use winapi::shared::minwindef::ULONG;
use winapi::shared::basetsd::UINT32;

pub type aesm_error_t = UINT32;
pub type aesm_interface_t = _aesm_interface;

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
            this: *const aesm_interface_t,
            riid: *const IID,
            object: *mut *mut ::std::os::raw::c_void,
        ) -> HRESULT,
    >,
    pub add_ref: ::std::option::Option<unsafe extern "system" fn(this: *mut aesm_interface_t) -> ULONG>,
    pub release: ::std::option::Option<unsafe extern "system" fn(this: *mut aesm_interface_t) -> ULONG>,
    pub get_license_token: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            mrenclave: *mut u8,
            mrenclave_size: u32,
            public_key: *mut u8,
            public_key_size: u32,
            se_attributes: *mut u8,
            se_attributes_size: u32,
            lictoken: *mut u8,
            lictoken_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub init_quote: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            target_info: *mut u8,
            target_info_size: u32,
            gid: *mut u8,
            gid_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_quote: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            report: *mut u8,
            report_size: u32,
            type_: u32,
            spid: *mut u8,
            spid_size: u32,
            nonce: *mut u8,
            nonce_size: u32,
            sig_rl: *mut u8,
            sig_rl_size: u32,
            qe_report: *mut u8,
            qe_report_size: u32,
            quote: *mut u8,
            buf_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub create_session: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            session_id: *mut u32,
            se_dh_msg1: *mut u8,
            se_dh_msg1_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub exchange_report: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            session_id: u32,
            se_dh_msg2: *mut u8,
            se_dh_msg2_size: u32,
            se_dh_msg3: *mut u8,
            se_dh_msg3_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub close_session: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            session_id: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub invoke_service: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            pse_message_req: *mut u8,
            pse_message_req_size: u32,
            pse_message_resp: *mut u8,
            pse_message_resp_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub report_attestation_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            platform_info: *mut u8,
            platform_info_size: u32,
            attestation_status: u32,
            update_info: *mut u8,
            update_info_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_ps_cap: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            ps_cap: *mut u64,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub sgx_register: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            white_list_cert: *mut u8,
            white_list_cert_size: u32,
            registration_data_type: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub proxy_setting_assist: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            proxy_info: *mut u8,
            proxy_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub query_sgx_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            sgx_status: *mut u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_whitelist_size: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            white_list_size: *mut u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_white_list: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            white_list: *mut u8,
            buf_size: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_sec_domain_id: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            sec_domain_id: *mut u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub switch_sec_domain: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            sec_domain_id: u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_epid_provision_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            epid_pr_status: *mut u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
    pub get_platform_service_status: ::std::option::Option<
        unsafe extern "system" fn(
            this: *const aesm_interface_t,
            pse_status: *mut u32,
            result: *mut aesm_error_t,
        ) -> HRESULT,
    >,
}
