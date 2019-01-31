/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! # Features
//!
//! * `sgxs`. Enable the `sgxs` feature to get an implemention of
//!   `EinittokenProvider` that uses AESM.

extern crate byteorder;
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
#[cfg(feature = "sgxs")]
extern crate sgxs;
#[cfg(unix)]
extern crate unix_socket;
#[cfg(windows)]
extern crate winapi;
use winapi::um::combaseapi::{CoInitializeEx, CoCreateInstance, CoUninitialize, CLSCTX_ALL};
use winapi::shared::winerror::{S_OK, S_FALSE};
use winapi::um::objbase::{COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, COINIT_DISABLE_OLE1DDE};
use winapi::shared::guiddef::{CLSID, IID};
use winapi::_core::ffi::c_void;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::ptr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[cfg(feature = "sgxs")]
use std::result::Result as StdResult;

use byteorder::{LittleEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use protobuf::{Message, ProtobufResult};
#[cfg(unix)]
use unix_socket::UnixStream;

#[cfg(feature = "sgxs")]
use sgxs::einittoken::{Einittoken, EinittokenProvider};
#[cfg(feature = "sgxs")]
use sgxs::sigstruct::{Attributes, Sigstruct};

include!(concat!(env!("OUT_DIR"), "/mod_aesm_proto.rs"));
mod error;
#[cfg(windows)] mod win_interface;
#[cfg(windows)] use win_interface::*;
#[cfg(windows)] extern crate sgx_isa;
use self::aesm_proto::*;
pub use error::{AesmError, Error, Result};

// From SDK aesm_error.h
const AESM_SUCCESS: u32 = 0;

/// This timeout is an argument in AESM request protobufs.
///
/// This value should be used for requests that can be completed locally, i.e.
/// without network interaction.
const LOCAL_AESM_TIMEOUT_US: u32 = 1_000_000;
/// This timeout is an argument in AESM request protobufs.
///
/// This value should be used for requests that might need interaction with
/// remote servers, such as provisioning EPID.
const REMOTE_AESM_TIMEOUT_US: u32 = 30_000_000;

// From SDK sgx_quote.h
#[repr(u32)]
pub enum QuoteType {
    Unlinkable = 0,
    Linkable = 1,
}

impl Into<u32> for QuoteType {
    fn into(self: QuoteType) -> u32 {
        use self::QuoteType::*;
        match self {
            Unlinkable => 0,
            Linkable => 1,
        }
    }
}

impl QuoteType {
    pub fn from_u32(v: u32) -> Result<Self> {
        use self::QuoteType::*;
        Ok(match v {
            0 => Unlinkable,
            1 => Linkable,
            _ => return Err(Error::InvalidQuoteType(v)),
        })
    }
}

#[derive(Debug)]
pub struct QuoteInfo {
    target_info: Vec<u8>,

    /// EPID group ID, big-endian byte order
    gid: Vec<u8>,
}

impl QuoteInfo {
    pub fn target_info(&self) -> &[u8] {
        &self.target_info
    }

    pub fn gid(&self) -> &[u8] {
        &self.gid
    }

    // The value returned here can depend on number of sigrl entries, and
    // possibly other factors. Although why the client needs to pass a length
    // in a protobuf API is beyond me.
    fn quote_buffer_size(&self, sig_rl: &[u8]) -> u32 {
        // Refer to se_quote_internal.h and sgx_quote.h in the Intel SDK.
        let quote_length = 436 + 288 + 12 + 4 + 16;

        // Refer to epid/common/types.h in the Intel SDK.
        // This is the truly correct way to compute sig_length:
        //let nr_proof_length = 160;
        //let sig_length = 352 + 4 + 4 + sig_rl_entries * nr_proof_length;
        // Instead we do something that should be conservative, and doesn't
        // require interpreting the sig_rl structure to determine the entry
        // count. An nr_proof is 5 field elements, a sig_rl entry is four.
        // Add some slop for sig_rl headers.
        let sig_length = 352 + 4 + 4 + (sig_rl.len() as u32 * 5 / 4) + 128;

        quote_length + sig_length
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuoteResult {
    /// For Intel attestatations, the EPID signature from Intel QE.
    quote: Vec<u8>,

    /// SGX report (EREPORT) from the Intel quoting enclave for the quote.
    qe_report: Vec<u8>,
}

impl QuoteResult {
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(quote: T, qe_report: U) -> Self {
        QuoteResult {
            quote: quote.into(),
            qe_report: qe_report.into(),
        }
    }

    pub fn quote(&self) -> &[u8] {
        &self.quote
    }

    pub fn qe_report(&self) -> &[u8] {
        &self.qe_report
    }
}
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct AesmClient {
    interface: *mut aesm_interface_t
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

    // try connect and make lazy
    // remove option
    fn create_instance() -> Result<Self> {
        let mut instance : *mut aesm_interface_t = std::ptr::null_mut();
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
                // raise error;
                //panic!("Fail to initialize Com interface");
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
        //Check if aesm is valid.
        let mut target_info : Vec<u8> = vec![0; sgx_isa::Targetinfo::UNPADDED_SIZE];
        let mut gid: Vec<u8> = vec![0; 4usize];
        let mut error : aesm_error_t = 0;
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
        let mut report_clone = report.clone();
        let mut spid_clone = spid.clone();
        let mut sig_rl = sig_rl.clone();
        let mut nonce : Vec<u8> = vec![0; 64];
        let quote_buffer_size = session.quote_buffer_size(&sig_rl);
        let mut qe_report:Vec<u8> = vec![0; Report::UNPADDED_SIZE as usize];
        let mut quote :Vec<u8> = vec![0; quote_buffer_size as usize];
        let mut error : aesm_error_t = 0;

        unsafe {
            if let Some(get_quote) = (*(*self.interface).vtbl).get_quote {
                let ret = get_quote(
                    self.interface,
                    report_clone.as_mut_ptr(),
                    report_clone.len() as _,
                    QuoteType::Linkable.into(),
                    spid_clone.as_mut_ptr(),
                    spid_clone.len() as _,
                    nonce.as_mut_ptr(),
                    nonce.len() as _,
                    sig_rl.as_mut_ptr(),
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
        let mut mr_enclave_clone = mr_enclave.clone();
        let mut signer_modulus_clone = signer_modulus.clone();
        let mut attributes_clone = attributes.clone();
        let mut licence_token = vec![0; sgx_isa::Einittoken::UNPADDED_SIZE ];
        let mut error : aesm_error_t = 0;
        unsafe {
            if let Some(get_license_token) = (*(*self.interface).vtbl).get_license_token {
                let ret = get_license_token(
                    self.interface,
                    mr_enclave_clone.as_mut_ptr(),
                    mr_enclave_clone.len() as _,
                    signer_modulus_clone.as_mut_ptr(),
                    signer_modulus_clone.len() as _,
                    attributes_clone.as_mut_ptr(),
                    attributes_clone.len() as _,
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

#[cfg(unix)]
#[derive(Default, Debug, Clone)]
pub struct AesmClient {
    path: Option<PathBuf>,
}
#[cfg(unix)]
impl AesmClient {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        AesmClient {
            path: Some(path.as_ref().to_owned()),
        }
    }

    fn open_socket(&self) -> Result<UnixStream> {
        lazy_static! {
            static ref AESM_SOCKET_ABSTRACT_PATH: PathBuf = {
                // This is defined in <linux/un.h>, although if aesm didn't pad
                // its address we wouldn't need to use it here.
                const UNIX_PATH_MAX: usize = 108;

                // The address of the AESM socket is "sgx_aesm_socket_base" followed by
                // enough NULs to pad to UNIX_PATH_MAX (and with a leading NUL to indicate
                // the abstract namespace).
                let mut path = [0; UNIX_PATH_MAX];
                path[1..21].copy_from_slice(b"sgx_aesm_socket_base");
                OsStr::from_bytes(&path).into()
            };
        };
        static AESM_SOCKET_FILE_PATH: &'static str = "/var/run/aesmd/aesm.socket";

        // AESM only accepts one request per connection, so we have to open
        // a fresh socket here.
        let path = if let Some(ref path) = self.path {
            &**path
        } else if Path::new(AESM_SOCKET_FILE_PATH).exists() {
            Path::new(AESM_SOCKET_FILE_PATH)
        } else {
            &**AESM_SOCKET_ABSTRACT_PATH
        };

        Ok(UnixStream::connect(path)?)
    }

    fn transact<T: AesmRequest>(&self, req: T) -> Result<T::Response> {
        let mut sock = self.open_socket()?;

        let req_bytes = req
            .into()
            .write_to_bytes()
            .expect("Failed to serialize protobuf");
        sock.write_u32::<NativeEndian>(req_bytes.len() as u32)?;
        sock.write_all(&req_bytes)?;

        let res_len = sock.read_u32::<NativeEndian>()?;
        let mut res_bytes = vec![0; res_len as usize];
        sock.read_exact(&mut res_bytes)?;

        let res = T::Response::from_response(protobuf::parse_from_bytes(&res_bytes))?;
        Ok(res)
    }

    /// Obtain target info from QE.
    pub fn init_quote(&self) -> Result<QuoteInfo> {
        let mut req = Request_InitQuoteRequest::new();
        req.set_timeout(LOCAL_AESM_TIMEOUT_US);

        let mut res = self.transact(req)?;

        let (target_info, mut gid) = (res.take_targetInfo(), res.take_gid());

        // AESM gives it to us little-endian, we want big-endian for writing into IAS URL with to_hex()
        gid.reverse();

        Ok(QuoteInfo { target_info, gid })
    }

    /// Obtain remote attestation quote from QE.
    pub fn get_quote(
        &self,
        session: &QuoteInfo,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> Result<QuoteResult> {
        let mut req = Request_GetQuoteRequest::new();
        req.set_report(report);
        req.set_quote_type(QuoteType::Linkable.into());
        req.set_spid(spid);
        req.set_nonce(vec![0; 16]); // TODO: caller-supplied nonce
        req.set_buf_size(session.quote_buffer_size(&sig_rl));
        if sig_rl.len() != 0 {
            req.set_sig_rl(sig_rl);
        }
        req.set_qe_report(true);
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        let mut res = self.transact(req)?;

        let (mut quote, qe_report) = (res.take_quote(), res.take_qe_report());

        // AESM allocates a buffer of the size we supplied and returns the whole
        // thing to us, regardless of how much space QE needed. Trim the excess.
        // The signature length is a little endian word at offset 432 in the quote
        // structure. See "QUOTE Structure" in the IAS API Spec.
        let sig_len = (&quote[432..436]).read_u32::<LittleEndian>().unwrap();
        let new_len = 436 + sig_len as usize;
        if quote.len() < new_len {
            // Quote is already too short, should not happen.
            // Probably we are interpreting the quote structure incorrectly.
            return Err(Error::InvalidQuoteSize);
        }
        quote.truncate(new_len);

        Ok(QuoteResult::new(quote, qe_report))
    }

    /// Obtain launch token
    pub fn get_launch_token(
        &self,
        mr_enclave: Vec<u8>,
        signer_modulus: Vec<u8>,
        attributes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut req = Request_GetLaunchTokenRequest::new();
        req.set_mr_enclave(mr_enclave);
        // The field in the request protobuf is called mr_signer, but it wants the modulus.
        req.set_mr_signer(signer_modulus);
        req.set_se_attributes(attributes);
        req.set_timeout(REMOTE_AESM_TIMEOUT_US);

        let mut res = self.transact(req)?;

        let token = res.take_token();

        Ok(token)
    }
}

#[cfg(feature = "sgxs")]
impl EinittokenProvider for AesmClient {
    fn token(
        &mut self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        _retry: bool,
    ) -> StdResult<Einittoken, ::failure::Error> {
        let token = self.get_launch_token(
            sigstruct.enclavehash.to_vec(),
            sigstruct.modulus.to_vec(),
            attributes.as_ref().to_vec(),
        )?;
        Einittoken::try_copy_from(&token).ok_or(Error::InvalidTokenSize.into())
    }

    fn can_retry(&self) -> bool {
        false
    }
}

trait AesmRequest: protobuf::Message + Into<Request> {
    type Response: protobuf::Message + FromResponse;
}

// This could be replaced with TryFrom when stable.
trait FromResponse: Sized {
    fn from_response(res: ProtobufResult<Response>) -> Result<Self>;
}

impl AesmRequest for Request_InitQuoteRequest {
    type Response = Response_InitQuoteResponse;
}

impl From<Request_InitQuoteRequest> for Request {
    fn from(r: Request_InitQuoteRequest) -> Request {
        let mut req = Request::new();
        req.set_initQuoteReq(r);
        req
    }
}

impl FromResponse for Response_InitQuoteResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_initQuoteRes() => {
                let body = res.take_initQuoteRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("InitQuoteResponse")),
        }
    }
}

impl AesmRequest for Request_GetQuoteRequest {
    type Response = Response_GetQuoteResponse;
}

impl From<Request_GetQuoteRequest> for Request {
    fn from(r: Request_GetQuoteRequest) -> Request {
        let mut req = Request::new();
        req.set_getQuoteReq(r);
        req
    }
}

impl FromResponse for Response_GetQuoteResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_getQuoteRes() => {
                let body = res.take_getQuoteRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("GetQuoteResponse")),
        }
    }
}

impl AesmRequest for Request_GetLaunchTokenRequest {
    type Response = Response_GetLaunchTokenResponse;
}

impl From<Request_GetLaunchTokenRequest> for Request {
    fn from(r: Request_GetLaunchTokenRequest) -> Request {
        let mut req = Request::new();
        req.set_getLicTokenReq(r);
        req
    }
}

impl FromResponse for Response_GetLaunchTokenResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_getLicTokenRes() => {
                let body = res.take_getLicTokenRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("GetLaunchTokenResponse")),
        }
    }
}

#[cfg(test)]
mod tests {
    // These tests require that aesmd is running and correctly configured.
    extern crate sgx_isa;

    use self::sgx_isa::{Report, Targetinfo};
    use super::*;

    const SPID_SIZE: usize = 16;

    #[test]
    fn test_init_quote() {
        let quote = AesmClient::new().init_quote().unwrap();
        assert_eq!(
            quote.target_info().len(),
            ::std::mem::size_of::<Targetinfo>()
        );
        assert!(quote.gid().len() != 0);
    }

    #[test]
    fn test_get_quote() {
        // Doing a meaningful test of this requires creating an enclave, this is
        // just a simple test that we can send a bogus request and get an error
        // back. The node attest flow in testsetup.sh exercises the real case.
        let client = AesmClient::new();

        let quote = client.init_quote().unwrap();

        let quote = client
            .get_quote(
                &quote,
                vec![0u8; Report::UNPADDED_SIZE],
                vec![0u8; SPID_SIZE],
                vec![],
            )
            .unwrap_err();

        assert!(if let Error::AesmCode(_) = quote {
            true
        } else {
            false
        });
    }
}
