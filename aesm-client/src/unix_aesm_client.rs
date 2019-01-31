use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use unix_socket::UnixStream;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use protobuf::Message;
use byteorder::{LittleEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use {Request_GetLaunchTokenRequest, Request_GetQuoteRequest, Request_InitQuoteRequest};
pub use error::{AesmError, Error, Result};
use {QuoteResult, QuoteType, QuoteInfo, AesmClient, AesmRequest, FromResponse};

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
