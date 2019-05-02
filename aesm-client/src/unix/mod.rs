use std::path::Path;
use imp::AesmClient;
pub trait AesmClientExt {
    fn with_path<P: AsRef<Path>>(path: P) -> Self;
}

impl AesmClientExt for crate::AesmClient {
    fn with_path<P: AsRef<Path>>(path: P) -> Self {
        crate::AesmClient {
            inner : AesmClient::with_path(path)
        }
    }
}
