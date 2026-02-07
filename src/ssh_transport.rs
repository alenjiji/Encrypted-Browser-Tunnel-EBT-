use crate::transport::{EncryptedTransport, TransportError};

/// SSH-based encrypted transport
pub struct SshTransport {
    host: String,
    port: u16,
}

impl SshTransport {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

impl EncryptedTransport for SshTransport {
    async fn establish_connection(&mut self) -> Result<(), TransportError> {
        Err(TransportError::Unimplemented(
            "ssh transport establish_connection",
        ))
    }

    async fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Unimplemented(
            "ssh transport encrypt_data",
        ))
    }

    async fn decrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Unimplemented(
            "ssh transport decrypt_data",
        ))
    }
}
