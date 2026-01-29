use crate::transport::{EncryptedTransport, TransportError};

/// Test-only transport that always fails connection establishment
pub struct FailingTransport;

impl EncryptedTransport for FailingTransport {
    async fn establish_connection(&self) -> Result<(), TransportError> {
        println!("Simulating transport connection failure");
        Err(TransportError::ConnectionFailed)
    }
    
    async fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::EncryptionFailed)
    }
    
    async fn decrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::DecryptionFailed)
    }
}