use std::net::TcpStream;
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_native_certs;
use tokio_rustls::TlsConnector;

/// TLS wrapper for client-side connections using rustls
pub struct TlsWrapper {
    config: Arc<ClientConfig>,
}

impl TlsWrapper {
    /// Create new TLS wrapper with native certificate store
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut root_store = rustls::RootCertStore::empty();
        
        // Load native certificates
        let native_certs = rustls_native_certs::load_native_certs()?;
        for cert in native_certs {
            root_store.add(&rustls::Certificate(cert.0))?;
        }
        
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        Ok(Self {
            config: Arc::new(config),
        })
    }
    
    /// Wrap a TcpStream with TLS for the given server name
    pub fn wrap_stream(&self, stream: TcpStream, server_name: &str) -> Result<TlsStream, Box<dyn std::error::Error>> {
        let server_name = server_name.try_into()?;
        let conn = ClientConnection::new(self.config.clone(), server_name)?;
        let tls_stream = StreamOwned::new(conn, stream);
        
        Ok(TlsStream {
            inner: tls_stream,
        })
    }
    
    /// Get TLS connector for async operations
    pub fn get_connector(&self) -> TlsConnector {
        TlsConnector::from(self.config.clone())
    }
}

/// TLS-wrapped stream for secure communication
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsStream {
    /// Read data from TLS stream
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn std::error::Error>> {
        use std::io::Read;
        Ok(self.inner.read(buf)?)
    }
    
    /// Write data to TLS stream
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        use std::io::Write;
        Ok(self.inner.write(buf)?)
    }
    
    /// Flush the TLS stream
    pub fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        self.inner.flush()?;
        Ok(())
    }
}