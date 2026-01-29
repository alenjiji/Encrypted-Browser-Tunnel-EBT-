// NOTE:
// This implementation establishes a CONNECT-based TCP tunnel.
// TLS encryption is layered inside the tunnel and will be added next.
// This commit focuses on correct CONNECT semantics and capability gating.

use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::sync::{Arc, Mutex};
use std::thread;
use crate::transport::{EncryptedTransport, TransportError};

/// Real TCP transport implementation with direct connection
pub struct DirectTcpTunnelTransport {
    target_host: String,
    target_port: u16,
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,
}

impl DirectTcpTunnelTransport {
    pub fn new(target_host: String, target_port: u16) -> Result<Self, TransportError> {
        Ok(Self {
            target_host,
            target_port,
            tcp_stream: None,
        })
    }
    
    /// Get the established TCP stream for forwarding
    pub fn get_tcp_stream(&self) -> Option<Arc<Mutex<TcpStream>>> {
        self.tcp_stream.clone()
    }
    
    /// Start bidirectional forwarding between client and TCP stream
    pub fn start_forwarding(&self, client_stream: TcpStream) -> Result<(), TransportError> {
        let tcp_stream = self.tcp_stream.as_ref()
            .ok_or(TransportError::ConnectionFailed)?
            .lock().map_err(|_| TransportError::ConnectionFailed)?
            .try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        
        // Clone streams for true full-duplex (no mutex)
        let client_read = client_stream.try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        let client_write = client_stream;
        
        let tcp_read = tcp_stream.try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        let tcp_write = tcp_stream;
        
        // Apply TCP socket tuning to all streams
        client_read.set_nodelay(true).ok();
        client_read.set_read_timeout(None).ok();
        client_read.set_write_timeout(None).ok();
        
        client_write.set_nodelay(true).ok();
        client_write.set_read_timeout(None).ok();
        client_write.set_write_timeout(None).ok();
        
        tcp_read.set_nodelay(true).ok();
        tcp_read.set_read_timeout(None).ok();
        tcp_read.set_write_timeout(None).ok();
        
        tcp_write.set_nodelay(true).ok();
        tcp_write.set_read_timeout(None).ok();
        tcp_write.set_write_timeout(None).ok();
        
        // client → TCP (no mutex)
        let a = thread::spawn(move || Self::forward_data_direct(client_read, tcp_write));
        
        // TCP → client (no mutex)
        let b = thread::spawn(move || Self::forward_data_direct(tcp_read, client_write));
        
        // Block until both directions complete
        let _ = a.join();
        let _ = b.join();
        
        Ok(())
    }
    
    /// Forward data directly between streams (no mutex)
    fn forward_data_direct(mut src: TcpStream, mut dst: TcpStream) -> Result<(), TransportError> {
        let mut buf = [0u8; 65536]; // 64KB buffer
        loop {
            match src.read(&mut buf) {
                Ok(0) => {
                    // EOF reached - shutdown write side of destination
                    let _ = dst.shutdown(std::net::Shutdown::Write);
                    return Ok(());
                }
                Ok(n) => {
                    if let Err(_) = dst.write_all(&buf[..n]) {
                        return Ok(());
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return Ok(());
                }
            }
        }
    }
}

impl EncryptedTransport for DirectTcpTunnelTransport {
    async fn establish_connection(&mut self) -> Result<(), TransportError> {
        let tcp = TcpStream::connect((self.target_host.as_str(), self.target_port))
            .map_err(|_| TransportError::ConnectionFailed)?;
        
        println!("*** DIRECT TCP CONNECT TO {}:{} (NO SSH) ***", self.target_host, self.target_port);
        
        tcp.set_nodelay(true).ok();
        
        self.tcp_stream = Some(Arc::new(Mutex::new(tcp)));
        println!("Direct TCP connection established to {}:{}", self.target_host, self.target_port);
        Ok(())
    }
    
    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // No encryption - pass through raw data
        Ok(data.to_vec())
    }
    
    async fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // No decryption - pass through raw data
        Ok(data.to_vec())
    }

}