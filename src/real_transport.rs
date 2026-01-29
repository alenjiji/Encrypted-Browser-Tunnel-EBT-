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
            .clone();
        
        let client_stream = Arc::new(Mutex::new(client_stream));
        
        // Set TCP_NODELAY on both streams
        if let Ok(tcp) = tcp_stream.lock() {
            tcp.set_nodelay(true).ok();
        }
        if let Ok(client) = client_stream.lock() {
            client.set_nodelay(true).ok();
        }
        
        // client → TCP
        let a = thread::spawn({
            let tcp = Arc::clone(&tcp_stream);
            let client = Arc::clone(&client_stream);
            move || Self::forward_data(client, tcp)
        });
        
        // TCP → client
        let b = thread::spawn({
            let tcp = Arc::clone(&tcp_stream);
            let client = Arc::clone(&client_stream);
            move || Self::forward_data(tcp, client)
        });
        
        // Let threads run independently - don't wait for both
        thread::spawn(move || {
            let _ = a.join();
            let _ = b.join();
        });
        
        Ok(())
    }
    
    /// Forward data from source to destination with TCP half-close support
    fn forward_data(source: Arc<Mutex<TcpStream>>, dest: Arc<Mutex<TcpStream>>) -> Result<(), TransportError> {
        let mut buffer = [0u8; 4096];
        
        loop {
            let bytes_read = {
                let mut src = source.lock().map_err(|_| TransportError::ConnectionFailed)?;
                match src.read(&mut buffer) {
                    Ok(0) => {
                        // Peer closed its write side — this is NORMAL
                        println!("Forward: EOF reached");
                        return Ok(()); // exit THIS direction only
                    }
                    Ok(n) => {
                        let mut dst = dest.lock().map_err(|_| TransportError::ConnectionFailed)?;
                        if let Err(_) = dst.write_all(&buffer[..n]) {
                            return Ok(());
                        }
                        n
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        // Non-fatal: exit this direction, do NOT kill tunnel
                        return Ok(());
                    }
                }
            };
            
            println!("Forward: {} bytes transferred", bytes_read);
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