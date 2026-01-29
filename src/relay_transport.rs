use std::net::TcpStream;
use std::io::{Result, Write, Read};

pub trait RelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream>;
}

pub struct DirectRelayTransport;

impl RelayTransport for DirectRelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        TcpStream::connect((target_host, target_port))
    }
}

impl Default for DirectRelayTransport {
    fn default() -> Self {
        Self
    }
}

#[cfg(feature = "single_hop_relay")]
pub struct SingleHopRelayTransport {
    relay_host: String,
    relay_port: u16,
}

#[cfg(feature = "single_hop_relay")]
impl SingleHopRelayTransport {
    pub fn new(relay_host: String, relay_port: u16) -> Self {
        Self { relay_host, relay_port }
    }
}

#[cfg(feature = "single_hop_relay")]
impl RelayTransport for SingleHopRelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        // Connect to relay server
        let mut relay_stream = TcpStream::connect((&self.relay_host, self.relay_port))?;
        
        // Send CONNECT request to relay
        let connect_request = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", target_host, target_port);
        relay_stream.write_all(connect_request.as_bytes())?;
        relay_stream.flush()?;
        
        // Read CONNECT response
        let mut response = [0u8; 1024];
        let mut total_read = 0;
        
        loop {
            let bytes_read = relay_stream.read(&mut response[total_read..])?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Relay closed connection"));
            }
            total_read += bytes_read;
            
            if total_read >= 4 && &response[total_read-4..total_read] == b"\r\n\r\n" {
                break;
            }
        }
        
        let response_str = String::from_utf8_lossy(&response[..total_read]);
        if !response_str.starts_with("HTTP/1.1 200") {
            return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Relay CONNECT failed"));
        }
        
        Ok(relay_stream)
    }
}