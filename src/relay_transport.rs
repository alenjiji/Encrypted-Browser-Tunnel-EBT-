use std::net::TcpStream;
use std::io::{Result, Write, Read};
#[cfg(feature = "encrypted_control")]
use crate::control_channel::ControlChannel;

pub trait RelayTransport: Send {
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

#[cfg(feature = "multi_hop_relay")]
pub struct MultiHopRelayTransport {
    relay_chain: Vec<(String, u16)>,
    #[cfg(feature = "encrypted_control")]
    control_channel: ControlChannel,
}

#[cfg(feature = "multi_hop_relay")]
impl MultiHopRelayTransport {
    pub fn new(relay_chain: Vec<(String, u16)>) -> Self {
        Self { 
            relay_chain,
            #[cfg(feature = "encrypted_control")]
            control_channel: ControlChannel::new(),
        }
    }
}

#[cfg(feature = "multi_hop_relay")]
impl RelayTransport for MultiHopRelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        if self.relay_chain.is_empty() {
            return TcpStream::connect((target_host, target_port));
        }
        
        // Connect to first relay
        let (first_host, first_port) = &self.relay_chain[0];
        let mut stream = TcpStream::connect((first_host, first_port))?;
        
        // Chain through each relay
        for i in 1..self.relay_chain.len() {
            let (next_host, next_port) = &self.relay_chain[i];
            stream = self.connect_through_relay(stream, next_host, *next_port)?;
        }
        
        // Final connection to target
        self.connect_through_relay(stream, target_host, target_port)
    }
}

#[cfg(feature = "multi_hop_relay")]
impl MultiHopRelayTransport {
    fn connect_through_relay(&self, mut stream: TcpStream, target_host: &str, target_port: u16) -> Result<TcpStream> {
        #[cfg(feature = "encrypted_control")]
        {
            // Send encrypted routing metadata
            self.control_channel.send_encrypted_routing(&mut stream, target_host, target_port)?;
            
            // Wait for control channel acknowledgment
            if !self.control_channel.read_control_response(&mut stream)? {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Control channel failed"));
            }
            return Ok(stream);
        }
        
        #[cfg(not(feature = "encrypted_control"))]
        {
            // Standard CONNECT
            let connect_request = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", target_host, target_port);
            stream.write_all(connect_request.as_bytes())?;
            stream.flush()?;
            
            let mut response = [0u8; 1024];
            let mut total_read = 0;
            
            loop {
                let bytes_read = stream.read(&mut response[total_read..])?;
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
            
            return Ok(stream);
        }
    }
}