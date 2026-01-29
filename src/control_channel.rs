use std::io::{Result, Write, Read};

#[cfg(feature = "encrypted_control")]
pub struct ControlChannel {
    key: [u8; 32], // Static key for now
}

#[cfg(feature = "encrypted_control")]
impl ControlChannel {
    pub fn new() -> Self {
        // Static key - in production this would be from key exchange
        let key = [0x42; 32];
        Self { key }
    }
    
    pub fn encrypt_routing_info(&self, target_host: &str, target_port: u16) -> Vec<u8> {
        let plaintext = format!("{}:{}", target_host, target_port);
        let mut encrypted = Vec::new();
        
        // Simple XOR encryption with static key (placeholder)
        for (i, byte) in plaintext.bytes().enumerate() {
            encrypted.push(byte ^ self.key[i % 32]);
        }
        
        encrypted
    }
    
    pub fn send_encrypted_routing(&self, stream: &mut std::net::TcpStream, target_host: &str, target_port: u16) -> Result<()> {
        let encrypted_routing = self.encrypt_routing_info(target_host, target_port);
        
        // Send control message header
        let header = format!("CTRL {} {}\r\n", encrypted_routing.len(), "ROUTE");
        stream.write_all(header.as_bytes())?;
        stream.write_all(&encrypted_routing)?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;
        
        Ok(())
    }
    
    pub fn read_control_response(&self, stream: &mut std::net::TcpStream) -> Result<bool> {
        let mut response = [0u8; 256];
        let mut total_read = 0;
        
        loop {
            let bytes_read = stream.read(&mut response[total_read..])?;
            if bytes_read == 0 {
                return Ok(false);
            }
            total_read += bytes_read;
            
            if total_read >= 2 && &response[total_read-2..total_read] == b"\r\n" {
                break;
            }
        }
        
        let response_str = String::from_utf8_lossy(&response[..total_read]);
        Ok(response_str.starts_with("CTRL OK"))
    }
}