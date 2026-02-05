use std::net::IpAddr;
use std::io::Result;
use socket2::{Socket, TcpKeepalive};
use std::time::Duration;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
#[cfg(feature = "encrypted_control")]
use crate::control_channel::ControlChannel;

#[async_trait]
pub trait RelayTransport: Send {
    async fn establish_relay_connection(
        &mut self,
        target_ip: IpAddr,
        target_port: u16,
    ) -> Result<tokio::net::TcpStream>;
}

pub struct DirectRelayTransport;

#[async_trait]
impl RelayTransport for DirectRelayTransport {
    async fn establish_relay_connection(
        &mut self,
        target_ip: IpAddr,
        target_port: u16,
    ) -> Result<tokio::net::TcpStream> {
        let addr = (target_ip, target_port);
        
        // Use shorter timeout for cold-start stability
        let stream = timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr)
        ).await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout"))?;
        
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // Ensure failed connections are properly cleaned up
                return Err(std::io::Error::new(e.kind(), format!("Connection to {}:{} failed: {}", target_ip, target_port, e)));
            }
        };
        
        stream.set_nodelay(true)?;
        
        let socket = Socket::from(stream.into_std()?);
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10))
        )?;
        
        Ok(tokio::net::TcpStream::from_std(socket.into())?)
    }
}

impl Default for DirectRelayTransport {
    fn default() -> Self {
        Self
    }
}

#[cfg(feature = "single_hop_relay")]
pub struct SingleHopRelayTransport {
    relay_ip: IpAddr,
    relay_port: u16,
}

#[cfg(feature = "single_hop_relay")]
impl SingleHopRelayTransport {
    pub fn new(relay_ip: IpAddr, relay_port: u16) -> Self {
        Self { relay_ip, relay_port }
    }
}

#[cfg(feature = "single_hop_relay")]
#[async_trait]
impl RelayTransport for SingleHopRelayTransport {
    async fn establish_relay_connection(
        &mut self,
        target_ip: IpAddr,
        target_port: u16,
    ) -> Result<tokio::net::TcpStream> {
        let addr = (self.relay_ip, self.relay_port);
        
        let stream = timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr)
        ).await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout"))??;
        
        stream.set_nodelay(true)?;
        
        let socket = Socket::from(stream.into_std()?);
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10))
        )?;
        
        let mut relay_stream = tokio::net::TcpStream::from_std(socket.into())?;
        
        // Send CONNECT request to relay
        let connect_request = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", target_ip, target_port);
        relay_stream.write_all(connect_request.as_bytes()).await?;
        
        // Read CONNECT response
        let mut response = [0u8; 1024];
        let mut total_read = 0;
        
        loop {
            let bytes_read = relay_stream.read(&mut response[total_read..]).await?;
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
    relay_chain: Vec<(IpAddr, u16)>,
    #[cfg(feature = "encrypted_control")]
    control_channel: ControlChannel,
}

#[cfg(feature = "multi_hop_relay")]
impl MultiHopRelayTransport {
    pub fn new(relay_chain: Vec<(IpAddr, u16)>) -> Self {
        Self { 
            relay_chain,
            #[cfg(feature = "encrypted_control")]
            control_channel: ControlChannel::new(),
        }
    }
}

#[cfg(feature = "multi_hop_relay")]
#[async_trait]
impl RelayTransport for MultiHopRelayTransport {
    async fn establish_relay_connection(
        &mut self,
        target_ip: IpAddr,
        target_port: u16,
    ) -> Result<tokio::net::TcpStream> {
        if self.relay_chain.is_empty() {
            let addr = (target_ip, target_port);
            
            let stream = timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr)
            ).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout"))??;
            
            stream.set_nodelay(true)?;
            
            let socket = Socket::from(stream.into_std()?);
            socket.set_tcp_keepalive(
                &TcpKeepalive::new()
                    .with_time(Duration::from_secs(30))
                    .with_interval(Duration::from_secs(10))
            )?;
            
            return Ok(tokio::net::TcpStream::from_std(socket.into())?);
        }
        
        // Connect to first relay
        let (first_ip, first_port) = &self.relay_chain[0];
        let addr = (*first_ip, *first_port);
        
        let stream = timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr)
        ).await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout"))??;
        
        stream.set_nodelay(true)?;
        
        let socket = Socket::from(stream.into_std()?);
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10))
        )?;
        
        let mut stream = tokio::net::TcpStream::from_std(socket.into())?;
        
        // Chain through each relay
        for i in 1..self.relay_chain.len() {
            let (next_ip, next_port) = &self.relay_chain[i];
            stream = self.connect_through_relay(stream, *next_ip, *next_port).await?;
        }
        
        // Final connection to target
        self.connect_through_relay(stream, target_ip, target_port).await
    }
}

#[cfg(feature = "multi_hop_relay")]
impl MultiHopRelayTransport {
    async fn connect_through_relay(&self, mut stream: tokio::net::TcpStream, target_ip: IpAddr, target_port: u16) -> Result<tokio::net::TcpStream> {
        #[cfg(feature = "encrypted_control")]
        {
            // Send encrypted routing metadata
            self.control_channel.send_encrypted_routing(&mut stream, &target_ip.to_string(), target_port).await?;
            
            // Wait for control channel acknowledgment
            if !self.control_channel.read_control_response(&mut stream).await? {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Control channel failed"));
            }
            return Ok(stream);
        }
        
        #[cfg(not(feature = "encrypted_control"))]
        {
            // Standard CONNECT
            let connect_request = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", target_ip, target_port);
            stream.write_all(connect_request.as_bytes()).await?;
            
            let mut response = [0u8; 1024];
            let mut total_read = 0;
            
            loop {
                let bytes_read = stream.read(&mut response[total_read..]).await?;
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