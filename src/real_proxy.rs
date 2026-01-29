// NOTE:
// This proxy currently accepts connections sequentially.
// A multi-connection loop will be added in a follow-up change.

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use crate::config::ProxyPolicy;
use crate::real_transport::DirectTcpTunnelTransport;
use crate::transport::EncryptedTransport;
use tokio::task;

/// Real proxy server that binds to network interfaces
pub struct RealProxyServer {
    policy: ProxyPolicy,
    listener: Option<TcpListener>,
}

impl RealProxyServer {
    pub fn new(policy: ProxyPolicy) -> Self {
        Self {
            policy,
            listener: None,
        }
    }
    
    /// Bind to the configured address and port
    pub fn bind(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.policy.bind_address, self.policy.bind_port);
        println!("Real proxy binding to {}", bind_addr);
        
        let listener = TcpListener::bind(&bind_addr)?;
        self.listener = Some(listener);
        
        println!("Real proxy server bound to {}", bind_addr);
        Ok(())
    }
    
    /// Accept multiple connections concurrently
    pub async fn accept_connections(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref listener) = self.listener {
            println!("Real proxy waiting for connections...");
            
            loop {
                // Handle each connection in a separate task
                let (stream, addr) = listener.accept()?;
                println!("Real proxy accepted connection from {}", addr);
                
                task::spawn(async move {
                    if let Err(e) = Self::handle_connection(stream).await {
                        eprintln!("Error handling connection: {}", e);
                    }
                });
            }
        } else {
            Err("Proxy server not bound".into())
        }
    }
    
    /// Handle a single client connection
    async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Read HTTP request
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        
        println!("Real proxy received request: {}", request.lines().next().unwrap_or(""));
        
        if request.starts_with("CONNECT ") {
            // Parse CONNECT target from request line
            let first_line = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            let (host, port) = if parts.len() >= 2 {
                let target = parts[1];
                if let Some(colon_pos) = target.rfind(':') {
                    let host = target[..colon_pos].to_string();
                    let port = target[colon_pos + 1..].parse::<u16>().unwrap_or(443);
                    (host, port)
                } else {
                    (target.to_string(), 443u16)
                }
            } else {
                ("unknown".to_string(), 443u16)
            };
            
            // Handle CONNECT request for HTTPS tunneling
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
            
            println!("CONNECT accepted, delegating to encrypted transport");
            
            // Create transport for this specific CONNECT target
            let mut transport = DirectTcpTunnelTransport::new(
                host.clone(),
                port
            )?;
            
            // Establish connection to target
            if let Err(e) = transport.establish_connection().await {
                eprintln!("Failed to establish connection to {}:{} - {}", host, port, e);
                return Err(e.into());
            }
            
            // Start encrypted forwarding using transport
            transport.start_forwarding(stream)?;
        } else {
            // Reject non-CONNECT requests
            let response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
        
        Ok(())
    }
}