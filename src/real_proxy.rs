// NOTE:
// This proxy currently accepts connections sequentially.
// A multi-connection loop will be added in a follow-up change.

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use crate::config::ProxyPolicy;
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
                let (stream, addr) = listener.accept()?;
                println!("Real proxy accepted connection from {}", addr);
                
                // Handle each connection in a separate task
                // Using spawn_blocking because TcpStream uses blocking I/O.
                // Async I/O can be introduced later without changing proxy semantics.
                task::spawn_blocking(move || {
                    if let Err(e) = Self::handle_connection(stream) {
                        eprintln!("Error handling connection: {}", e);
                    }
                });
            }
        } else {
            Err("Proxy server not bound".into())
        }
    }
    
    /// Handle a single client connection
    fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Read HTTP request
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        
        println!("Real proxy received request: {}", request.lines().next().unwrap_or(""));
        
        // Send simple HTTP response
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nProxy Working";
        stream.write_all(response.as_bytes())?;
        
        println!("Real proxy sent response");
        Ok(())
    }
}