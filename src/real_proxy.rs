// NOTE:
// This proxy currently accepts connections sequentially.
// A multi-connection loop will be added in a follow-up change.

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
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
        } else if request.starts_with("GET ") || request.starts_with("POST ") || request.starts_with("HEAD ") {
            // Handle HTTP request forwarding
            Self::handle_http_request(stream, &request).await?;
        } else {
            // Reject other methods
            let response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
        
        Ok(())
    }
    
    /// Handle HTTP request forwarding (non-CONNECT)
    async fn handle_http_request(mut client_stream: TcpStream, request: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Parse the request line to extract target host and port
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        
        if parts.len() < 2 {
            let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            client_stream.write_all(response.as_bytes())?;
            return Ok(());
        }
        
        let url = parts[1];
        
        // Extract host and port from absolute URL
        let (host, port) = if url.starts_with("http://") {
            let url_part = &url[7..]; // Remove "http://"
            if let Some(slash_pos) = url_part.find('/') {
                let host_part = &url_part[..slash_pos];
                Self::parse_host_port(host_part, 80)
            } else {
                Self::parse_host_port(url_part, 80)
            }
        } else {
            return Err("Only absolute HTTP URLs supported".into());
        };
        
        println!("HTTP request to {}:{}", host, port);
        
        // Connect to target server
        let mut target_stream = TcpStream::connect(format!("{}:{}", host, port))?;
        
        // Forward the original request
        target_stream.write_all(request.as_bytes())?;
        target_stream.flush()?;
        
        // Start bidirectional forwarding
        Self::forward_http_streams(client_stream, target_stream)?;
        
        Ok(())
    }
    
    /// Parse host:port from string, using default port if not specified
    fn parse_host_port(host_part: &str, default_port: u16) -> (String, u16) {
        if let Some(colon_pos) = host_part.rfind(':') {
            let host = host_part[..colon_pos].to_string();
            let port = host_part[colon_pos + 1..].parse::<u16>().unwrap_or(default_port);
            (host, port)
        } else {
            (host_part.to_string(), default_port)
        }
    }
    
    /// Forward data between client and target for HTTP requests
    fn forward_http_streams(client_stream: TcpStream, target_stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let client = Arc::new(Mutex::new(client_stream));
        let target = Arc::new(Mutex::new(target_stream));
        
        // client → target
        let a = thread::spawn({
            let client = Arc::clone(&client);
            let target = Arc::clone(&target);
            move || Self::forward_http_data(client, target)
        });
        
        // target → client
        let b = thread::spawn({
            let client = Arc::clone(&client);
            let target = Arc::clone(&target);
            move || Self::forward_http_data(target, client)
        });
        
        let _ = a.join();
        let _ = b.join();
        
        Ok(())
    }
    
    /// Forward data in one direction for HTTP
    fn forward_http_data(source: Arc<Mutex<TcpStream>>, dest: Arc<Mutex<TcpStream>>) {
        use std::net::Shutdown;
        
        let mut buffer = [0u8; 4096];
        
        loop {
            let bytes_read = {
                let mut src = match source.lock() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                match src.read(&mut buffer) {
                    Ok(0) => {
                        // EOF - shutdown write side of destination
                        if let Ok(dst) = dest.lock() {
                            let _ = dst.shutdown(Shutdown::Write);
                        }
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => break,
                }
            };
            
            {
                let mut dst = match dest.lock() {
                    Ok(d) => d,
                    Err(_) => break,
                };
                if dst.write_all(&buffer[..bytes_read]).is_err() {
                    break;
                }
                if dst.flush().is_err() {
                    break;
                }
            }
        }
    }
}