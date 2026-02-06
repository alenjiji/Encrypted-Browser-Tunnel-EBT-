// NOTE:
// This proxy currently accepts connections sequentially.
// A multi-connection loop will be added in a follow-up change.

use std::net::{TcpListener as StdTcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use crate::config::ProxyPolicy;
use crate::real_transport::DirectTcpTunnelTransport;
use crate::transport::EncryptedTransport;
use crate::logging::LogLevel;
use crate::log;
use crate::core::observability;
use tokio::task;
use tokio::sync::Semaphore;
use tokio::net::TcpListener;

lazy_static::lazy_static! {
    // Restore higher global concurrency for asset-heavy sites
    static ref TUNNEL_SEMAPHORE: Arc<Semaphore> = Arc::new(Semaphore::new(256));
}

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
        
        let std_listener = StdTcpListener::bind(&bind_addr)?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        self.listener = Some(listener);
        
        println!("Real proxy server bound to {}", bind_addr);
        Ok(())
    }
    
    /// Accept multiple connections concurrently
    pub async fn accept_connections(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref listener) = self.listener {
            log!(LogLevel::Info, "Proxy server ready for connections");
            
            loop {
                // Handle each connection in a separate task
                let (stream, _addr) = listener.accept().await?;
                observability::record_connection_opened();
                let stream = stream.into_std()?;
                stream.set_nodelay(true).ok();
                
                task::spawn(async move {
                    let permit = match TUNNEL_SEMAPHORE.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    
                    let result = Self::handle_connection(stream).await;
                    observability::record_connection_closed();
                    
                    // Ensure permit is always released
                    drop(permit);
                    
                    if let Err(e) = result {
                        log!(LogLevel::Error, "Connection failed: {}", e);
                    }
                });
            }
        } else {
            Err("Proxy server not bound".into())
        }
    }
    
    /// Handle a single client connection
    async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Read HTTP request headers in chunks until \r\n\r\n
        let mut buffer = Vec::new();
        let mut chunk_buf = [0u8; 4096]; // 4KB chunks
        let mut header_end = 0;
        
        // Read in chunks until we find \r\n\r\n
        loop {
            let bytes_read = stream.read(&mut chunk_buf)?;
            if bytes_read == 0 {
                break; // EOF
            }
            
            buffer.extend_from_slice(&chunk_buf[..bytes_read]);
            
            // Check for \r\n\r\n pattern in the buffer
            if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        
        if header_end == 0 {
            return Ok(());
        }
        
        let request = String::from_utf8_lossy(&buffer[..header_end]);
        
        if request.starts_with("GET ") {
            if request.contains("clients3.google.com/generate_204") {
                let response = b"HTTP/1.1 204 No Content\r\n\r\n";
                stream.write_all(response)?;
                stream.flush()?;
                return Ok(());
            }
            
            if request.contains("detectportal.firefox.com") {
                let response = b"HTTP/1.1 200 OK\r\n\r\n";
                stream.write_all(response)?;
                stream.flush()?;
                return Ok(());
            }
        }
        
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
            
            log!(LogLevel::Debug, "CONNECT tunnel requested to {}:{}", host, port);
            
            // Handle CONNECT request for HTTPS tunneling
            let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            stream.write_all(response)?;
            stream.flush()?;
            
            // Create transport for this specific CONNECT target
            let mut transport = DirectTcpTunnelTransport::new(
                host.clone(),
                port
            )?;
            
            // LEAK ANNOTATION: LeakStatus::Intentional
            // Connection establishment leaks destination IP and SNI to ISP/transit because:
            // 1. Direct TCP connection exposes destination IP in packet headers
            // 2. TLS handshake SNI field contains domain name in plaintext
            // 3. This is documented Phase 3 behavior - no relay indirection yet
            
            // Establish connection to target
            match transport.establish_connection().await {
                Ok(_) => {},
                Err(e) => {
                    log!(LogLevel::Error, "Failed to establish connection to {}:{} - {}", host, port, e);
                    return Err(e.into());
                }
            }
            
            // Start encrypted forwarding using transport
            transport.start_forwarding(stream)?;
            return Ok(());
        } else {
            // Temporarily disable HTTP handling for debugging
            // } else if request.starts_with("GET ") || request.starts_with("POST ") || request.starts_with("HEAD ") {
            //     // Handle HTTP request forwarding
            //     Self::handle_http_request(stream, &request).await?;
            // } else {
            // Reject non-CONNECT requests
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
        
        // Extract host, port, and path from absolute URL
        let (host, port, path) = if url.starts_with("http://") {
            let url_part = &url[7..]; // Remove "http://"
            if let Some(slash_pos) = url_part.find('/') {
                let host_part = &url_part[..slash_pos];
                let path = &url_part[slash_pos..]; // Include the leading slash
                let (host, port) = Self::parse_host_port(host_part, 80);
                (host, port, path.to_string())
            } else {
                let (host, port) = Self::parse_host_port(url_part, 80);
                (host, port, "/".to_string())
            }
        } else {
            return Err("Only absolute HTTP URLs supported".into());
        };
        
        log!(LogLevel::Debug, "HTTP request to {}:{}", host, port);
        
        // Connect to target server
        let mut target_stream = TcpStream::connect(format!("{}:{}", host, port))?;
        
        // Convert absolute-form request to origin-form
        let method = parts[0];
        let version = if parts.len() >= 3 { parts[2] } else { "HTTP/1.1" };
        let mut origin_request = format!("{} {} {}\r\n", method, path, version);
        
        // Add filtered headers (skip the first line and hop-by-hop headers)
        let mut lines = request.lines();
        lines.next(); // Skip request line
        for line in lines {
            let header_line = line.trim();
            if header_line.is_empty() {
                break; // End of headers
            }
            
            // Filter out hop-by-hop headers
            let header_name = if let Some(colon_pos) = header_line.find(':') {
                header_line[..colon_pos].trim().to_lowercase()
            } else {
                continue;
            };
            
            match header_name.as_str() {
                "proxy-connection" | "connection" | "keep-alive" | "te" | 
                "trailer" | "transfer-encoding" | "upgrade" => {
                    // Skip hop-by-hop headers
                    continue;
                }
                _ => {
                    origin_request.push_str(header_line);
                    origin_request.push_str("\r\n");
                }
            }
        }
        
        // Add Connection: close header
        origin_request.push_str("Connection: close\r\n");
        origin_request.push_str("\r\n"); // End headers
        
        // Forward the converted request
        target_stream.write_all(origin_request.as_bytes())?;
        target_stream.flush()?;
        
        // Read the full response from target and forward to client
        let mut response_buffer = Vec::new();
        target_stream.read_to_end(&mut response_buffer)?;
        
        // Send response to client and close connection
        client_stream.write_all(&response_buffer)?;
        client_stream.flush()?;
        
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
