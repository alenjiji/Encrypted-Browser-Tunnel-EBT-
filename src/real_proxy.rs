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
use crate::logging::LogLevel;
use crate::log;
use tokio::task;
use tokio::sync::Semaphore;

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
        
        let listener = TcpListener::bind(&bind_addr)?;
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
                let (stream, addr) = listener.accept()?;
                stream.set_nodelay(true).ok();
                
                log!(LogLevel::Debug, "Connection accepted from {}", addr);
                
                task::spawn(async move {
                    // Ensure task cleanup on early exit
                    let _cleanup_guard = scopeguard::guard((), |_| {
                        log!(LogLevel::Debug, "Task cleanup for {}", addr);
                    });
                    
                    let permit = match TUNNEL_SEMAPHORE.clone().acquire_owned().await {
                        Ok(p) => {
                            log!(LogLevel::Debug, "Task permit acquired for {}", addr);
                            p
                        },
                        Err(_) => {
                            log!(LogLevel::Error, "Failed to acquire task permit for {}", addr);
                            return;
                        }
                    };
                    
                    let result = Self::handle_connection(stream).await;
                    
                    // Ensure permit is always released
                    drop(permit);
                    log!(LogLevel::Debug, "Task permit released for {}", addr);
                    
                    match result {
                        Ok(_) => log!(LogLevel::Debug, "Connection {} completed successfully", addr),
                        Err(e) => log!(LogLevel::Error, "Connection {} failed: {}", addr, e),
                    }
                });
            }
        } else {
            Err("Proxy server not bound".into())
        }
    }
    
    /// Handle a single client connection
    async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        log!(LogLevel::Debug, "Reading client request headers");
        
        // Read HTTP request headers only (until \r\n\r\n)
        let mut buffer = Vec::new();
        let mut temp_buf = [0u8; 1];
        let mut header_end = 0;
        
        // Read byte by byte until we find \r\n\r\n
        loop {
            let bytes_read = stream.read(&mut temp_buf)?;
            if bytes_read == 0 {
                log!(LogLevel::Debug, "Client EOF during header read");
                break; // EOF
            }
            buffer.push(temp_buf[0]);
            
            // Check for \r\n\r\n pattern
            if buffer.len() >= 4 {
                let len = buffer.len();
                if &buffer[len-4..len] == b"\r\n\r\n" {
                    header_end = len;
                    break;
                }
            }
        }
        
        if header_end == 0 {
            log!(LogLevel::Debug, "No complete headers received");
            return Ok(());
        }
        
        // Read any remaining bytes that might be TLS data
        let mut leftover_bytes = Vec::new();
        let mut remaining_buf = [0u8; 4096];
        stream.set_nonblocking(true).ok();
        if let Ok(n) = stream.read(&mut remaining_buf) {
            if n > 0 {
                leftover_bytes.extend_from_slice(&remaining_buf[..n]);
                log!(LogLevel::Debug, "Read {} leftover bytes (likely TLS)", n);
            }
        }
        stream.set_nonblocking(false).ok();
        
        let request = String::from_utf8_lossy(&buffer[..header_end]);
        log!(LogLevel::Debug, "Request type: {}", request.lines().next().unwrap_or("unknown"));
        
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
            
            log!(LogLevel::Debug, "CONNECT response sent, establishing upstream connection");
            
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
                Ok(_) => log!(LogLevel::Debug, "Upstream connection established to {}:{}", host, port),
                Err(e) => {
                    log!(LogLevel::Error, "Failed to establish connection to {}:{} - {}", host, port, e);
                    return Err(e.into());
                }
            }
            
            // Forward any leftover bytes (TLS ClientHello) to target before tunneling
            if !leftover_bytes.is_empty() {
                if let Some(target_stream) = transport.get_tcp_stream() {
                    if let Ok(mut target) = target_stream.lock() {
                        let _ = target.write_all(&leftover_bytes);
                        let _ = target.flush();
                        log!(LogLevel::Debug, "Forwarded {} leftover bytes to upstream", leftover_bytes.len());
                    }
                }
            }
            
            log!(LogLevel::Debug, "Starting tunnel forwarding for {}:{}", host, port);
            
            // Start encrypted forwarding using transport
            match transport.start_forwarding(stream) {
                Ok(_) => log!(LogLevel::Debug, "Tunnel completed for {}:{}", host, port),
                Err(e) => {
                    log!(LogLevel::Error, "Tunnel forwarding failed for {}:{} - {}", host, port, e);
                    return Err(e.into());
                }
            }
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