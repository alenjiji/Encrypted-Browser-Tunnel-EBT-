// NOTE:
// This proxy currently accepts connections sequentially.
// A multi-connection loop will be added in a follow-up change.

use std::net::{TcpListener as StdTcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use crate::config::ProxyPolicy;
use crate::content_policy::{ContentPolicyEngine, Decision, RequestMetadata, RuleSet};
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

#[derive(Debug)]
struct HeaderParseError(HeaderParseKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderParseKind {
    ClientClosed,
    TimedOut,
}

impl std::fmt::Display for HeaderParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            HeaderParseKind::ClientClosed => write!(f, "Client closed before completing CONNECT headers"),
            HeaderParseKind::TimedOut => write!(f, "CONNECT headers timed out"),
        }
    }
}

impl std::error::Error for HeaderParseError {}


/// Real proxy server that binds to network interfaces
pub struct RealProxyServer {
    policy: ProxyPolicy,
    listener: Option<TcpListener>,
    policy_adapter: Arc<PolicyAdapter>,
}

impl RealProxyServer {
    pub fn new(policy: ProxyPolicy) -> Self {
        Self {
            policy,
            listener: None,
            policy_adapter: Arc::new(PolicyAdapter::new(
                ContentPolicyEngine::new(RuleSet::default()),
                policy.content_policy_enabled,
            )),
        }
    }

    pub fn set_content_policy_enabled(&self, enabled: bool) {
        self.policy_adapter.set_enabled(enabled);
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
                let policy_adapter = Arc::clone(&self.policy_adapter);
                let stream = stream.into_std()?;
                stream.set_nonblocking(false)?;
                stream.set_nodelay(true).ok();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
                
                task::spawn(async move {
                    let permit = match TUNNEL_SEMAPHORE.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    
                    let handle = tokio::runtime::Handle::current();
                    let result = task::spawn_blocking(move || handle.block_on(Self::handle_connection(stream, policy_adapter)))
                        .await
                        .unwrap_or_else(|e| Err(e.into()));
                    observability::record_connection_closed();
                    
                    // Ensure permit is always released
                    drop(permit);
                    
                    if let Err(e) = result {
                        if let Some(header_err) = e.downcast_ref::<HeaderParseError>() {
                            match header_err.0 {
                                HeaderParseKind::TimedOut | HeaderParseKind::ClientClosed => {
                                    observability::record_header_discard();
                                }
                            }
                        } else {
                            log!(LogLevel::Error, "Connection failed: {}", e);
                        }
                    }
                });
            }
        } else {
            Err("Proxy server not bound".into())
        }
    }
    
    /// Handle a single client connection
    async fn handle_connection(
        mut stream: TcpStream,
        policy_adapter: Arc<PolicyAdapter>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Read HTTP request headers in chunks until \r\n\r\n
        let mut buffer = Vec::new();
        let mut chunk_buf = [0u8; 4096]; // 4KB chunks
        
        // Read in chunks until we find \r\n\r\n
        let header_end = loop {
            match stream.read(&mut chunk_buf) {
                Ok(0) => {
                    // true EOF: client closed before completing headers
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return Err(Box::new(HeaderParseError(HeaderParseKind::ClientClosed)));
                }
                Ok(n) => {
                    buffer.extend_from_slice(&chunk_buf[..n]);
                    
                    // Check for \r\n\r\n pattern in the buffer
                    if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                        break pos + 4;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // IMPORTANT: just continue, do NOT fail
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(Box::new(HeaderParseError(HeaderParseKind::TimedOut)));
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        };

        let _ = stream.set_read_timeout(None);
        
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
            
            log!(LogLevel::Debug, "CONNECT tunnel requested");

            if !policy_allows_connect(policy_adapter.as_ref(), &request, &host, port) {
                let response = b"HTTP/1.1 403 Forbidden\r\n\r\n";
                stream.write_all(response)?;
                stream.flush()?;
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            
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
                    log!(LogLevel::Error, "Failed to establish connection - {}", e);
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
        
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
    
    /// Handle HTTP request forwarding (non-CONNECT)
    async fn handle_http_request(mut client_stream: TcpStream, request: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        
        log!(LogLevel::Debug, "HTTP request forwarding");
        
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
    fn forward_http_streams(client_stream: TcpStream, target_stream: TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

struct PolicyAdapter {
    engine: ContentPolicyEngine,
    enabled: AtomicBool,
}

impl PolicyAdapter {
    fn new(engine: ContentPolicyEngine, enabled: bool) -> Self {
        Self {
            engine,
            enabled: AtomicBool::new(enabled),
        }
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn evaluate(&self, request: &RequestMetadata) -> Decision {
        self.engine.evaluate(request)
    }
}

fn parse_headers(request: &str) -> std::collections::BTreeMap<String, String> {
    let mut headers = std::collections::BTreeMap::new();
    let mut lines = request.lines();
    lines.next();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }
    headers
}

fn build_connect_metadata(request: &str, host: &str, port: u16) -> RequestMetadata {
    let headers = parse_headers(request);
    let full_url = format!("https://{}:{}", host, port);
    RequestMetadata::new(
        "CONNECT".to_string(),
        full_url,
        host.to_string(),
        port,
        headers,
    )
}

fn policy_allows_connect(
    policy_adapter: &PolicyAdapter,
    request: &str,
    host: &str,
    port: u16,
) -> bool {
    if !policy_adapter.is_enabled() {
        return true;
    }

    let metadata = build_connect_metadata(request, host, port);
    match policy_adapter.evaluate(&metadata) {
        Decision::Allow => {
            observability::record_policy_allowed();
            true
        }
        Decision::Block { reason } => {
            observability::record_policy_blocked();
            match reason {
                crate::content_policy::ReasonCode::Ads => {
                    observability::record_policy_blocked_ads();
                }
                crate::content_policy::ReasonCode::Tracking => {
                    observability::record_policy_blocked_tracking();
                }
                crate::content_policy::ReasonCode::Custom => {
                    observability::record_policy_blocked_custom();
                }
                crate::content_policy::ReasonCode::Unknown => {}
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_policy::{ReasonCode, Rule, RuleAction};

    fn make_adapter(rules: Vec<Rule>, enabled: bool) -> PolicyAdapter {
        PolicyAdapter::new(ContentPolicyEngine::new(RuleSet::new(rules)), enabled)
    }

    #[test]
    fn blocked_requests_do_not_reach_connect() {
        let adapter = make_adapter(
            vec![Rule::DomainExact {
                domain: "blocked.example.com".to_string(),
                action: RuleAction::Block(ReasonCode::Custom),
            }],
            true,
        );
        let request = "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n";

        assert!(!policy_allows_connect(
            &adapter,
            request,
            "blocked.example.com",
            443
        ));
    }

    #[test]
    fn allowed_requests_behave_like_phase6_when_disabled() {
        let adapter = make_adapter(
            vec![Rule::DomainExact {
                domain: "blocked.example.com".to_string(),
                action: RuleAction::Block(ReasonCode::Ads),
            }],
            false,
        );
        let request = "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n";

        assert!(policy_allows_connect(
            &adapter,
            request,
            "blocked.example.com",
            443
        ));
    }

    #[test]
    fn allowed_rule_proceeds_when_enabled() {
        let adapter = make_adapter(
            vec![Rule::DomainExact {
                domain: "allowed.example.com".to_string(),
                action: RuleAction::Allow,
            }],
            true,
        );
        let request = "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n";

        assert!(policy_allows_connect(
            &adapter,
            request,
            "allowed.example.com",
            443
        ));
    }
}
