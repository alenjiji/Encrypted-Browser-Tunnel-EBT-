// NOTE:
// This implementation establishes a CONNECT-based TCP tunnel.
// TLS encryption is layered inside the tunnel and will be added next.
// This commit focuses on correct CONNECT semantics and capability gating.

use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown, IpAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::transport::{EncryptedTransport, TransportError};
use crate::dns_resolver::{DnsResolver, DohResolver};
use crate::relay_transport::{RelayTransport, DirectRelayTransport};
use crate::logging::LogLevel;
use crate::log;
#[cfg(feature = "single_hop_relay")]
use crate::relay_transport::SingleHopRelayTransport;
#[cfg(feature = "multi_hop_relay")]
use crate::relay_transport::MultiHopRelayTransport;

/// Real TCP transport implementation with direct connection
pub struct DirectTcpTunnelTransport {
    target_host: String,
    target_port: u16,
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,
    dns_resolver: DohResolver,
    relay_transport: Box<dyn RelayTransport>,
}

impl DirectTcpTunnelTransport {
    pub fn new(target_host: String, target_port: u16) -> Result<Self, TransportError> {
        #[cfg(feature = "multi_hop_relay")]
        let relay_transport: Box<dyn RelayTransport> = Box::new(MultiHopRelayTransport::new(vec![
            ("127.0.0.1".parse().unwrap(), 8080),
            ("127.0.0.1".parse().unwrap(), 8081),
            ("127.0.0.1".parse().unwrap(), 8082),
        ]));
        
        #[cfg(all(feature = "single_hop_relay", not(feature = "multi_hop_relay")))]
        let relay_transport: Box<dyn RelayTransport> = Box::new(SingleHopRelayTransport::new(
            "127.0.0.1".parse().unwrap(),
            8080
        ));
        
        #[cfg(all(not(feature = "single_hop_relay"), not(feature = "multi_hop_relay")))]
        let relay_transport: Box<dyn RelayTransport> = Box::new(DirectRelayTransport::default());
        
        Ok(Self {
            target_host,
            target_port,
            tcp_stream: None,
            dns_resolver: DohResolver::new(),
            relay_transport,
        })
    }
    
    /// Get the established TCP stream for forwarding
    pub fn get_tcp_stream(&self) -> Option<Arc<Mutex<TcpStream>>> {
        self.tcp_stream.clone()
    }
    
    /// Start bidirectional forwarding between client and TCP stream
    pub fn start_forwarding(&self, client_stream: TcpStream) -> Result<(), TransportError> {
        #[cfg(feature = "async_tunnel")]
        {
            return self.start_async_forwarding(client_stream);
        }
        
        #[cfg(not(feature = "async_tunnel"))]
        {
            return self.start_blocking_forwarding(client_stream);
        }
    }
    
    #[cfg(feature = "async_tunnel")]
    fn start_async_forwarding(&self, client_stream: TcpStream) -> Result<(), TransportError> {
        let tcp_stream = self.tcp_stream.as_ref()
            .ok_or(TransportError::ConnectionFailed)?
            .lock().map_err(|_| TransportError::ConnectionFailed)?
            .try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let client = tokio::net::TcpStream::from_std(client_stream)
                .map_err(|_| TransportError::ConnectionFailed)?;
            let target = tokio::net::TcpStream::from_std(tcp_stream)
                .map_err(|_| TransportError::ConnectionFailed)?;
            
            client.set_nodelay(true).ok();
            target.set_nodelay(true).ok();
            
            crate::async_tunnel::tunnel_connect(client, target).await
                .map_err(|_| TransportError::ConnectionFailed)
        })
    }
    
    #[cfg(not(feature = "async_tunnel"))]
    fn start_blocking_forwarding(&self, client_stream: TcpStream) -> Result<(), TransportError> {
        let tcp_stream = self.tcp_stream.as_ref()
            .ok_or(TransportError::ConnectionFailed)?
            .lock().map_err(|_| TransportError::ConnectionFailed)?
            .try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        
        // Clone streams for true full-duplex (no mutex)
        let client_read = client_stream.try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        let client_write = client_stream;
        
        let tcp_read = tcp_stream.try_clone().map_err(|_| TransportError::ConnectionFailed)?;
        let tcp_write = tcp_stream;
        
        // Apply TCP socket tuning to all streams
        client_read.set_nodelay(true).ok();
        client_read.set_read_timeout(None).ok();
        client_read.set_write_timeout(None).ok();
        
        client_write.set_nodelay(true).ok();
        client_write.set_read_timeout(None).ok();
        client_write.set_write_timeout(None).ok();
        
        tcp_read.set_nodelay(true).ok();
        tcp_read.set_read_timeout(None).ok();
        tcp_read.set_write_timeout(None).ok();
        
        tcp_write.set_nodelay(true).ok();
        tcp_write.set_read_timeout(None).ok();
        tcp_write.set_write_timeout(None).ok();
        
        // Metrics tracking
        let start_time = Instant::now();
        let client_to_upstream_bytes = Arc::new(AtomicU64::new(0));
        let upstream_to_client_bytes = Arc::new(AtomicU64::new(0));
        
        // client → TCP (no mutex)
        let a = thread::Builder::new()
            .name("client-to-tcp".to_string())
            .spawn({
                let counter = Arc::clone(&client_to_upstream_bytes);
                move || Self::forward_data_with_metrics(client_read, tcp_write, counter)
            })
            .map_err(|_| TransportError::ConnectionFailed)?;
        
        // TCP → client (no mutex)
        let b = thread::Builder::new()
            .name("tcp-to-client".to_string())
            .spawn({
                let counter = Arc::clone(&upstream_to_client_bytes);
                move || Self::forward_data_with_metrics(tcp_read, client_write, counter)
            })
            .map_err(|_| TransportError::ConnectionFailed)?;
        
        // Wait for both threads to complete cleanly
        log!(LogLevel::Debug, "Waiting for forwarding threads to complete");
        let result_a = a.join();
        let result_b = b.join();
        
        // Emit metrics once on connection close
        let duration = start_time.elapsed();
        let client_bytes = client_to_upstream_bytes.load(Ordering::Relaxed);
        let upstream_bytes = upstream_to_client_bytes.load(Ordering::Relaxed);
        
        log!(LogLevel::Debug, "CONNECT tunnel closed: client→upstream {} bytes, upstream→client {} bytes, duration {:?}", 
             client_bytes, upstream_bytes, duration);
        
        // Handle thread panics or errors
        match (result_a, result_b) {
            (Ok(Ok(_)), Ok(Ok(_))) => {
                log!(LogLevel::Debug, "Both forwarding threads completed successfully");
                Ok(())
            },
            _ => {
                log!(LogLevel::Debug, "One or both forwarding threads failed");
                Err(TransportError::ConnectionFailed)
            }
        }
    }
    
    /// Forward data directly between streams with metrics (no mutex)
    fn forward_data_with_metrics(mut src: TcpStream, mut dst: TcpStream, byte_counter: Arc<AtomicU64>) -> Result<(), TransportError> {
        let mut buf = [0u8; 65536]; // 64KB buffer
        loop {
            match src.read(&mut buf) {
                Ok(0) => {
                    // EOF reached - shutdown write side of destination
                    log!(LogLevel::Debug, "EOF detected on source stream");
                    let _ = dst.shutdown(std::net::Shutdown::Write);
                    return Ok(());
                }
                Ok(n) => {
                    if let Err(_) = dst.write_all(&buf[..n]) {
                        log!(LogLevel::Debug, "Write failed to destination stream");
                        return Ok(());
                    }
                    byte_counter.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    log!(LogLevel::Debug, "Read error on source stream: {}", e);
                    return Ok(());
                }
            }
        }
    }
}

impl EncryptedTransport for DirectTcpTunnelTransport {
    async fn establish_connection(&mut self) -> Result<(), TransportError> {
        // Resolve hostname using DoH resolver (no plaintext DNS)
        let ips = self.dns_resolver.resolve(&self.target_host).await
            .map_err(|_| TransportError::ConnectionFailed)?;
        
        if ips.is_empty() {
            log!(LogLevel::Error, "No IP addresses resolved for {}", self.target_host);
            return Err(TransportError::ConnectionFailed);
        }
        
        let mut last_error = None;
        
        // Try first IP address immediately, then others if needed
        // This avoids head-of-line blocking while maintaining sequential attempts per host
        for (i, ip) in ips.iter().enumerate() {
            if i == 0 {
                // First attempt - immediate
                log!(LogLevel::Debug, "Primary connection attempt to {}:{} via {}", 
                     self.target_host, self.target_port, ip);
            } else {
                // Fallback attempts - only after first fails
                log!(LogLevel::Debug, "Fallback connection attempt {}/{} to {}:{} via {}", 
                     i + 1, ips.len(), self.target_host, self.target_port, ip);
            }
            
            // LEAK ANNOTATION: LeakStatus::Intentional  
            // Relay handling in direct mode leaks connection metadata because:
            // 1. No actual relay indirection - connects directly to destination
            // 2. ISP sees real destination IP in TCP SYN packets
            // 3. Timing correlation possible between client request and outbound connection
            // 4. Phase 3 explicitly documents this as direct-connect behavior
            
            match self.relay_transport.establish_relay_connection(*ip, self.target_port).await {
                Ok(tcp) => {
                    log!(LogLevel::Debug, "Connection established to {}:{} via {} (attempt {})", 
                         self.target_host, self.target_port, ip, i + 1);
                    
                    let std_stream = tcp.into_std().map_err(|e| {
                        log!(LogLevel::Error, "Failed to convert tokio stream to std: {}", e);
                        TransportError::ConnectionFailed
                    })?;
                    
                    self.tcp_stream = Some(Arc::new(Mutex::new(std_stream)));
                    return Ok(());
                }
                Err(e) => {
                    log!(LogLevel::Debug, "Connection attempt {}/{} to {} via {} failed: {}", 
                         i + 1, ips.len(), self.target_host, ip, e);
                    last_error = Some(e);
                    // Continue to next IP address
                }
            }
        }
        
        log!(LogLevel::Error, "All connection attempts failed for {}: {:?}", 
             self.target_host, last_error);
        Err(TransportError::ConnectionFailed)
    }
    
    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // No encryption - pass through raw data
        Ok(data.to_vec())
    }
    
    async fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // No decryption - pass through raw data
        Ok(data.to_vec())
    }

}