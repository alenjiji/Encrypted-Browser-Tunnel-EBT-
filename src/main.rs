mod client;
mod proxy;
mod transport;
mod dns;
mod session;

#[cfg(test)]
mod test_transport;

use std::error::Error;
use client::{ProxyConfig, ProxyType};
use session::TunnelSession;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Encrypted Browser Tunnel (Educational)");
    println!("Demonstrating conceptual architecture flow\n");
    
    // Create tunnel session with SSH SOCKS configuration
    let config = ProxyConfig {
        proxy_type: ProxyType::SshSocks,
        address: "relay.example.com".to_string(),
        port: 22,
    };
    
    let session = TunnelSession::new(config);
    
    // Establish tunnel
    session.establish_tunnel().await?;
    
    // Validate DNS configuration
    session.validate_dns_configuration();
    
    // Process a sample request
    let sample_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let _response = session.process_request("example.com", sample_request).await?;
    
    println!("\nEducational demonstration complete");
    Ok(())
}