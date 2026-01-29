mod client;
mod transport;
mod dns;
mod session;
mod config;
mod real_transport;
mod real_proxy;
mod real_dns;
mod tls_wrapper;
#[cfg(feature = "async_tunnel")]
mod async_tunnel;

use std::error::Error;
use client::{ProxyConfig, ProxyType};
use session::TunnelSession;
use config::{CapabilityPolicy, ExecutionMode, Capability, ProxyPolicy, ProxyMode};

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tokio_main().await
}

#[cfg(not(feature = "tokio"))]
fn main() -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(tokio_main())
}

async fn tokio_main() -> Result<(), Box<dyn Error>> {
    println!("=== DIRECT CONNECT MODE (NO SSH) ===");
    
    // TEMPORARILY DISABLED FOR CONNECT DEBUGGING:
    // Create tunnel session with SSH SOCKS configuration
    // let config = ProxyConfig {
    //     proxy_type: ProxyType::SshSocks,
    //     address: "relay.example.com".to_string(),
    //     port: 22,
    // };
    // 
    // let capability_policy = CapabilityPolicy {
    //     execution_mode: ExecutionMode::RealNetwork,
    //     allowed_capabilities: vec![Capability::RealNetworking],
    // };
    // 
    // let mut session = TunnelSession::new(config, capability_policy);
    // 
    // // Establish tunnel
    // session.establish_tunnel().await?;
    
    // Start real proxy server
    let proxy_policy = ProxyPolicy {
        mode: ProxyMode::Application,
        bind_address: "127.0.0.1".to_string(),
        bind_port: 8080,
        authentication: None,
    };
    
    println!("\n=== Starting Real Network Mode ===");
    // session.start_real_proxy(&proxy_policy)?;
    
    // Start accepting connections
    let mut real_proxy = crate::real_proxy::RealProxyServer::new(proxy_policy.clone());
    real_proxy.bind()?;
    
    println!("\nReal proxy server ready!");
    println!("Configure your browser to use proxy: 127.0.0.1:8080");
    println!("Press Ctrl+C to stop the server");
    
    // Accept connections
    real_proxy.accept_connections().await?;
    Ok(())
}