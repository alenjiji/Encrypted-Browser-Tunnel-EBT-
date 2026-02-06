#![allow(dead_code)]

mod client;
mod core;
mod transport;
mod dns;
mod session;
mod config;
mod real_transport;
mod real_proxy;
mod real_dns;
mod tls_wrapper;
mod dns_resolver;
mod relay_transport;
mod logging;
mod tunnel_stats;
mod threat_invariants;
mod attack_surfaces;
mod trust_boundaries;
mod prohibited_capabilities;
mod threat_model_tests;
mod crypto_transport_design;
mod control_plane;
mod data_plane;
mod key_management;
mod zone_interfaces;
mod crypto_transport_tests;
mod threat_model;
mod traffic_shaping;
mod relay_protocol;
mod transport_adapter;
mod protocol_engine;
mod connection_mapping;
mod binding_pump;
#[cfg(feature = "encrypted_control")]
mod control_channel;
#[cfg(feature = "async_tunnel")]
mod async_tunnel;

use std::error::Error;
use config::{ProxyPolicy, ProxyMode};

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
    
    // Phase 5 feature gate check
    if traffic_shaping::PHASE_5_ENABLED {
        println!("Phase 5 traffic shaping: ENABLED");
        traffic_shaping::initialize_traffic_shaping();
    } else {
        println!("Phase 5 traffic shaping: DISABLED (Phase 4 invariants enforced)");
    }
    
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
    
    // TCP warm-up to improve initial connection reliability
    tokio::spawn(async {
        if let Err(_) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect("1.1.1.1:443")
        ).await {
            // Warm-up failure is expected and ignored
        }
    });
    
    println!("\nReal proxy server ready!");
    println!("Configure your browser to use proxy: 127.0.0.1:8080");
    println!("Press Ctrl+C to stop the server");
    
    // Accept connections
    real_proxy.accept_connections().await?;
    Ok(())
}
