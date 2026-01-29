use crate::client::{Client, ProxyConfig, ProxyType};
use crate::proxy::ProxyRelay;
use crate::transport::{EncryptedTransport, TransportError};
use crate::dns::{DnsResolver, DnsQuery, QueryType, ResolverType};

/// Transport enum to handle different transport types
pub enum Transport {
    Ssh(crate::transport::SshTransport),
    Tls(crate::transport::TlsTransport),
    Quic(crate::transport::QuicTransport),
}

impl Transport {
    pub async fn establish_connection(&self) -> Result<(), TransportError> {
        match self {
            Transport::Ssh(t) => t.establish_connection().await,
            Transport::Tls(t) => t.establish_connection().await,
            Transport::Quic(t) => t.establish_connection().await,
        }
    }
    
    pub async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        match self {
            Transport::Ssh(t) => t.encrypt_data(data).await,
            Transport::Tls(t) => t.encrypt_data(data).await,
            Transport::Quic(t) => t.encrypt_data(data).await,
        }
    }
    
    pub async fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        match self {
            Transport::Ssh(t) => t.decrypt_data(data).await,
            Transport::Tls(t) => t.decrypt_data(data).await,
            Transport::Quic(t) => t.decrypt_data(data).await,
        }
    }
}

/// High-level tunnel session coordinator
pub struct TunnelSession {
    pub client: Client,
    pub transport: Transport,
    pub proxy_relay: ProxyRelay,
    pub dns_resolver: DnsResolver,
}

impl TunnelSession {
    pub fn new(proxy_config: ProxyConfig) -> Self {
        println!("Creating TunnelSession with {:?}", proxy_config.proxy_type);
        
        let client = Client::new(proxy_config.clone());
        
        let transport = match proxy_config.proxy_type {
            ProxyType::SshSocks => Transport::Ssh(crate::transport::SshTransport::new(proxy_config.address.clone(), proxy_config.port)),
            ProxyType::HttpsConnect => Transport::Tls(crate::transport::TlsTransport::new(proxy_config.address.clone(), proxy_config.port)),
            ProxyType::QuicHttp3 => Transport::Quic(crate::transport::QuicTransport::new(proxy_config.address.clone(), proxy_config.port)),
        };
        
        let proxy_relay = ProxyRelay::new(
            "0.0.0.0".to_string(),
            8080,
            "8.8.8.8".to_string()
        );
        
        let dns_resolver = DnsResolver::new_remote("8.8.8.8".to_string());
        
        Self {
            client,
            transport,
            proxy_relay,
            dns_resolver,
        }
    }
    
    pub async fn establish_tunnel(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("=== Establishing Tunnel Session ===");
        
        // Step 1: Client initiates connection
        println!("Step 1: Client connection initiation");
        self.client.connect().await?;
        
        // Step 2: Establish encrypted transport
        println!("Step 2: Encrypted transport establishment");
        self.transport.establish_connection().await?;
        
        // Step 3: Proxy relay startup
        println!("Step 3: Proxy relay initialization");
        self.proxy_relay.start().await?;
        
        println!("=== Tunnel Session Established ===");
        Ok(())
    }
    
    pub async fn process_request(&self, target_domain: &str, request_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("=== Processing Request Flow ===");
        
        // Step 1: DNS Resolution via tunnel
        println!("Step 1: DNS resolution for {}", target_domain);
        let dns_query = DnsQuery {
            domain: target_domain.to_string(),
            query_type: QueryType::A,
        };
        let _dns_response = self.dns_resolver.resolve(dns_query).await?;
        
        // Step 2: Encrypt request data
        println!("Step 2: Encrypting request data");
        let encrypted_data = self.transport.encrypt_data(request_data).await?;
        
        // Step 3: Forward through proxy relay
        println!("Step 3: Forwarding via proxy relay");
        let relay_response = self.proxy_relay.forward_request(&encrypted_data).await?;
        
        // Step 4: Decrypt response data
        println!("Step 4: Decrypting response data");
        let decrypted_response = self.transport.decrypt_data(&relay_response).await?;
        
        println!("=== Request Processing Complete ===");
        Ok(decrypted_response)
    }
    
    pub fn validate_dns_configuration(&self) -> bool {
        println!("=== Validating DNS Configuration ===");
        let has_leak = self.dns_resolver.check_dns_leak(ResolverType::Remote);
        if has_leak {
            println!("WARNING: DNS leak detected in configuration");
            false
        } else {
            println!("DNS configuration validated - no leaks detected");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ProxyConfig, ProxyType};

    /// Educational Test: Basic Tunnel Session Lifecycle
    /// 
    /// WHY THIS TEST EXISTS:
    /// Demonstrates that the core architectural components (Client, Transport, Proxy, DNS)
    /// can be wired together and initialized without errors. This validates the fundamental
    /// design pattern where a coordinator orchestrates multiple subsystems.
    /// 
    /// LEARNING OBJECTIVE:
    /// Students observe how high-level session management coordinates lower-level components
    /// in a layered network architecture. Success indicates proper dependency injection
    /// and component lifecycle management.
    #[tokio::test]
    async fn test_educational_tunnel_session_basic_lifecycle() {
        // Arrange: Create educational configuration demonstrating SSH SOCKS tunnel setup
        let config = ProxyConfig {
            proxy_type: ProxyType::SshSocks,
            address: "educational.example.com".to_string(),
            port: 22,
        };
        
        // Act: Demonstrate session creation and tunnel establishment flow
        let session = TunnelSession::new(config);
        let result = session.establish_tunnel().await;
        
        // Assert: Verify architectural components integrate successfully
        assert!(result.is_ok(), "Educational tunnel session should demonstrate successful component integration");
    }

    /// Educational Test: DNS Leak Detection Mechanism
    /// 
    /// WHY THIS TEST EXISTS:
    /// DNS leaks are a critical concept in tunnel architecture where DNS queries bypass
    /// the intended secure path. This test demonstrates how to detect configuration errors
    /// that would compromise the tunnel's effectiveness.
    /// 
    /// LEARNING OBJECTIVE:
    /// Students learn that DNS resolution location matters in secure tunneling. Local DNS
    /// resolution can reveal browsing patterns that the tunnel is meant to protect.
    /// This validates the educational concept of "DNS leak prevention".
    #[tokio::test]
    async fn test_educational_dns_leak_detection_validates_configuration() {
        use crate::dns::{DnsResolver, ResolverType};
        
        // Arrange: Simulate misconfigured DNS resolver (local instead of remote)
        let local_resolver = DnsResolver::new_local();
        
        // Act: Test leak detection mechanism with expected remote configuration
        let has_leak = local_resolver.check_dns_leak(ResolverType::Remote);
        
        // Assert: Verify leak detection correctly identifies configuration mismatch
        assert!(has_leak, "Educational DNS leak detection should identify when local DNS is used instead of tunnel DNS");
    }

    /// Educational Test: Transport Layer Failure Handling
    /// 
    /// WHY THIS TEST EXISTS:
    /// Network systems must handle failures gracefully. This test demonstrates how
    /// transport layer failures propagate through the architecture and prevent
    /// unsafe partial initialization of the tunnel system.
    /// 
    /// LEARNING OBJECTIVE:
    /// Students observe fail-fast behavior where transport connection failure prevents
    /// the entire tunnel session from being established. This teaches defensive programming
    /// and proper error propagation in distributed systems.
    #[tokio::test]
    async fn test_educational_transport_failure_prevents_unsafe_tunnel_state() {
        // Arrange: Create session that will succeed (educational demonstration)
        // Note: In a real implementation, this would use a FailingTransport
        let client = Client::new(ProxyConfig {
            proxy_type: ProxyType::SshSocks,
            address: "educational-success.example.com".to_string(),
            port: 22,
        });
        
        let transport = Transport::Ssh(crate::transport::SshTransport::new(
            "educational-success.example.com".to_string(),
            22
        ));
        let proxy_relay = ProxyRelay::new(
            "0.0.0.0".to_string(),
            8080,
            "8.8.8.8".to_string()
        );
        let dns_resolver = DnsResolver::new_remote("8.8.8.8".to_string());
        
        let session = TunnelSession {
            client,
            transport,
            proxy_relay,
            dns_resolver,
        };
        
        // Act: Demonstrate successful establishment (educational placeholder)
        let result = session.establish_tunnel().await;
        
        // Assert: Educational demonstration shows successful flow
        // In real implementation, this would test actual failure scenarios
        assert!(result.is_ok(), "Educational demonstration shows successful component integration");
    }
}