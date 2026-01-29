use std::time::Duration;
use std::net::IpAddr;

/// Execution mode controlling what the program is allowed to do
#[derive(Debug, Clone)]
pub enum ExecutionMode {
    Conceptual,
    RealNetwork,
}

/// System capabilities representing allowed operations
#[derive(Debug, Clone, PartialEq)]
pub enum Capability {
    NoNetworking,
    RealNetworking,
}

/// Policy binding execution mode to allowed capabilities
#[derive(Debug, Clone)]
pub struct CapabilityPolicy {
    pub execution_mode: ExecutionMode,
    pub allowed_capabilities: Vec<Capability>,
}

/// Top-level tunnel configuration for production deployment
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub transport: TransportConfig,
    pub dns_policy: DnsPolicy,
    pub proxy_policy: ProxyPolicy,
}

impl TunnelConfig {
    /// Creates a TunnelConfig matching current conceptual behavior
    pub fn educational_ssh_socks() -> Self {
        Self {
            transport: TransportConfig {
                kind: TransportKind::Ssh,
                remote_address: "relay.example.com".to_string(),
                remote_port: 22,
            },
            dns_policy: DnsPolicy {
                resolution_location: ResolutionLocation::Remote,
                leak_detection: LeakDetection::Warn,
            },
            proxy_policy: ProxyPolicy {
                mode: ProxyMode::Application,
                bind_address: "proxy-bind.placeholder".to_string(),
                bind_port: 8080,
                authentication: None,
            },
        }
    }
}

/// Transport configuration describing encrypted transport intent
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub kind: TransportKind,
    pub remote_address: String,
    pub remote_port: u16,
}

/// Transport kinds matching existing Transport enum variants
#[derive(Debug, Clone)]
pub enum TransportKind {
    Ssh,
    Tls,
    Quic,
}

/// DNS handling policy for secure tunnel configuration
#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub resolution_location: ResolutionLocation,
    pub leak_detection: LeakDetection,
}

/// Where DNS resolution should occur
#[derive(Debug, Clone)]
pub enum ResolutionLocation {
    Local,
    Remote,
}

/// DNS leak detection enforcement level
#[derive(Debug, Clone)]
pub enum LeakDetection {
    Strict,
    Warn,
    Disabled,
}

/// Proxy exposure behavior policy
#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub bind_port: u16,
    pub authentication: Option<AuthenticationPlaceholder>,
}

/// How the proxy should be exposed
#[derive(Debug, Clone)]
pub enum ProxyMode {
    System,
    Application,
}

/// Authentication configuration placeholder
#[derive(Debug, Clone)]
pub struct AuthenticationPlaceholder {
    pub enabled: bool,
    pub method: String,
}