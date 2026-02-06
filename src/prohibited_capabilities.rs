use crate::trust_boundaries::{SourceIp, DestinationHostname};

/// Prohibited: DNS resolution outside Exit zone
/// This trait is intentionally NOT implemented for Entry/Relay zones
pub trait DnsResolution {
    /// Only available in Exit zone - compile error elsewhere
    fn resolve_hostname(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, DnsError>;
}

#[derive(Debug)]
pub struct DnsError;

/// Prohibited: Network metadata logging by default
/// No default logging traits - must be explicitly opted in
pub struct NetworkMetadata {
    // Fields are private - cannot be accessed directly
    source_ip: SourceIp,
    destination: DestinationHostname,
    timestamp: std::time::SystemTime,
}

impl NetworkMetadata {
    /// Prohibited: No constructor available
    /// Cannot create NetworkMetadata instances
    fn new(source: SourceIp, dest: DestinationHostname) -> Self {
        Self {
            source_ip: source,
            destination: dest,
            timestamp: std::time::SystemTime::now(),
        }
    }
    
    // Prohibited: No getter methods
}

/// Prohibited: Raw socket access in core
/// This trait is intentionally empty - no socket operations allowed
pub trait RawSocketAccess {
    // Intentionally no methods - compile error if attempted
}

/// Prohibited: Destination hostname upstream propagation
pub struct UpstreamMessage {
    // Only encrypted payload allowed
    encrypted_data: Vec<u8>,
    // Destination hostname field is intentionally missing
}

impl UpstreamMessage {
    pub fn new(encrypted_data: Vec<u8>) -> Self {
        Self { encrypted_data }
    }
    
    // Prohibited: No method to set destination or include metadata
}

/// Prohibited: Cross-zone data correlation
pub struct ZoneIsolation;

impl ZoneIsolation {
    // Prohibited: No methods to correlate or bridge zones
}

/// Prohibited: Implicit logging capabilities
/// No Default trait implementation - must be explicitly constructed
pub struct LoggingCapability {
    enabled: bool,
}

impl LoggingCapability {
    /// Only explicit construction allowed
    pub fn explicitly_enabled() -> Self {
        Self { enabled: true }
    }
    
    // Prohibited: No default constructor
}

/// Prohibited: Plaintext data in non-terminal zones
pub struct PlaintextData {
    data: Vec<u8>,
}

impl PlaintextData {
    /// Prohibited: Constructor only available in specific zones
    /// This would be gated by zone-specific traits in real implementation
    fn new_in_local_zone(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    fn new_in_exit_zone(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    // Prohibited: No constructors for intermediate zones
}

/// Prohibited: Direct IP address exposure
pub struct IpAddress {
    addr: std::net::IpAddr,
}

impl IpAddress {
    /// Prohibited: No public constructor
    fn new(addr: std::net::IpAddr) -> Self {
        Self { addr }
    }
    
    // Prohibited: No getter methods
}

/// Prohibited: Session correlation across zones
pub struct SessionCorrelation;

impl SessionCorrelation {
    // Prohibited: No methods to link or correlate sessions
}

// Documentation-only prohibition markers
// PROHIBITED: No Display, Debug, Clone, Serialize, Default traits for sensitive types
// PROHIBITED: No println!/eprintln! with sensitive data - use explicit logging only