//! Threat Model - Phase 3 Behavior Documentation
//! 
//! Represents Phase 3 behavior: what each observer can see in the current system.
//! This module documents existing leaks and visibility, not mitigations.

/// System observers who can see different types of metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observer {
    LocalHost,      // Local machine (OS, malware, admin)
    Browser,        // Browser application
    Proxy,          // EBT local proxy
    ISP,            // Access ISP (Airtel, Jio, etc.)
    Transit,        // Transit networks
    Destination,    // Destination server
    GlobalObserver, // Passive global observer (IXP / nation-state)
}

/// Metadata visibility constants - represents Phase 3 behavior
pub mod visibility {
    /// Destination IP is visible to network observers
    pub const DESTINATION_IP_VISIBLE: bool = true;
    
    /// SNI domain is visible in TLS handshake
    pub const SNI_VISIBLE: bool = true;
    
    /// DNS queries may leak through various channels
    pub const DNS_METADATA_VISIBLE: bool = true;
    
    /// Connection timing patterns are observable
    pub const TIMING_VISIBLE: bool = true;
    
    /// HTTP payload is encrypted and not visible to intermediaries
    pub const PAYLOAD_VISIBLE: bool = false;
}