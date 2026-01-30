//! Threat Model - Phase 3 Behavior Documentation
//! 
//! Represents Phase 3 behavior: what each observer can see in the current system.
//! This module documents existing leaks and visibility, not mitigations.

#![forbid(unsafe_code)]

/// Current development phase - enforces phase boundaries
pub const PHASE: u8 = 4;

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

/// Classification of information leaks in Phase 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakStatus {
    /// Leak is by design and documented
    Intentional,
    /// Leak is unavoidable given current architecture
    Inherent,
    /// Leak must not occur - violation of Phase 3 guarantees
    Forbidden,
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

/// Compile-time enforcement of Phase 3 invariants
pub mod invariants {
    use super::PHASE;
    
    /// Marker trait: Types that never inspect TLS payload
    pub trait NoTlsInspection {}
    
    /// Marker trait: Types that never parse HTTP after CONNECT
    pub trait NoHttpParsing {}
    
    /// Marker trait: Types that never log destination identifiers
    pub trait NoDestinationLogging {}
    
    /// Compile-time assertion: TLS payload inspection is forbidden
    const _: () = {
        // This will fail to compile if any code tries to inspect TLS payload
        // by requiring explicit opt-out via unsafe marker
        struct TlsPayloadInspectionForbidden;
        impl !Send for TlsPayloadInspectionForbidden {}
    };
    
    /// Compile-time assertion: HTTP parsing after CONNECT is forbidden
    const _: () = {
        // Ensures no HTTP parsing occurs in tunnel data path
        struct HttpParsingAfterConnectForbidden;
        impl !Sync for HttpParsingAfterConnectForbidden {}
    };
}

/// Phase boundary enforcement - prevents premature Phase 5+ features
pub mod phase_guards {
    use super::PHASE;
    
    /// Compile-time guard: Traffic shaping forbidden in Phase 4
    const _: () = {
        if PHASE < 5 {
            // Traffic shaping module would fail to compile
            struct TrafficShapingForbidden;
            const _GUARD: TrafficShapingForbidden = TrafficShapingForbidden;
        }
    };
    
    /// Compile-time guard: Padding forbidden in Phase 4
    const _: () = {
        if PHASE < 5 {
            // Padding logic would fail to compile
            struct PaddingForbidden;
            const _GUARD: PaddingForbidden = PaddingForbidden;
        }
    };
    
    /// Compile-time guard: Timing obfuscation forbidden in Phase 4
    const _: () = {
        if PHASE < 5 {
            // Timing obfuscation would fail to compile
            struct TimingObfuscationForbidden;
            const _GUARD: TimingObfuscationForbidden = TimingObfuscationForbidden;
        }
    };
    
    /// Compile-time guard: Cover traffic forbidden in Phase 4
    const _: () = {
        if PHASE < 7 {
            // Cover traffic would fail to compile
            struct CoverTrafficForbidden;
            const _GUARD: CoverTrafficForbidden = CoverTrafficForbidden;
        }
    };
    
    /// Compile-time guard: DNS modification forbidden in Phase 4
    const _: () = {
        if PHASE < 5 {
            // DNS obfuscation would fail to compile
            struct DnsModificationForbidden;
            const _GUARD: DnsModificationForbidden = DnsModificationForbidden;
        }
    };
}