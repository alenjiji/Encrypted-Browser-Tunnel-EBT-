use crate::threat_invariants::InvariantId;

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct AttackSurface {
    pub invariant_id: InvariantId,
    pub violation_path: String,
    pub severity: Severity,
    pub component: String,
}

pub struct AttackSurfaceEnumeration {
    pub surfaces: Vec<AttackSurface>,
}

impl AttackSurfaceEnumeration {
    pub fn new() -> Self {
        Self {
            surfaces: vec![
                // DNS Resolution At Exit Only
                AttackSurface {
                    invariant_id: InvariantId::DnsResolutionAtExitOnly,
                    violation_path: "OS resolver fallback in DoH failure".to_string(),
                    severity: Severity::High,
                    component: "dns_resolver".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::DnsResolutionAtExitOnly,
                    violation_path: "System DNS via ToSocketAddrs".to_string(),
                    severity: Severity::High,
                    component: "transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::DnsResolutionAtExitOnly,
                    violation_path: "Browser DNS prefetch bypass".to_string(),
                    severity: Severity::Medium,
                    component: "proxy".to_string(),
                },

                // No Source Destination Correlation
                AttackSurface {
                    invariant_id: InvariantId::NoSourceDestinationCorrelation,
                    violation_path: "Proxy logs client IP with CONNECT target".to_string(),
                    severity: Severity::High,
                    component: "real_proxy".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::NoSourceDestinationCorrelation,
                    violation_path: "Transport stores both source and destination".to_string(),
                    severity: Severity::High,
                    component: "real_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::NoSourceDestinationCorrelation,
                    violation_path: "Session state correlation".to_string(),
                    severity: Severity::Medium,
                    component: "session".to_string(),
                },

                // ISP Traffic Encrypted
                AttackSurface {
                    invariant_id: InvariantId::IspTrafficEncrypted,
                    violation_path: "Plaintext CONNECT before TLS".to_string(),
                    severity: Severity::High,
                    component: "relay_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::IspTrafficEncrypted,
                    violation_path: "DNS queries in plaintext".to_string(),
                    severity: Severity::High,
                    component: "dns_resolver".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::IspTrafficEncrypted,
                    violation_path: "Control channel metadata leak".to_string(),
                    severity: Severity::Medium,
                    component: "control_channel".to_string(),
                },

                // Entry Node Blind To Destination
                AttackSurface {
                    invariant_id: InvariantId::EntryNodeBlindToDestination,
                    violation_path: "SNI visible to entry relay".to_string(),
                    severity: Severity::High,
                    component: "relay_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::EntryNodeBlindToDestination,
                    violation_path: "CONNECT target in relay protocol".to_string(),
                    severity: Severity::High,
                    component: "control_channel".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::EntryNodeBlindToDestination,
                    violation_path: "Traffic analysis correlation".to_string(),
                    severity: Severity::Medium,
                    component: "async_tunnel".to_string(),
                },

                // Exit Node Blind To Source
                AttackSurface {
                    invariant_id: InvariantId::ExitNodeBlindToSource,
                    violation_path: "Source IP forwarded in headers".to_string(),
                    severity: Severity::High,
                    component: "real_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::ExitNodeBlindToSource,
                    violation_path: "Relay chain metadata exposure".to_string(),
                    severity: Severity::Medium,
                    component: "relay_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::ExitNodeBlindToSource,
                    violation_path: "Session correlation via timing".to_string(),
                    severity: Severity::Low,
                    component: "tunnel_stats".to_string(),
                },

                // Logging Opt In
                AttackSurface {
                    invariant_id: InvariantId::LoggingOptIn,
                    violation_path: "Default println! statements".to_string(),
                    severity: Severity::Medium,
                    component: "real_proxy".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::LoggingOptIn,
                    violation_path: "Error logging with sensitive data".to_string(),
                    severity: Severity::High,
                    component: "real_transport".to_string(),
                },
                AttackSurface {
                    invariant_id: InvariantId::LoggingOptIn,
                    violation_path: "Debug logs in release builds".to_string(),
                    severity: Severity::Low,
                    component: "logging".to_string(),
                },
            ],
        }
    }

    pub fn get_surfaces_for_invariant(&self, invariant_id: &InvariantId) -> Vec<&AttackSurface> {
        self.surfaces.iter()
            .filter(|surface| &surface.invariant_id == invariant_id)
            .collect()
    }

    pub fn get_high_severity_surfaces(&self) -> Vec<&AttackSurface> {
        self.surfaces.iter()
            .filter(|surface| surface.severity == Severity::High)
            .collect()
    }

    pub fn get_surfaces_for_component(&self, component: &str) -> Vec<&AttackSurface> {
        self.surfaces.iter()
            .filter(|surface| surface.component == component)
            .collect()
    }
}

impl Default for AttackSurfaceEnumeration {
    fn default() -> Self {
        Self::new()
    }
}