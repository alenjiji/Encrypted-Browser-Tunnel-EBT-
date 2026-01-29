#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InvariantId {
    DnsResolutionAtExitOnly,
    NoSourceDestinationCorrelation,
    IspTrafficEncrypted,
    EntryNodeBlindToDestination,
    ExitNodeBlindToSource,
    LoggingOptIn,
}

#[derive(Debug, Clone)]
pub enum InvariantViolation {
    DnsResolutionAtExitOnly {
        component: String,
        attempted_hostname: String,
    },
    NoSourceDestinationCorrelation {
        component: String,
        has_source_ip: bool,
        has_destination: bool,
    },
    IspTrafficEncrypted {
        component: String,
        plaintext_detected: bool,
    },
    EntryNodeBlindToDestination {
        entry_node: String,
        destination_exposed: String,
    },
    ExitNodeBlindToSource {
        exit_node: String,
        source_ip_exposed: String,
    },
    LoggingOptIn {
        component: String,
        implicit_logging: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ThreatInvariant {
    pub id: InvariantId,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct InvariantContext {
    pub component_name: String,
    pub has_source_ip: bool,
    pub has_destination_hostname: bool,
    pub traffic_encrypted: bool,
    pub dns_resolution_attempted: bool,
    pub logging_enabled: bool,
}

pub struct ThreatInvariants {
    invariants: Vec<ThreatInvariant>,
}

impl ThreatInvariants {
    pub fn new() -> Self {
        Self {
            invariants: vec![
                ThreatInvariant {
                    id: InvariantId::DnsResolutionAtExitOnly,
                    description: "DNS resolution must only occur at the exit node".to_string(),
                    enabled: true,
                },
                ThreatInvariant {
                    id: InvariantId::NoSourceDestinationCorrelation,
                    description: "No component may have access to both source IP and destination hostname".to_string(),
                    enabled: true,
                },
                ThreatInvariant {
                    id: InvariantId::IspTrafficEncrypted,
                    description: "ISP-facing traffic must be encrypted before leaving local machine".to_string(),
                    enabled: true,
                },
                ThreatInvariant {
                    id: InvariantId::EntryNodeBlindToDestination,
                    description: "Entry node must never know final destination".to_string(),
                    enabled: true,
                },
                ThreatInvariant {
                    id: InvariantId::ExitNodeBlindToSource,
                    description: "Exit node must never know client source IP".to_string(),
                    enabled: true,
                },
                ThreatInvariant {
                    id: InvariantId::LoggingOptIn,
                    description: "Logging must be opt-in and disabled by default".to_string(),
                    enabled: true,
                },
            ],
        }
    }

    pub fn get_invariant(&self, id: &InvariantId) -> Option<&ThreatInvariant> {
        self.invariants.iter().find(|inv| &inv.id == id)
    }

    pub fn is_enabled(&self, id: &InvariantId) -> bool {
        self.get_invariant(id).map_or(false, |inv| inv.enabled)
    }

    pub fn check_context(&self, context: &InvariantContext) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Check DNS resolution invariant
        if self.is_enabled(&InvariantId::DnsResolutionAtExitOnly) {
            if context.dns_resolution_attempted && context.component_name != "exit_node" {
                violations.push(InvariantViolation::DnsResolutionAtExitOnly {
                    component: context.component_name.clone(),
                    attempted_hostname: "detected".to_string(),
                });
            }
        }

        // Check source-destination correlation
        if self.is_enabled(&InvariantId::NoSourceDestinationCorrelation) {
            if context.has_source_ip && context.has_destination_hostname {
                violations.push(InvariantViolation::NoSourceDestinationCorrelation {
                    component: context.component_name.clone(),
                    has_source_ip: true,
                    has_destination: true,
                });
            }
        }

        // Check ISP traffic encryption
        if self.is_enabled(&InvariantId::IspTrafficEncrypted) {
            if !context.traffic_encrypted && context.component_name.contains("isp_facing") {
                violations.push(InvariantViolation::IspTrafficEncrypted {
                    component: context.component_name.clone(),
                    plaintext_detected: true,
                });
            }
        }

        // Check logging opt-in
        if self.is_enabled(&InvariantId::LoggingOptIn) {
            if context.logging_enabled && context.component_name != "explicit_logging" {
                violations.push(InvariantViolation::LoggingOptIn {
                    component: context.component_name.clone(),
                    implicit_logging: true,
                });
            }
        }

        violations
    }
}

impl Default for ThreatInvariants {
    fn default() -> Self {
        Self::new()
    }
}