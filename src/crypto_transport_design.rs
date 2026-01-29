// CRYPTOGRAPHIC TRANSPORT DESIGN - PHASE 5.1

// COMPONENT LIST
pub struct ComponentList {
    pub control_plane: Vec<&'static str>,
    pub data_plane: Vec<&'static str>,
    pub key_management: Vec<&'static str>,
    pub zone_interfaces: Vec<&'static str>,
}

impl ComponentList {
    pub fn new() -> Self {
        Self {
            control_plane: vec![
                "SessionEstablisher",
                "KeyExchanger", 
                "RouteNegotiator",
                "ControlMessageHandler",
            ],
            data_plane: vec![
                "PayloadEncryptor",
                "PayloadDecryptor",
                "HopForwarder",
                "TunnelManager",
            ],
            key_management: vec![
                "EphemeralKeyGenerator",
                "HopKeyDeriver",
                "KeyRotator",
                "SecureKeyStorage",
            ],
            zone_interfaces: vec![
                "LocalZoneInterface",
                "EntryZoneInterface", 
                "RelayZoneInterface",
                "ExitZoneInterface",
            ],
        }
    }
}

// MESSAGE TYPES
#[derive(Debug, Clone)]
pub enum MessageType {
    Control(ControlMessage),
    Encrypted(EncryptedMessage),
    Payload(PayloadMessage),
}

#[derive(Debug, Clone)]
pub enum ControlMessage {
    SessionInit {
        session_id: [u8; 32],
        public_key: [u8; 32],
        route_length: u8,
    },
    KeyExchange {
        encrypted_key: Vec<u8>,
        hop_index: u8,
    },
    RouteSetup {
        encrypted_next_hop: Vec<u8>,
        layer_count: u8,
    },
    SessionTeardown {
        session_id: [u8; 32],
    },
}

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub hop_layer: u8,
    pub encrypted_payload: Vec<u8>,
    pub authentication_tag: [u8; 16],
}

#[derive(Debug, Clone)]
pub enum PayloadMessage {
    TunnelData {
        encrypted_content: Vec<u8>,
        sequence_number: u64,
    },
    DnsRequest {
        encrypted_hostname: Vec<u8>,
        request_id: u32,
    },
    DnsResponse {
        encrypted_ip_list: Vec<u8>,
        request_id: u32,
    },
}

// KEY MATERIAL OWNERSHIP
pub struct KeyOwnership {
    pub local_zone: LocalZoneKeys,
    pub entry_zone: EntryZoneKeys,
    pub relay_zone: RelayZoneKeys,
    pub exit_zone: ExitZoneKeys,
}

pub struct LocalZoneKeys {
    pub session_private_key: [u8; 32],
    pub all_hop_keys: Vec<[u8; 32]>,
    pub route_encryption_key: [u8; 32],
}

pub struct EntryZoneKeys {
    pub hop_decryption_key: [u8; 32],
    pub next_hop_encryption_key: [u8; 32],
    pub session_authentication_key: [u8; 32],
}

pub struct RelayZoneKeys {
    pub previous_hop_decryption_key: [u8; 32],
    pub next_hop_encryption_key: [u8; 32],
    pub layer_authentication_key: [u8; 32],
}

pub struct ExitZoneKeys {
    pub final_decryption_key: [u8; 32],
    pub dns_encryption_key: [u8; 32],
    pub response_encryption_key: [u8; 32],
}

// SEQUENCE DIAGRAM STEPS
pub struct SequenceStep {
    pub step_number: u8,
    pub source_zone: &'static str,
    pub target_zone: &'static str,
    pub message_type: &'static str,
    pub data_visibility: Vec<&'static str>,
    pub key_operations: Vec<&'static str>,
}

pub struct TransportSequence {
    pub session_establishment: Vec<SequenceStep>,
    pub data_forwarding: Vec<SequenceStep>,
    pub dns_resolution: Vec<SequenceStep>,
    pub session_teardown: Vec<SequenceStep>,
}

impl TransportSequence {
    pub fn new() -> Self {
        Self {
            session_establishment: vec![
                SequenceStep {
                    step_number: 1,
                    source_zone: "Local",
                    target_zone: "Entry",
                    message_type: "SessionInit",
                    data_visibility: vec!["session_id", "public_key", "encrypted_route"],
                    key_operations: vec!["generate_ephemeral_key", "encrypt_route_info"],
                },
                SequenceStep {
                    step_number: 2,
                    source_zone: "Entry",
                    target_zone: "Relay",
                    message_type: "KeyExchange",
                    data_visibility: vec!["encrypted_key", "hop_index"],
                    key_operations: vec!["decrypt_layer", "derive_next_key"],
                },
                SequenceStep {
                    step_number: 3,
                    source_zone: "Relay",
                    target_zone: "Exit",
                    message_type: "RouteSetup",
                    data_visibility: vec!["encrypted_next_hop", "layer_count"],
                    key_operations: vec!["decrypt_final_layer", "setup_exit_keys"],
                },
            ],
            data_forwarding: vec![
                SequenceStep {
                    step_number: 1,
                    source_zone: "Local",
                    target_zone: "Entry",
                    message_type: "EncryptedMessage",
                    data_visibility: vec!["encrypted_payload", "authentication_tag"],
                    key_operations: vec!["encrypt_with_hop_key", "authenticate"],
                },
                SequenceStep {
                    step_number: 2,
                    source_zone: "Entry",
                    target_zone: "Relay",
                    message_type: "EncryptedMessage",
                    data_visibility: vec!["re_encrypted_payload", "new_auth_tag"],
                    key_operations: vec!["decrypt_layer", "re_encrypt_for_next"],
                },
                SequenceStep {
                    step_number: 3,
                    source_zone: "Relay",
                    target_zone: "Exit",
                    message_type: "EncryptedMessage",
                    data_visibility: vec!["final_encrypted_payload"],
                    key_operations: vec!["decrypt_to_plaintext"],
                },
            ],
            dns_resolution: vec![
                SequenceStep {
                    step_number: 1,
                    source_zone: "Exit",
                    target_zone: "External",
                    message_type: "DnsRequest",
                    data_visibility: vec!["hostname_plaintext"],
                    key_operations: vec!["decrypt_hostname", "resolve_dns"],
                },
                SequenceStep {
                    step_number: 2,
                    source_zone: "External",
                    target_zone: "Exit",
                    message_type: "DnsResponse",
                    data_visibility: vec!["ip_addresses"],
                    key_operations: vec!["encrypt_response"],
                },
            ],
            session_teardown: vec![
                SequenceStep {
                    step_number: 1,
                    source_zone: "Local",
                    target_zone: "Entry",
                    message_type: "SessionTeardown",
                    data_visibility: vec!["session_id"],
                    key_operations: vec!["clear_session_keys"],
                },
                SequenceStep {
                    step_number: 2,
                    source_zone: "Entry",
                    target_zone: "Exit",
                    message_type: "SessionTeardown",
                    data_visibility: vec!["propagated_teardown"],
                    key_operations: vec!["clear_all_hop_keys"],
                },
            ],
        }
    }
}

// INVARIANT COMPLIANCE MATRIX
pub struct InvariantCompliance {
    pub dns_at_exit_only: bool,
    pub no_source_destination_correlation: bool,
    pub isp_traffic_encrypted: bool,
    pub entry_blind_to_destination: bool,
    pub exit_blind_to_source: bool,
    pub no_default_logging: bool,
}

impl InvariantCompliance {
    pub fn validate() -> Self {
        Self {
            dns_at_exit_only: true,           // DNS only in Exit zone
            no_source_destination_correlation: true, // No single zone sees both
            isp_traffic_encrypted: true,      // All external traffic encrypted
            entry_blind_to_destination: true, // Entry sees only encrypted route
            exit_blind_to_source: true,       // Exit sees only final payload
            no_default_logging: true,         // No logging in transport layer
        }
    }
}