#[cfg(test)]
mod crypto_transport_tests {
    use super::*;
    use crate::control_plane::*;
    use crate::data_plane::*;
    use crate::key_management::*;
    use crate::zone_interfaces::*;
    use crate::trust_boundaries::*;
    use crate::threat_invariants::*;

    #[tokio::test]
    async fn test_entry_cannot_access_destination() {
        let entry_interface = EntryZoneInterface::new();
        
        assert!(!entry_interface.has_destination_hostname());
        
        let context = InvariantContext {
            component_name: "entry_zone".to_string(),
            has_source_ip: entry_interface.has_source_ip(),
            has_destination_hostname: entry_interface.has_destination_hostname(),
            traffic_encrypted: true,
            dns_resolution_attempted: false,
            logging_enabled: false,
        };
        
        let invariants = ThreatInvariants::new();
        let violations = invariants.check_context(&context);
        
        assert!(violations.is_empty());
    }

    #[tokio::test]
    async fn test_exit_cannot_access_source_ip() {
        let exit_interface = ExitZoneInterface::new().unwrap();
        
        assert!(!exit_interface.has_source_ip());
        
        let context = InvariantContext {
            component_name: "exit_zone".to_string(),
            has_source_ip: exit_interface.has_source_ip(),
            has_destination_hostname: exit_interface.has_destination_hostname(),
            traffic_encrypted: true,
            dns_resolution_attempted: true,
            logging_enabled: false,
        };
        
        let invariants = ThreatInvariants::new();
        let violations = invariants.check_context(&context);
        
        assert!(violations.is_empty());
    }

    #[tokio::test]
    async fn test_relay_sees_neither_source_nor_destination() {
        let relay_interface = RelayZoneInterface::new();
        
        assert!(!relay_interface.has_source_ip());
        assert!(!relay_interface.has_destination_hostname());
        
        let context = InvariantContext {
            component_name: "relay_zone".to_string(),
            has_source_ip: relay_interface.has_source_ip(),
            has_destination_hostname: relay_interface.has_destination_hostname(),
            traffic_encrypted: true,
            dns_resolution_attempted: false,
            logging_enabled: false,
        };
        
        let invariants = ThreatInvariants::new();
        let violations = invariants.check_context(&context);
        
        assert!(violations.is_empty());
    }

    #[tokio::test]
    async fn test_dns_only_callable_from_exit_zone() {
        let exit_resolver = ExitZoneDnsResolver::new().unwrap();
        let result = exit_resolver.resolve_hostname("example.com").await;
        assert!(result.is_ok());
        
        let entry_tunnel_manager = TunnelManager::new(TrustZone::Entry);
        let context = InvariantContext {
            component_name: "entry_zone".to_string(),
            has_source_ip: true,
            has_destination_hostname: false,
            traffic_encrypted: true,
            dns_resolution_attempted: true,
            logging_enabled: false,
        };
        
        let invariants = ThreatInvariants::new();
        let violations = invariants.check_context(&context);
        
        assert!(!violations.is_empty());
        assert!(matches!(violations[0], InvariantViolation::DnsResolutionAtExitOnly { .. }));
    }

    #[tokio::test]
    async fn test_encrypted_payload_required_in_transit() {
        let session_id = SessionId("test-session-001".to_string());
        
        let entry_manager = TunnelManager::new(TrustZone::Entry);
        let encrypted_payload = EncryptedPayload(vec![1, 2, 3, 4]);
        
        let result = entry_manager.process_inbound(&session_id, encrypted_payload).await;
        assert!(result.is_ok());
        
        if let Ok(ProcessResult::Forward(forwarded)) = result {
            assert!(!forwarded.0.is_empty());
        } else {
            panic!("Expected forwarded encrypted payload");
        }
    }

    #[tokio::test]
    async fn test_plaintext_only_in_local_and_exit_zones() {
        let exit_manager = TunnelManager::new(TrustZone::Exit);
        let session_id = SessionId("test-session-002".to_string());
        let encrypted_payload = EncryptedPayload(vec![1, 2, 3, 4]);
        
        let result = exit_manager.process_inbound(&session_id, encrypted_payload).await;
        assert!(result.is_ok());
        
        if let Ok(ProcessResult::Deliver(plaintext)) = result {
            assert!(!plaintext.0.is_empty());
        } else {
            panic!("Expected plaintext payload in exit zone");
        }
        
        let relay_decryptor = PayloadDecryptor::new(TrustZone::Relay);
        let encrypted = EncryptedPayload(vec![1, 2, 3, 4]);
        let plaintext_result = relay_decryptor.decrypt_to_plaintext(&session_id, &encrypted).await;
        assert!(plaintext_result.is_err());
        assert!(matches!(plaintext_result.unwrap_err(), DataError::PlaintextNotAllowed));
    }

    #[tokio::test]
    async fn test_key_storage_zone_enforcement() {
        let mut local_storage = SecureKeyStorage::new(TrustZone::Local);
        let local_keys = LocalZoneKeys {
            session_private_key: [1u8; 32],
            all_hop_keys: vec![[2u8; 32]],
            route_encryption_key: [3u8; 32],
        };
        
        let result = local_storage.store_local_keys(local_keys).await;
        assert!(result.is_ok());
        
        let entry_keys = EntryZoneKeys {
            hop_decryption_key: [4u8; 32],
            next_hop_encryption_key: [5u8; 32],
            session_authentication_key: [6u8; 32],
        };
        
        let invalid_result = local_storage.store_entry_keys(entry_keys).await;
        assert!(invalid_result.is_err());
        assert!(matches!(invalid_result.unwrap_err(), KeyError::InvalidZone));
    }

    #[tokio::test]
    async fn test_session_establishment_zone_restrictions() {
        let local_establisher = SessionEstablisher::new(TrustZone::Local);
        let route = EncryptedRoute(vec![1, 2, 3, 4]);
        let result = local_establisher.initiate_session(route).await;
        assert!(result.is_ok());
        
        let entry_establisher = SessionEstablisher::new(TrustZone::Entry);
        let route = EncryptedRoute(vec![1, 2, 3, 4]);
        let invalid_result = entry_establisher.initiate_session(route).await;
        assert!(invalid_result.is_err());
        assert!(matches!(invalid_result.unwrap_err(), ControlError::InvalidZone));
    }

    #[tokio::test]
    async fn test_source_destination_correlation_blocked() {
        let local_interface = LocalZoneInterface::new();
        assert!(local_interface.has_source_ip());
        assert!(local_interface.has_destination_hostname());
        
        let context = InvariantContext {
            component_name: "local_zone".to_string(),
            has_source_ip: true,
            has_destination_hostname: true,
            traffic_encrypted: true,
            dns_resolution_attempted: false,
            logging_enabled: false,
        };
        
        let invariants = ThreatInvariants::new();
        let violations = invariants.check_context(&context);
        
        assert!(!violations.is_empty());
        assert!(matches!(violations[0], InvariantViolation::NoSourceDestinationCorrelation { .. }));
    }

    #[tokio::test]
    async fn test_hop_key_derivation_zone_restrictions() {
        let entry_deriver = HopKeyDeriver::new(TrustZone::Entry);
        let hop_key = HopKey([1u8; 32]);
        let result = entry_deriver.derive_next_hop_key(&hop_key).await;
        assert!(result.is_ok());
        
        let local_deriver = HopKeyDeriver::new(TrustZone::Local);
        let invalid_result = local_deriver.derive_next_hop_key(&hop_key).await;
        assert!(invalid_result.is_err());
        assert!(matches!(invalid_result.unwrap_err(), KeyError::InvalidZone));
    }
}