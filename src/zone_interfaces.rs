use crate::trust_boundaries::{TrustZone, DestinationHostname, SessionId as TrustSessionId, EncryptedPayload as TrustEncryptedPayload, PlaintextPayload};
use crate::control_plane::{SessionId, EncryptedRoute};
use crate::data_plane::{TunnelManager, EncryptedPayload, ProcessResult, ExitZoneDnsResolver};
use crate::key_management::SecureKeyStorage;

pub struct LocalZoneInterface {
    tunnel_manager: TunnelManager,
    key_storage: SecureKeyStorage,
}

impl LocalZoneInterface {
    pub fn new() -> Self {
        Self {
            tunnel_manager: TunnelManager::new(TrustZone::Local),
            key_storage: SecureKeyStorage::new(TrustZone::Local),
        }
    }

    pub async fn initiate_tunnel(&mut self, _destination: DestinationHostname, _route: EncryptedRoute) -> Result<TrustSessionId, ZoneError> {
        let session_id = SessionId("local-session".to_string());
        Ok(TrustSessionId(format!("{:?}", session_id)))
    }

    pub async fn send_data(&self, _session_id: &TrustSessionId, plaintext: PlaintextPayload) -> Result<TrustEncryptedPayload, ZoneError> {
        let control_session = SessionId("local-control".to_string());
        let encrypted = self.tunnel_manager.encryptor.encrypt_payload(&control_session, &plaintext.0).await
            .map_err(|_| ZoneError::EncryptionFailed)?;
        Ok(TrustEncryptedPayload(encrypted.0))
    }

    pub fn has_source_ip(&self) -> bool {
        true
    }

    pub fn has_destination_hostname(&self) -> bool {
        true
    }
}

pub struct EntryZoneInterface {
    tunnel_manager: TunnelManager,
    key_storage: SecureKeyStorage,
}

impl EntryZoneInterface {
    pub fn new() -> Self {
        Self {
            tunnel_manager: TunnelManager::new(TrustZone::Entry),
            key_storage: SecureKeyStorage::new(TrustZone::Entry),
        }
    }

    pub async fn process_session_init(&mut self, _session_id: TrustSessionId, _encrypted_key: Vec<u8>) -> Result<(), ZoneError> {
        Ok(())
    }

    pub async fn forward_payload(&self, _session_id: &TrustSessionId, encrypted: TrustEncryptedPayload) -> Result<TrustEncryptedPayload, ZoneError> {
        let control_session = SessionId("entry-control".to_string());
        let data_encrypted = EncryptedPayload(encrypted.0);
        match self.tunnel_manager.process_inbound(&control_session, data_encrypted).await {
            Ok(ProcessResult::Forward(forwarded)) => Ok(TrustEncryptedPayload(forwarded.0)),
            _ => Err(ZoneError::ForwardingFailed),
        }
    }

    pub fn has_source_ip(&self) -> bool {
        true
    }

    pub fn has_destination_hostname(&self) -> bool {
        false
    }
}

pub struct RelayZoneInterface {
    tunnel_manager: TunnelManager,
    key_storage: SecureKeyStorage,
}

impl RelayZoneInterface {
    pub fn new() -> Self {
        Self {
            tunnel_manager: TunnelManager::new(TrustZone::Relay),
            key_storage: SecureKeyStorage::new(TrustZone::Relay),
        }
    }

    pub async fn relay_payload(&self, _session_id: &TrustSessionId, encrypted: TrustEncryptedPayload) -> Result<TrustEncryptedPayload, ZoneError> {
        let control_session = SessionId("relay-control".to_string());
        let data_encrypted = EncryptedPayload(encrypted.0);
        match self.tunnel_manager.process_inbound(&control_session, data_encrypted).await {
            Ok(ProcessResult::Forward(forwarded)) => Ok(TrustEncryptedPayload(forwarded.0)),
            _ => Err(ZoneError::RelayFailed),
        }
    }

    pub fn has_source_ip(&self) -> bool {
        false
    }

    pub fn has_destination_hostname(&self) -> bool {
        false
    }
}

pub struct ExitZoneInterface {
    tunnel_manager: TunnelManager,
    key_storage: SecureKeyStorage,
    dns_resolver: ExitZoneDnsResolver,
}

impl ExitZoneInterface {
    pub fn new() -> Result<Self, ZoneError> {
        Ok(Self {
            tunnel_manager: TunnelManager::new(TrustZone::Exit),
            key_storage: SecureKeyStorage::new(TrustZone::Exit),
            dns_resolver: ExitZoneDnsResolver::new().map_err(|_| ZoneError::DnsResolverFailed)?,
        })
    }

    pub async fn terminate_tunnel(&self, _session_id: &TrustSessionId, encrypted: TrustEncryptedPayload) -> Result<PlaintextPayload, ZoneError> {
        let control_session = SessionId("exit-control".to_string());
        let data_encrypted = EncryptedPayload(encrypted.0);
        match self.tunnel_manager.process_inbound(&control_session, data_encrypted).await {
            Ok(ProcessResult::Deliver(plaintext)) => Ok(plaintext),
            _ => Err(ZoneError::TerminationFailed),
        }
    }

    pub async fn resolve_dns(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, ZoneError> {
        let addrs: Vec<std::net::IpAddr> = self.dns_resolver.resolve_hostname(hostname).await
            .map_err(|_| ZoneError::DnsResolutionFailed)?;
        Ok(addrs)
    }

    pub fn has_source_ip(&self) -> bool {
        false
    }

    pub fn has_destination_hostname(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum ZoneError {
    SessionInitFailed,
    KeyExchangeFailed,
    EncryptionFailed,
    ForwardingFailed,
    RelayFailed,
    TerminationFailed,
    DnsResolverFailed,
    DnsResolutionFailed,
}