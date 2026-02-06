use crate::trust_boundaries::*;
use crate::control_plane::{SessionId, HopKey};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EncryptedPayload(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct AuthenticationTag([u8; 16]);

#[derive(Debug, Clone)]
pub struct SequenceNumber(u64);

pub struct PayloadEncryptor {
    zone: TrustZone,
    hop_keys: HashMap<SessionId, HopKey>,
}

impl PayloadEncryptor {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone,
            hop_keys: HashMap::new(),
        }
    }

    pub async fn encrypt_payload(&self, _session_id: &SessionId, plaintext: &[u8]) -> Result<EncryptedPayload, DataError> {
        match self.zone {
            TrustZone::Local | TrustZone::Entry | TrustZone::Relay => {
                Ok(EncryptedPayload(plaintext.to_vec()))
            }
            _ => Err(DataError::InvalidZone),
        }
    }
}

pub struct PayloadDecryptor {
    zone: TrustZone,
    hop_keys: HashMap<SessionId, HopKey>,
}

impl PayloadDecryptor {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone,
            hop_keys: HashMap::new(),
        }
    }

    pub async fn decrypt_hop_payload(&self, _session_id: &SessionId, encrypted: &EncryptedPayload) -> Result<Vec<u8>, DataError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay | TrustZone::Exit => {
                Ok(encrypted.0.clone())
            }
            _ => Err(DataError::InvalidZone),
        }
    }

    pub async fn decrypt_to_plaintext(&self, _session_id: &SessionId, encrypted: &EncryptedPayload) -> Result<PlaintextPayload, DataError> {
        match self.zone {
            TrustZone::Exit => {
                Ok(PlaintextPayload(encrypted.0.clone()))
            }
            _ => Err(DataError::PlaintextNotAllowed),
        }
    }
}

pub struct HopForwarder {
    zone: TrustZone,
}

impl HopForwarder {
    pub fn new(zone: TrustZone) -> Self {
        Self { zone }
    }

    pub async fn forward_to_next_hop(&self, encrypted: EncryptedPayload) -> Result<EncryptedPayload, DataError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay => Ok(encrypted),
            _ => Err(DataError::InvalidZone),
        }
    }
}

pub struct TunnelManager {
    zone: TrustZone,
    pub encryptor: PayloadEncryptor,
    decryptor: PayloadDecryptor,
    forwarder: HopForwarder,
}

impl TunnelManager {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone: zone.clone(),
            encryptor: PayloadEncryptor::new(zone.clone()),
            decryptor: PayloadDecryptor::new(zone.clone()),
            forwarder: HopForwarder::new(zone),
        }
    }

    pub async fn process_inbound(&self, session_id: &SessionId, encrypted: EncryptedPayload) -> Result<ProcessResult, DataError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay => {
                let decrypted = self.decryptor.decrypt_hop_payload(session_id, &encrypted).await?;
                let re_encrypted = self.encryptor.encrypt_payload(session_id, &decrypted).await?;
                let forwarded = self.forwarder.forward_to_next_hop(re_encrypted).await?;
                Ok(ProcessResult::Forward(forwarded))
            }
            TrustZone::Exit => {
                let plaintext = self.decryptor.decrypt_to_plaintext(session_id, &encrypted).await?;
                Ok(ProcessResult::Deliver(plaintext))
            }
            _ => Err(DataError::InvalidZone),
        }
    }
}

#[derive(Debug)]
pub enum ProcessResult {
    Forward(EncryptedPayload),
    Deliver(PlaintextPayload),
}

#[derive(Debug)]
pub enum DataError {
    InvalidZone,
    PlaintextNotAllowed,
    EncryptionFailed,
    DecryptionFailed,
}

pub struct ExitZoneDnsResolver {
    zone: TrustZone,
}

impl ExitZoneDnsResolver {
    pub fn new() -> Result<Self, DataError> {
        Ok(Self {
            zone: TrustZone::Exit,
        })
    }

    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, DataError> {
        match self.zone {
            TrustZone::Exit => {
                use std::net::ToSocketAddrs;
                let addrs: Vec<std::net::IpAddr> = format!("{}:0", hostname)
                    .to_socket_addrs()
                    .map_err(|_| DataError::InvalidZone)?
                    .map(|addr| addr.ip())
                    .collect();
                Ok(addrs)
            }
            _ => Err(DataError::InvalidZone),
        }
    }
}