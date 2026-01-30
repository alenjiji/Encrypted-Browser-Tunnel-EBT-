use crate::trust_boundaries::*;
use crate::control_plane::{SessionId, HopKey, PrivateKey, PublicKey};
use std::collections::HashMap;

pub struct EphemeralKeyGenerator {
    zone: TrustZone,
}

impl EphemeralKeyGenerator {
    pub fn new(zone: TrustZone) -> Self {
        Self { zone }
    }

    pub async fn generate_session_keypair(&self) -> Result<(PrivateKey, PublicKey), KeyError> {
        match self.zone {
            TrustZone::Local => {
                let private_key = PrivateKey([0u8; 32]);
                let public_key = PublicKey([0u8; 32]);
                Ok((private_key, public_key))
            }
            _ => Err(KeyError::InvalidZone),
        }
    }

    pub async fn generate_hop_key(&self) -> Result<HopKey, KeyError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay | TrustZone::Exit => {
                Ok(HopKey([0u8; 32]))
            }
            _ => Err(KeyError::InvalidZone),
        }
    }
}

pub struct HopKeyDeriver {
    zone: TrustZone,
}

impl HopKeyDeriver {
    pub fn new(zone: TrustZone) -> Self {
        Self { zone }
    }

    pub async fn derive_next_hop_key(&self, current_key: &HopKey) -> Result<HopKey, KeyError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay => {
                Ok(HopKey([0u8; 32]))
            }
            _ => Err(KeyError::InvalidZone),
        }
    }
}

pub struct KeyRotator {
    zone: TrustZone,
    rotation_counter: u64,
}

impl KeyRotator {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone,
            rotation_counter: 0,
        }
    }

    pub async fn rotate_session_keys(&mut self, session_id: &SessionId) -> Result<(), KeyError> {
        match self.zone {
            TrustZone::Local | TrustZone::Entry | TrustZone::Relay | TrustZone::Exit => {
                self.rotation_counter += 1;
                Ok(())
            }
            _ => Err(KeyError::InvalidZone),
        }
    }
}

pub struct SecureKeyStorage {
    zone: TrustZone,
    local_keys: Option<LocalZoneKeys>,
    entry_keys: Option<EntryZoneKeys>,
    relay_keys: Option<RelayZoneKeys>,
    exit_keys: Option<ExitZoneKeys>,
}

impl SecureKeyStorage {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone,
            local_keys: None,
            entry_keys: None,
            relay_keys: None,
            exit_keys: None,
        }
    }

    pub async fn store_local_keys(&mut self, keys: LocalZoneKeys) -> Result<(), KeyError> {
        match self.zone {
            TrustZone::Local => {
                self.local_keys = Some(keys);
                Ok(())
            }
            _ => Err(KeyError::InvalidZone),
        }
    }

    pub async fn store_entry_keys(&mut self, keys: EntryZoneKeys) -> Result<(), KeyError> {
        match self.zone {
            TrustZone::Entry => {
                self.entry_keys = Some(keys);
                Ok(())
            }
            _ => Err(KeyError::InvalidZone),
        }
    }

    pub async fn store_relay_keys(&mut self, keys: RelayZoneKeys) -> Result<(), KeyError> {
        match self.zone {
            TrustZone::Relay => {
                self.relay_keys = Some(keys);
                Ok(())
            }
            _ => Err(KeyError::InvalidZone),
        }
    }

    pub async fn store_exit_keys(&mut self, keys: ExitZoneKeys) -> Result<(), KeyError> {
        match self.zone {
            TrustZone::Exit => {
                self.exit_keys = Some(keys);
                Ok(())
            }
            _ => Err(KeyError::InvalidZone),
        }
    }

    pub async fn clear_all_keys(&mut self) -> Result<(), KeyError> {
        self.local_keys = None;
        self.entry_keys = None;
        self.relay_keys = None;
        self.exit_keys = None;
        Ok(())
    }
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

#[derive(Debug)]
pub enum KeyError {
    InvalidZone,
    GenerationFailed,
    DerivationFailed,
    StorageFailed,
}