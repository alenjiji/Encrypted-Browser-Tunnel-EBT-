#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrustZone {
    Local,
    Entry,
    Relay,
    Exit,
    External,
}

#[derive(Debug, Clone)]
pub struct SourceIp(String);

#[derive(Debug, Clone)]
pub struct DestinationHostname(String);

#[derive(Debug, Clone)]
pub struct EncryptedPayload(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct PlaintextPayload(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct RelayMetadata {
    pub hop_count: u32,
    pub encrypted_routing: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionId(pub String);

pub trait LocalZoneData {
    fn source_ip(&self) -> &SourceIp;
    fn destination_hostname(&self) -> &DestinationHostname;
    fn plaintext_payload(&self) -> &PlaintextPayload;
    fn session_id(&self) -> &SessionId;
}

pub trait EntryZoneData {
    fn source_ip(&self) -> &SourceIp;
    fn encrypted_payload(&self) -> &EncryptedPayload;
    fn next_hop_metadata(&self) -> &RelayMetadata;
    fn session_id(&self) -> &SessionId;
}

pub trait RelayZoneData {
    fn encrypted_payload(&self) -> &EncryptedPayload;
    fn previous_hop_metadata(&self) -> &RelayMetadata;
    fn next_hop_metadata(&self) -> &RelayMetadata;
}

pub trait ExitZoneData {
    fn destination_hostname(&self) -> &DestinationHostname;
    fn plaintext_payload(&self) -> &PlaintextPayload;
    fn previous_hop_metadata(&self) -> &RelayMetadata;
}

pub trait ExternalZoneData {
    fn plaintext_payload(&self) -> &PlaintextPayload;
}

pub struct TrustBoundary<T> {
    zone: TrustZone,
    data: T,
}

impl<T> TrustBoundary<T> {
    pub fn new(zone: TrustZone, data: T) -> Self {
        Self { zone, data }
    }

    pub fn zone(&self) -> &TrustZone {
        &self.zone
    }
}

impl<T: LocalZoneData> TrustBoundary<T> {
    pub fn as_local(&self) -> Option<&T> {
        match self.zone {
            TrustZone::Local => Some(&self.data),
            _ => None,
        }
    }
}

impl<T: EntryZoneData> TrustBoundary<T> {
    pub fn as_entry(&self) -> Option<&T> {
        match self.zone {
            TrustZone::Entry => Some(&self.data),
            _ => None,
        }
    }
}

impl<T: RelayZoneData> TrustBoundary<T> {
    pub fn as_relay(&self) -> Option<&T> {
        match self.zone {
            TrustZone::Relay => Some(&self.data),
            _ => None,
        }
    }
}

impl<T: ExitZoneData> TrustBoundary<T> {
    pub fn as_exit(&self) -> Option<&T> {
        match self.zone {
            TrustZone::Exit => Some(&self.data),
            _ => None,
        }
    }
}

impl<T: ExternalZoneData> TrustBoundary<T> {
    pub fn as_external(&self) -> Option<&T> {
        match self.zone {
            TrustZone::External => Some(&self.data),
            _ => None,
        }
    }
}

pub struct ZoneTransition;

impl ZoneTransition {
    pub fn local_to_entry<T: LocalZoneData>(
        _local_data: TrustBoundary<T>,
    ) -> Result<TrustBoundary<()>, &'static str> {
        Ok(TrustBoundary::new(TrustZone::Entry, ()))
    }

    pub fn entry_to_relay<T: EntryZoneData>(
        _entry_data: TrustBoundary<T>,
    ) -> Result<TrustBoundary<()>, &'static str> {
        Ok(TrustBoundary::new(TrustZone::Relay, ()))
    }

    pub fn relay_to_exit<T: RelayZoneData>(
        _relay_data: TrustBoundary<T>,
    ) -> Result<TrustBoundary<()>, &'static str> {
        Ok(TrustBoundary::new(TrustZone::Exit, ()))
    }

    pub fn exit_to_external<T: ExitZoneData>(
        _exit_data: TrustBoundary<T>,
    ) -> Result<TrustBoundary<()>, &'static str> {
        Ok(TrustBoundary::new(TrustZone::External, ()))
    }
}