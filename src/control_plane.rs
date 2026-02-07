use crate::trust_boundaries::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
#[derive(Eq, Hash, PartialEq)]
pub struct SessionId(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct PrivateKey(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct EncryptedRoute(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct HopKey(pub [u8; 32]);

pub struct SessionEstablisher {
    zone: TrustZone,
}

impl SessionEstablisher {
    pub fn new(zone: TrustZone) -> Self {
        Self { zone }
    }

    pub async fn initiate_session(&self, _route: EncryptedRoute) -> Result<SessionId, ControlError> {
        match self.zone {
            TrustZone::Local => {
                let session_id = SessionId(rand::random());
                Ok(session_id)
            }
            _ => Err(ControlError::InvalidZone),
        }
    }
}

pub struct KeyExchanger {
    zone: TrustZone,
    hop_keys: HashMap<SessionId, HopKey>,
}

impl KeyExchanger {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone,
            hop_keys: HashMap::new(),
        }
    }

    pub async fn exchange_key(&mut self, session_id: SessionId, _encrypted_key: Vec<u8>) -> Result<(), ControlError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay => {
                let hop_key = HopKey(rand::random());
                self.hop_keys.insert(session_id, hop_key);
                Ok(())
            }
            _ => Err(ControlError::InvalidZone),
        }
    }
}

pub struct RouteNegotiator {
    zone: TrustZone,
}

impl RouteNegotiator {
    pub fn new(zone: TrustZone) -> Self {
        Self { zone }
    }

    pub async fn setup_route(&self, _encrypted_next_hop: Vec<u8>) -> Result<(), ControlError> {
        match self.zone {
            TrustZone::Entry | TrustZone::Relay | TrustZone::Exit => Ok(()),
            _ => Err(ControlError::InvalidZone),
        }
    }
}

pub struct ControlMessageHandler {
    zone: TrustZone,
    session_establisher: SessionEstablisher,
    key_exchanger: KeyExchanger,
    route_negotiator: RouteNegotiator,
}

impl ControlMessageHandler {
    pub fn new(zone: TrustZone) -> Self {
        Self {
            zone: zone.clone(),
            session_establisher: SessionEstablisher::new(zone.clone()),
            key_exchanger: KeyExchanger::new(zone.clone()),
            route_negotiator: RouteNegotiator::new(zone),
        }
    }

    pub async fn handle_session_init(&mut self, route: EncryptedRoute) -> Result<SessionId, ControlError> {
        self.session_establisher.initiate_session(route).await
    }

    pub async fn handle_key_exchange(&mut self, session_id: SessionId, encrypted_key: Vec<u8>) -> Result<(), ControlError> {
        self.key_exchanger.exchange_key(session_id, encrypted_key).await
    }

    pub async fn handle_route_setup(&self, encrypted_next_hop: Vec<u8>) -> Result<(), ControlError> {
        self.route_negotiator.setup_route(encrypted_next_hop).await
    }
}

#[derive(Debug)]
pub enum ControlError {
    InvalidZone,
    KeyExchangeFailed,
    RouteSetupFailed,
}

mod rand {
    pub fn random<T>() -> T
    where
        T: Default,
    {
        T::default()
    }
}