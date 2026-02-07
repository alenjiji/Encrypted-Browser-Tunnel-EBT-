use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMetadata {
    pub method: String,
    pub full_url: String,
    pub host: String,
    pub port: u16,
    headers: BTreeMap<String, String>,
}

impl RequestMetadata {
    pub fn new(
        method: String,
        full_url: String,
        host: String,
        port: u16,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            method,
            full_url,
            host,
            port,
            headers,
        }
    }

    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { reason: ReasonCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Ads,
    Tracking,
    Custom,
    Unknown,
}
