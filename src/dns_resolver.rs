use std::net::IpAddr;

pub trait DnsResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError>;
}

#[derive(Debug)]
pub enum DnsError {
    ResolutionFailed,
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
        use std::net::ToSocketAddrs;
        
        let addrs: Vec<IpAddr> = format!("{}:0", hostname)
            .to_socket_addrs()
            .map_err(|_| DnsError::ResolutionFailed)?
            .map(|addr| addr.ip())
            .collect();
            
        if addrs.is_empty() {
            Err(DnsError::ResolutionFailed)
        } else {
            Ok(addrs)
        }
    }
}

impl Default for SystemDnsResolver {
    fn default() -> Self {
        Self
    }
}