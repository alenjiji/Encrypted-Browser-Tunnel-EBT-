/// DNS resolution handling - local vs remote
use std::net::IpAddr;

pub struct DnsResolver {
    resolver_type: ResolverType,
    server_address: String,
}

#[derive(Debug, Clone)]
pub enum ResolverType {
    Local,
    Remote,
}

#[derive(Debug)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: QueryType,
}

#[derive(Debug)]
pub enum QueryType {
    A,
    AAAA,
    CNAME,
}

#[derive(Debug)]
pub struct DnsResponse {
    pub domain: String,
    pub ip_address: Option<IpAddr>,
    pub resolved_via: ResolverType,
}

impl DnsResolver {
    pub fn new_local() -> Self {
        Self {
            resolver_type: ResolverType::Local,
            server_address: "local-dns.placeholder".to_string(),
        }
    }
    
    pub fn new_remote(server_address: String) -> Self {
        Self {
            resolver_type: ResolverType::Remote,
            server_address,
        }
    }
    
    pub async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
        match self.resolver_type {
            ResolverType::Local => {
                println!("Resolving {} via local DNS", query.domain);
            }
            ResolverType::Remote => {
                println!("Resolving {} via remote DNS at {}", query.domain, self.server_address);
            }
        }
        
        Ok(DnsResponse {
            domain: query.domain,
            ip_address: None, // Placeholder - no actual resolution
            resolved_via: self.resolver_type.clone(),
        })
    }
    
    pub fn check_dns_leak(&self, expected_resolver: ResolverType) -> bool {
        match (&self.resolver_type, expected_resolver) {
            (ResolverType::Local, ResolverType::Remote) => {
                println!("DNS LEAK DETECTED: Expected remote resolution, got local");
                true
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum DnsError {
    ResolutionFailed,
    Timeout,
    InvalidDomain,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::ResolutionFailed => write!(f, "DNS resolution failed"),
            DnsError::Timeout => write!(f, "DNS query timeout"),
            DnsError::InvalidDomain => write!(f, "Invalid domain name"),
        }
    }
}

impl std::error::Error for DnsError {}