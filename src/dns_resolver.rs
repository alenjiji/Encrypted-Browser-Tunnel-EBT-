use std::net::IpAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose};

pub trait DnsResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError>;
}

#[derive(Debug)]
pub enum DnsError {
    ResolutionFailed,
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
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

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "data")]
    data: String,
}

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

pub struct DohResolver {
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    #[cfg(feature = "doh_fallback")]
    fallback: SystemDnsResolver,
}

impl DohResolver {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "doh_fallback")]
            fallback: SystemDnsResolver,
        }
    }
    
    fn get_cached(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(hostname)?;
        if entry.expires > Instant::now() {
            Some(entry.ips.clone())
        } else {
            None
        }
    }
    
    fn cache_result(&self, hostname: &str, ips: Vec<IpAddr>, ttl: u32) {
        if let Ok(mut cache) = self.cache.lock() {
            let expires = Instant::now() + Duration::from_secs(ttl as u64);
            cache.insert(hostname.to_string(), CacheEntry { ips, expires });
        }
    }
}

impl DnsResolver for DohResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Some(cached) = self.get_cached(hostname) {
            return Ok(cached);
        }
        
        let url = format!(
            "https://1.1.1.1/dns-query?name={}&type=A",
            hostname
        );
        
        // Attempt DoH resolution with timeout and retry
        let mut last_error = None;
        for attempt in 0..2 {
            let response_result = self.client
                .get(&url)
                .header("Accept", "application/dns-json")
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            
            let response = match response_result {
                Ok(resp) => match resp.json::<DohResponse>().await {
                    Ok(json) => json,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                },
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            
            let mut ips = Vec::new();
            let mut min_ttl = 300u32;
            
            if let Some(answers) = response.answer {
                for answer in answers {
                    if let Ok(ip) = answer.data.parse::<IpAddr>() {
                        ips.push(ip);
                        min_ttl = min_ttl.min(answer.ttl);
                    }
                }
            }
            
            if !ips.is_empty() {
                self.cache_result(hostname, ips.clone(), min_ttl);
                return Ok(ips);
            }
        }
        
        // All attempts failed
        #[cfg(feature = "doh_fallback")]
        {
            self.fallback.resolve(hostname).await
        }
        #[cfg(not(feature = "doh_fallback"))]
        {
            Err(DnsError::ResolutionFailed)
        }
    }
}