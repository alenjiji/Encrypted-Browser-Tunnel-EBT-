/// Client device component - represents the browser/application side
#[derive(Clone)]
pub struct Client {
    proxy_config: ProxyConfig,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub enum ProxyType {
    SshSocks,
    HttpsConnect,
    QuicHttp3,
}

impl Client {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            proxy_config: config,
        }
    }
    
    pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Client connecting via {:?}", self.proxy_config.proxy_type);
        Ok(())
    }
}