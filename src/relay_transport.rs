use std::net::TcpStream;
use std::io::Result;

pub trait RelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream>;
}

pub struct DirectRelayTransport;

impl RelayTransport for DirectRelayTransport {
    fn establish_relay_connection(&mut self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        TcpStream::connect((target_host, target_port))
    }
}

impl Default for DirectRelayTransport {
    fn default() -> Self {
        Self
    }
}