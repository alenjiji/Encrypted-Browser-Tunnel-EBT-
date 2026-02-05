use std::sync::Arc;
use std::net::TcpStream;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    ConnectionLost,
    WriteBlocked,
    ReadError,
    Timeout,
}

pub trait TransportAdapter: Send + Sync {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError>;
    fn close_transport(&mut self);
}

pub trait TransportCallbacks: Send + Sync {
    fn on_bytes_received(&mut self, data: &[u8]);
    fn on_transport_error(&mut self, error: TransportError);
}

pub struct TransportHandle {
    adapter: Box<dyn TransportAdapter>,
    callbacks: Arc<dyn TransportCallbacks>,
}

impl TransportHandle {
    pub fn new(
        adapter: Box<dyn TransportAdapter>,
        callbacks: Arc<dyn TransportCallbacks>,
    ) -> Self {
        Self { adapter, callbacks }
    }
    
    pub fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.adapter.send_bytes(data)
    }
    
    pub fn close(&mut self) {
        self.adapter.close_transport();
    }
}

pub struct TcpTransportAdapter {
    stream: TcpStream,
}

impl TcpTransportAdapter {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl TransportAdapter for TcpTransportAdapter {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
        match self.stream.write_all(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
                        Err(TransportError::ConnectionLost)
                    }
                    std::io::ErrorKind::WouldBlock => {
                        Err(TransportError::WriteBlocked)
                    }
                    std::io::ErrorKind::TimedOut => {
                        Err(TransportError::Timeout)
                    }
                    _ => {
                        Err(TransportError::ConnectionLost)
                    }
                }
            }
        }
    }
    
    fn close_transport(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}