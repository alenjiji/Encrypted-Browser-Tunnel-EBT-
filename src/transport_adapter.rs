use std::sync::Arc;

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