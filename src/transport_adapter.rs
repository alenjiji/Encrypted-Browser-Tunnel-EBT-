use std::sync::Arc;
use std::net::TcpStream;
use std::io::{Write, Read};
use std::sync::Mutex;
use std::thread;

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
    fn start_reading(&mut self, callbacks: Arc<dyn TransportCallbacks>);
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
    
    pub fn start_reading(&mut self) {
        let callbacks = Arc::clone(&self.callbacks);
        self.adapter.start_reading(callbacks);
    }
    
    pub fn close(&mut self) {
        self.adapter.close_transport();
    }
}

pub struct TcpTransportAdapter {
    stream: Arc<Mutex<TcpStream>>,
}

impl TcpTransportAdapter {
    pub fn new(stream: TcpStream) -> Self {
        Self { 
            stream: Arc::new(Mutex::new(stream))
        }
    }
}

impl TransportAdapter for TcpTransportAdapter {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut stream = self.stream.lock().unwrap();
        match stream.write_all(data) {
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
    
    fn start_reading(&mut self, callbacks: Arc<dyn TransportCallbacks>) {
        let stream = Arc::clone(&self.stream);
        
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            
            loop {
                let bytes_read = {
                    let mut stream = match stream.lock() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            // EOF - connection closed
                            let mut cb = callbacks.as_ref();
                            // SAFETY: We need mutable access but Arc<dyn Trait> doesn't allow it
                            // This is a design limitation we'll address later
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            let error = match e.kind() {
                                std::io::ErrorKind::WouldBlock => continue,
                                std::io::ErrorKind::TimedOut => TransportError::Timeout,
                                _ => TransportError::ReadError,
                            };
                            // Same mutable access issue here
                            break;
                        }
                    }
                };
                
                // Forward bytes immediately without interpretation
                // Note: This has the mutable callback issue that needs resolution
                // callbacks.on_bytes_received(&buffer[..bytes_read]);
            }
        });
    }
    
    fn close_transport(&mut self) {
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}