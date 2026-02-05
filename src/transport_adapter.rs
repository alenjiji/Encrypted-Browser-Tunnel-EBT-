use std::sync::Arc;
use std::net::TcpStream;
use std::io::{Write, Read};
use std::sync::Mutex;
use std::thread;
use std::collections::VecDeque;

// NOTE: Thread-per-transport is an implementation detail, not a contract.
// Later transports (SSH, QUIC) may use different scheduling models.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    ConnectionLost,
    WriteBlocked, // NOTE: Currently maps both protocol and OS-level backpressure
    ReadError,
    Timeout,
}

pub trait TransportAdapter: Send + Sync {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError>;
    fn close_transport(&mut self);
    fn start_reading(&mut self, callbacks: Arc<Mutex<dyn TransportCallbacks>>);
}

pub trait TransportCallbacks: Send + Sync {
    fn on_bytes_received(&mut self, data: &[u8]);
    fn on_transport_error(&mut self, error: TransportError);
}

pub struct FakeTransportAdapter {
    outbound_queue: Arc<Mutex<VecDeque<u8>>>,
    inbound_queue: Arc<Mutex<VecDeque<u8>>>,
    closed: Arc<Mutex<bool>>,
}

impl FakeTransportAdapter {
    pub fn new() -> Self {
        Self {
            outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
            inbound_queue: Arc::new(Mutex::new(VecDeque::new())),
            closed: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn inject_bytes(&self, data: &[u8]) {
        if let Ok(mut queue) = self.inbound_queue.lock() {
            queue.extend(data);
        }
    }
    
    pub fn drain_outbound(&self) -> Vec<u8> {
        if let Ok(mut queue) = self.outbound_queue.lock() {
            queue.drain(..).collect()
        } else {
            Vec::new()
        }
    }
}

impl TransportAdapter for FakeTransportAdapter {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if *self.closed.lock().unwrap() {
            return Err(TransportError::ConnectionLost);
        }
        
        if let Ok(mut queue) = self.outbound_queue.lock() {
            queue.extend(data);
            Ok(())
        } else {
            Err(TransportError::WriteBlocked)
        }
    }
    
    fn start_reading(&mut self, callbacks: Arc<Mutex<dyn TransportCallbacks>>) {
        let inbound_queue = Arc::clone(&self.inbound_queue);
        let closed = Arc::clone(&self.closed);
        
        thread::spawn(move || {
            let mut buffer = Vec::new();
            
            loop {
                if *closed.lock().unwrap() {
                    break;
                }
                
                {
                    if let Ok(mut queue) = inbound_queue.lock() {
                        buffer.extend(queue.drain(..));
                    }
                }
                
                if !buffer.is_empty() {
                    if let Ok(mut cb) = callbacks.lock() {
                        cb.on_bytes_received(&buffer);
                    }
                    buffer.clear();
                }
                
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
    }
    
    fn close_transport(&mut self) {
        *self.closed.lock().unwrap() = true;
    }
}

pub struct TransportHandle {
    adapter: Box<dyn TransportAdapter>,
    callbacks: Arc<Mutex<dyn TransportCallbacks>>,
}

impl TransportHandle {
    pub fn new(
        adapter: Box<dyn TransportAdapter>,
        callbacks: Arc<Mutex<dyn TransportCallbacks>>,
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
    
    fn start_reading(&mut self, callbacks: Arc<Mutex<dyn TransportCallbacks>>) {
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
                        Ok(0) => break, // EOF
                        Ok(n) => n,
                        Err(e) => {
                            let error = match e.kind() {
                                std::io::ErrorKind::WouldBlock => continue,
                                std::io::ErrorKind::TimedOut => TransportError::Timeout,
                                _ => TransportError::ReadError,
                            };
                            if let Ok(mut cb) = callbacks.lock() {
                                cb.on_transport_error(error);
                            }
                            break;
                        }
                    }
                };
                
                if let Ok(mut cb) = callbacks.lock() {
                    cb.on_bytes_received(&buffer[..bytes_read]);
                }
            }
        });
    }
    
    fn close_transport(&mut self) {
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}