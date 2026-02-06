use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use crate::protocol_engine::ProtocolEngine;
use crate::transport_adapter::TransportAdapter;

pub struct BindingPump {
    protocol_engine: Arc<Mutex<ProtocolEngine>>,
    transports: HashMap<u32, Box<dyn TransportAdapter>>,
    running: Arc<Mutex<bool>>,
}

impl BindingPump {
    pub fn new(protocol_engine: Arc<Mutex<ProtocolEngine>>) -> Self {
        Self {
            protocol_engine,
            transports: HashMap::new(),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn add_transport(&mut self, conn_id: u32, transport: Box<dyn TransportAdapter>) {
        self.transports.insert(conn_id, transport);
    }
    
    pub fn start(&mut self) {
        *self.running.lock().unwrap() = true;
        
        let protocol_engine = Arc::clone(&self.protocol_engine);
        let running = Arc::clone(&self.running);
        
        // Move transports to the pump thread
        let mut transports = std::mem::take(&mut self.transports);
        
        thread::spawn(move || {
            while *running.lock().unwrap() {
                // Get all connection IDs
                let conn_ids: Vec<u32> = transports.keys().copied().collect();
                
                for conn_id in conn_ids {
                    // Extract frames from protocol (short lock)
                    let mut frames = Vec::new();
                    {
                        if let Ok(mut engine) = protocol_engine.lock() {
                            while let Some(frame) = engine.next_outbound_frame(conn_id) {
                                frames.push(frame);
                            }
                        }
                    }
                    
                    // Send frames to transport (no protocol lock held)
                    for frame in frames {
                        if let Some(transport) = transports.get_mut(&conn_id) {
                            if transport.send_bytes(&frame).is_err() {
                                transports.remove(&conn_id);
                                break;
                            }
                        }
                    }
                }
                
                // Small yield to prevent busy loop
                thread::sleep(Duration::from_millis(1));
            }
        });
    }
    
    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}