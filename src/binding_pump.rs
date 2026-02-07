use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::marker::PhantomData;
use crate::anonymity::invariants::{
    AllowsDirectTimingCorrespondence,
    AllowsRelayLocalLinkability,
};
use crate::protocol_engine::ProtocolEngine;
use crate::transport_adapter::TransportAdapter;
use crate::core::observability;

pub struct BindingPump<Phase: AllowsDirectTimingCorrespondence + AllowsRelayLocalLinkability> {
    protocol_engine: Arc<Mutex<ProtocolEngine<Phase>>>,
    transports: HashMap<u32, Box<dyn TransportAdapter>>,
    running: Arc<Mutex<bool>>,
    _phase: PhantomData<Phase>,
}

impl<Phase: AllowsDirectTimingCorrespondence + AllowsRelayLocalLinkability> BindingPump<Phase> {
    pub fn new(protocol_engine: Arc<Mutex<ProtocolEngine<Phase>>>) -> Self {
        Self {
            protocol_engine,
            transports: HashMap::new(),
            running: Arc::new(Mutex::new(false)),
            _phase: PhantomData,
        }
    }
    
    pub fn add_transport(&mut self, conn_id: u32, transport: Box<dyn TransportAdapter>) {
        self.transports.insert(conn_id, transport);
    }
    
    #[deprecated(note = "Phase 9 forbids direct FIFO timing between protocol and transport; binding must add mixing/delay.")]
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
                                observability::record_error(observability::ErrorClass::TRANSPORT_IO);
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
