use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use crate::transport_adapter::{TcpTransportAdapter, TransportAdapter};
use crate::protocol_engine::ProtocolEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrowserSocketId(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogicalConnectionId(u32);

pub struct ConnectionMapping {
    socket_to_logical: HashMap<BrowserSocketId, LogicalConnectionId>,
    logical_to_socket: HashMap<LogicalConnectionId, BrowserSocketId>,
    logical_to_transport: HashMap<LogicalConnectionId, Box<dyn TransportAdapter>>,
    next_socket_id: usize,
    next_logical_id: u32,
}

impl ConnectionMapping {
    pub fn new() -> Self {
        Self {
            socket_to_logical: HashMap::new(),
            logical_to_socket: HashMap::new(),
            logical_to_transport: HashMap::new(),
            next_socket_id: 1,
            next_logical_id: 1,
        }
    }
    
    pub fn create_mapping(
        &mut self, 
        browser_socket: TcpStream,
        _protocol_engine: &Arc<Mutex<ProtocolEngine>>
    ) -> Result<(BrowserSocketId, LogicalConnectionId), &'static str> {
        let socket_id = BrowserSocketId(self.next_socket_id);
        self.next_socket_id += 1;
        
        let logical_id = LogicalConnectionId(self.next_logical_id);
        self.next_logical_id += 1;
        
        // Create transport adapter for this connection
        let transport = Box::new(TcpTransportAdapter::new(browser_socket));
        
        // Explicit bidirectional mapping
        self.socket_to_logical.insert(socket_id, logical_id);
        self.logical_to_socket.insert(logical_id, socket_id);
        self.logical_to_transport.insert(logical_id, transport);
        
        // Register with protocol engine
        // Note: ProtocolEngine no longer has add_transport method
        // Transport registration handled by binding layer
        
        Ok((socket_id, logical_id))
    }
    
    pub fn get_logical_id(&self, socket_id: BrowserSocketId) -> Option<LogicalConnectionId> {
        self.socket_to_logical.get(&socket_id).copied()
    }
    
    pub fn get_socket_id(&self, logical_id: LogicalConnectionId) -> Option<BrowserSocketId> {
        self.logical_to_socket.get(&logical_id).copied()
    }
    
    pub fn on_browser_socket_closed(
        &mut self, 
        socket_id: BrowserSocketId,
        protocol_engine: &Arc<Mutex<ProtocolEngine>>
    ) {
        if let Some(_logical_id) = self.socket_to_logical.get(&socket_id) {
            // Notify protocol engine of socket close - do NOT destroy state
            // Protocol engine decides cleanup policy
            if let Ok(_engine) = protocol_engine.lock() {
                // Protocol receives notification but maintains state authority
                // Transport is closed but protocol connection may remain
            }
            
            // Remove socket mapping but keep logical connection
            self.socket_to_logical.remove(&socket_id);
            // Keep logical_to_socket mapping for protocol-initiated cleanup
        }
    }
    
    pub fn protocol_close_connection(
        &mut self,
        logical_id: LogicalConnectionId,
        _protocol_engine: &Arc<Mutex<ProtocolEngine>>
    ) {
        // Protocol-initiated cleanup - remove all mappings
        if let Some(socket_id) = self.logical_to_socket.remove(&logical_id) {
            self.socket_to_logical.remove(&socket_id);
        }
        
        // Close transport via binding layer (not protocol engine)
        // Protocol engine no longer manages transports directly
        self.logical_to_transport.remove(&logical_id);
    }
    
    pub fn get_active_mappings(&self) -> Vec<(BrowserSocketId, LogicalConnectionId)> {
        self.socket_to_logical.iter()
            .map(|(&socket_id, &logical_id)| (socket_id, logical_id))
            .collect()
    }
}

pub struct ConnectionManager {
    mapping: Arc<Mutex<ConnectionMapping>>,
    protocol_engine: Arc<Mutex<ProtocolEngine>>,
}

impl ConnectionManager {
    pub fn new(protocol_engine: Arc<Mutex<ProtocolEngine>>) -> Self {
        Self {
            mapping: Arc::new(Mutex::new(ConnectionMapping::new())),
            protocol_engine,
        }
    }
    
    pub fn handle_new_browser_connection(
        &self,
        browser_socket: TcpStream
    ) -> Result<(BrowserSocketId, LogicalConnectionId), &'static str> {
        let mut mapping = self.mapping.lock().unwrap();
        mapping.create_mapping(browser_socket, &self.protocol_engine)
    }
    
    pub fn notify_browser_socket_closed(&self, socket_id: BrowserSocketId) {
        let mut mapping = self.mapping.lock().unwrap();
        mapping.on_browser_socket_closed(socket_id, &self.protocol_engine);
    }
    
    pub fn close_logical_connection(&self, logical_id: LogicalConnectionId) {
        let mut mapping = self.mapping.lock().unwrap();
        mapping.protocol_close_connection(logical_id, &self.protocol_engine);
    }
}