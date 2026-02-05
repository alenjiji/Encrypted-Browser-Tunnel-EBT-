use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::relay_protocol::{
    FrameEncoder, FrameDecoder, ControlMessage, DataFrame, 
    ConnectionTable, RelayLimits, ProtocolNegotiator
};
use crate::transport_adapter::{TransportAdapter, TransportCallbacks, TransportError};
use std::io::Cursor;

pub struct ProtocolEngine {
    connection_table: ConnectionTable,
    negotiator: ProtocolNegotiator,
    transports: HashMap<u32, Box<dyn TransportAdapter>>,
}

impl ProtocolEngine {
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            connection_table: ConnectionTable::new(limits),
            negotiator: ProtocolNegotiator::new(),
            transports: HashMap::new(),
        }
    }
    
    pub fn add_transport(&mut self, conn_id: u32, transport: Box<dyn TransportAdapter>) {
        self.transports.insert(conn_id, transport);
    }
    
    pub fn send_control_message(&mut self, conn_id: u32, message: ControlMessage) -> Result<(), TransportError> {
        if let Some(transport) = self.transports.get_mut(&conn_id) {
            let payload = message.encode();
            let mut buffer = Vec::new();
            FrameEncoder::encode_frame(
                &mut buffer, 
                1, // protocol version
                crate::relay_protocol::FrameType::Control, 
                &payload
            ).map_err(|_| TransportError::WriteBlocked)?;
            
            transport.send_bytes(&buffer)
        } else {
            Err(TransportError::ConnectionLost)
        }
    }
    
    pub fn send_data_frame(&mut self, conn_id: u32, data: &[u8]) -> Result<(), TransportError> {
        if !self.connection_table.can_send_data(conn_id, data.len() as u32) {
            return Err(TransportError::WriteBlocked);
        }
        
        if let Some(transport) = self.transports.get_mut(&conn_id) {
            let frame = DataFrame::new(conn_id, data.to_vec());
            let payload = frame.encode();
            let mut buffer = Vec::new();
            FrameEncoder::encode_frame(
                &mut buffer,
                1, // protocol version
                crate::relay_protocol::FrameType::Data,
                &payload
            ).map_err(|_| TransportError::WriteBlocked)?;
            
            self.connection_table.consume_send_credits(conn_id, data.len() as u32)
                .map_err(|_| TransportError::WriteBlocked)?;
            
            transport.send_bytes(&buffer)
        } else {
            Err(TransportError::ConnectionLost)
        }
    }
    
    pub fn close_transport(&mut self, conn_id: u32) {
        if let Some(mut transport) = self.transports.remove(&conn_id) {
            transport.close_transport();
        }
    }
    
    pub fn poll_control_frames(&mut self) -> Vec<(u32, ControlMessage)> {
        let frames = self.connection_table.poll_control_frames();
        frames.into_iter().map(|msg| {
            let conn_id = match &msg {
                ControlMessage::Open { conn_id, .. } => *conn_id,
                ControlMessage::Close { conn_id, .. } => *conn_id,
                ControlMessage::WindowUpdate { conn_id, .. } => *conn_id,
                ControlMessage::Error { conn_id, .. } => *conn_id,
                ControlMessage::Hello { .. } => 0, // Special case for handshake
            };
            (conn_id, msg)
        }).collect()
    }
}

pub struct ProtocolCallbacks {
    engine: Arc<Mutex<ProtocolEngine>>,
    conn_id: u32,
    frame_buffer: Vec<u8>,
}

impl ProtocolCallbacks {
    pub fn new(engine: Arc<Mutex<ProtocolEngine>>, conn_id: u32) -> Self {
        Self {
            engine,
            conn_id,
            frame_buffer: Vec::new(),
        }
    }
}

impl TransportCallbacks for ProtocolCallbacks {
    fn on_bytes_received(&mut self, data: &[u8]) {
        // Accumulate bytes for frame parsing
        self.frame_buffer.extend_from_slice(data);
        
        // Try to parse complete frames
        while self.frame_buffer.len() >= 6 { // Minimum frame size
            let mut cursor = Cursor::new(&self.frame_buffer);
            
            match FrameDecoder::decode_frame(&mut cursor) {
                Ok((version, frame_type, payload)) => {
                    let consumed = cursor.position() as usize;
                    self.frame_buffer.drain(..consumed);
                    
                    // Process frame based on type
                    match frame_type {
                        crate::relay_protocol::FrameType::Control => {
                            if let Ok(control_msg) = ControlMessage::decode(&payload) {
                                // Protocol engine processes control message
                                // (Implementation would handle specific control logic)
                            }
                        }
                        crate::relay_protocol::FrameType::Data => {
                            if let Ok(data_frame) = DataFrame::decode(&payload) {
                                // Protocol engine processes data frame
                                // (Implementation would forward to appropriate connection)
                            }
                        }
                    }
                }
                Err(_) => {
                    // Not enough data for complete frame, wait for more
                    break;
                }
            }
        }
    }
    
    fn on_transport_error(&mut self, error: TransportError) {
        // Transport error does NOT auto-close protocol state
        // Protocol engine decides how to handle transport failures
        if let Ok(mut engine) = self.engine.lock() {
            // Log transport error but don't change connection state
            // Protocol maintains authority over connection lifecycle
        }
    }
}