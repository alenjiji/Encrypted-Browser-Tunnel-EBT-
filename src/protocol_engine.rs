use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::relay_protocol::{
    FrameEncoder, FrameDecoder, ControlMessage, DataFrame, 
    ConnectionTable, RelayLimits, ProtocolNegotiator
};
use crate::transport_adapter::{TransportCallbacks, TransportError};
use std::io::Cursor;

pub struct ProtocolEngine {
    connection_table: ConnectionTable,
    negotiator: ProtocolNegotiator,
    outbound_frames: HashMap<u32, Vec<Vec<u8>>>,
    frame_buffers: HashMap<u32, Vec<u8>>,
}

impl ProtocolEngine {
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            connection_table: ConnectionTable::new(limits),
            negotiator: ProtocolNegotiator::new(),
            outbound_frames: HashMap::new(),
            frame_buffers: HashMap::new(),
        }
    }
    
    pub fn on_transport_bytes(&mut self, conn_id: u32, data: &[u8]) {
        // Accumulate bytes in connection-specific buffer
        let buffer = self.frame_buffers.entry(conn_id).or_insert_with(Vec::new);
        buffer.extend_from_slice(data);
        
        // Parse complete frames from buffer
        let mut parsed_frames = Vec::new();
        while buffer.len() >= 6 { // Minimum frame size
            let mut cursor = Cursor::new(&buffer);
            
            match FrameDecoder::decode_frame(&mut cursor) {
                Ok((version, frame_type, payload)) => {
                    let consumed = cursor.position() as usize;
                    buffer.drain(..consumed);
                    parsed_frames.push((version, frame_type, payload));
                }
                Err(_) => break, // Incomplete frame, wait for more data
            }
        }
        
        // Process parsed frames
        for (_version, frame_type, payload) in parsed_frames {
            match frame_type {
                crate::relay_protocol::FrameType::Control => {
                    if let Ok(control_msg) = ControlMessage::decode(&payload) {
                        self.process_control_message(conn_id, control_msg);
                    }
                }
                crate::relay_protocol::FrameType::Data => {
                    if let Ok(data_frame) = DataFrame::decode(&payload) {
                        self.process_data_frame(data_frame);
                    }
                }
            }
        }
    }
    
    pub fn next_outbound_frame(&mut self, conn_id: u32) -> Option<Vec<u8>> {
        self.outbound_frames.get_mut(&conn_id)?.pop()
    }
    
    pub fn queue_control_message(&mut self, conn_id: u32, message: ControlMessage) {
        let payload = message.encode();
        let mut buffer = Vec::new();
        if FrameEncoder::encode_frame(
            &mut buffer, 
            1, // protocol version
            crate::relay_protocol::FrameType::Control, 
            &payload
        ).is_ok() {
            self.outbound_frames.entry(conn_id).or_insert_with(Vec::new).push(buffer);
        }
    }
    
    pub fn queue_data_frame(&mut self, conn_id: u32, data: &[u8]) -> Result<(), &'static str> {
        if !self.connection_table.can_send_data(conn_id, data.len() as u32) {
            return Err("Insufficient credits");
        }
        
        let frame = DataFrame::new(conn_id, data.to_vec());
        let payload = frame.encode();
        let mut buffer = Vec::new();
        
        if FrameEncoder::encode_frame(
            &mut buffer,
            1, // protocol version
            crate::relay_protocol::FrameType::Data,
            &payload
        ).is_ok() {
            self.connection_table.consume_send_credits(conn_id, data.len() as u32)?;
            self.outbound_frames.entry(conn_id).or_insert_with(Vec::new).push(buffer);
            Ok(())
        } else {
            Err("Frame encoding failed")
        }
    }
    
    pub fn poll_control_frames(&mut self) -> Vec<(u32, ControlMessage)> {
        let frames = self.connection_table.poll_control_frames();
        for frame in &frames {
            let conn_id = match frame {
                ControlMessage::Open { conn_id, .. } => *conn_id,
                ControlMessage::Close { conn_id, .. } => *conn_id,
                ControlMessage::WindowUpdate { conn_id, .. } => *conn_id,
                ControlMessage::Error { conn_id, .. } => *conn_id,
                ControlMessage::Hello { .. } => 0,
            };
            self.queue_control_message(conn_id, frame.clone());
        }
        frames.into_iter().map(|msg| {
            let conn_id = match &msg {
                ControlMessage::Open { conn_id, .. } => *conn_id,
                ControlMessage::Close { conn_id, .. } => *conn_id,
                ControlMessage::WindowUpdate { conn_id, .. } => *conn_id,
                ControlMessage::Error { conn_id, .. } => *conn_id,
                ControlMessage::Hello { .. } => 0,
            };
            (conn_id, msg)
        }).collect()
    }
    
    fn process_control_message(&mut self, conn_id: u32, message: ControlMessage) {
        match message {
            ControlMessage::Open { target_host: _, target_port: _, .. } => {
                let _ = self.connection_table.open_connection(conn_id);
            }
            ControlMessage::Close { reason: _, .. } => {
                let _ = self.connection_table.close_connection(conn_id);
            }
            ControlMessage::WindowUpdate { credits, .. } => {
                let _ = self.connection_table.add_send_credits(conn_id, credits);
            }
            _ => {}
        }
    }
    
    fn process_data_frame(&mut self, _frame: DataFrame) {
        // Forward data frame to appropriate connection
        // Implementation depends on specific relay logic
    }
}

pub struct ProtocolCallbacks {
    engine: Arc<Mutex<ProtocolEngine>>,
    conn_id: u32,
}

impl ProtocolCallbacks {
    pub fn new(engine: Arc<Mutex<ProtocolEngine>>, conn_id: u32) -> Self {
        Self { engine, conn_id }
    }
}

impl TransportCallbacks for ProtocolCallbacks {
    fn on_bytes_received(&mut self, data: &[u8]) {
        if let Ok(mut engine) = self.engine.lock() {
            engine.on_transport_bytes(self.conn_id, data);
        }
    }
    
    fn on_transport_error(&mut self, _error: TransportError) {
        // Transport error notification - protocol decides response
    }
}