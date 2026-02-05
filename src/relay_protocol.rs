use std::io::{Read, Write, Result as IoResult};
use std::collections::HashMap;

pub type ProtocolVersion = u8;

const MAX_FRAME_SIZE: u32 = 1024 * 1024; // 1MB

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Control = 0x01,
    Data = 0x02,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOpcode {
    Hello = 0x00,
    Open = 0x01,
    Close = 0x02,
    WindowUpdate = 0x03,
    Error = 0x04,
}

const PROTOCOL_VERSION_1: u8 = 1;
const SUPPORTED_VERSIONS: &[u8] = &[PROTOCOL_VERSION_1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    WaitingForHello,
    Negotiated,
    Failed,
}

pub struct ProtocolNegotiator {
    state: HandshakeState,
    negotiated_version: Option<u8>,
    peer_capabilities: Option<u32>,
}

impl ProtocolNegotiator {
    pub fn new() -> Self {
        Self {
            state: HandshakeState::WaitingForHello,
            negotiated_version: None,
            peer_capabilities: None,
        }
    }
    
    pub fn process_hello(&mut self, version: u8, capability_flags: u32) -> Result<ControlMessage, &'static str> {
        if self.state != HandshakeState::WaitingForHello {
            return Err("Handshake already completed or failed");
        }
        
        if !SUPPORTED_VERSIONS.contains(&version) {
            self.state = HandshakeState::Failed;
            return Err("Unsupported protocol version");
        }
        
        self.negotiated_version = Some(version);
        self.peer_capabilities = Some(capability_flags);
        self.state = HandshakeState::Negotiated;
        
        // Respond with our capabilities (flags are optional and ignorable)
        Ok(ControlMessage::Hello { version, capability_flags: 0 }) // No capabilities for now
    }
    
    pub fn is_negotiated(&self) -> bool {
        self.state == HandshakeState::Negotiated
    }
    
    pub fn negotiated_version(&self) -> Option<u8> {
        self.negotiated_version
    }
    
    pub fn peer_capabilities(&self) -> Option<u32> {
        self.peer_capabilities
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Init,
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_connections: usize,
    pub max_inflight_opens: usize,
    pub max_buffered_bytes: usize,
}

#[derive(Debug, Default)]
pub struct RelayMetrics {
    pub connections_rejected: u64,
    pub opens_rejected: u64,
    pub buffer_limit_breached: u64,
}

struct ConnectionInfo {
    state: ConnectionState,
    buffered_bytes: usize,
    send_window: u32,
    initial_window_size: u32,
}

pub struct ConnectionTable {
    connections: HashMap<u32, ConnectionInfo>,
    inflight_opens: usize,
    limits: RelayLimits,
    metrics: RelayMetrics,
    default_window_size: u32,
}

impl ConnectionTable {
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            connections: HashMap::new(),
            inflight_opens: 0,
            limits,
            metrics: RelayMetrics::default(),
            default_window_size: 65536, // 64KB default window
        }
    }
    
    /// Relay is authoritative for flow control.
    /// This method generates control frames that MUST be sent to maintain protocol correctness.
    pub fn poll_control_frames(&mut self) -> Vec<ControlMessage> {
        let mut frames = Vec::new();
        
        for (&conn_id, info) in &mut self.connections {
            if let Some(credits) = self.calculate_window_update(conn_id) {
                frames.push(ControlMessage::WindowUpdate { conn_id, credits });
                // Update window immediately to prevent duplicate updates
                info.send_window = info.send_window.saturating_add(credits).min(info.initial_window_size * 2);
            }
        }
        
        frames
    }
    
    pub fn set_default_window_size(&mut self, size: u32) {
        self.default_window_size = size;
    }
    
    pub fn open_connection(&mut self, conn_id: u32) -> Result<(), &'static str> {
        if self.connections.len() >= self.limits.max_connections {
            self.metrics.connections_rejected += 1;
            return Err("Max connections exceeded");
        }
        
        if self.inflight_opens >= self.limits.max_inflight_opens {
            self.metrics.opens_rejected += 1;
            return Err("Max inflight opens exceeded");
        }
        
        match self.connections.get(&conn_id) {
            None => {
                self.connections.insert(conn_id, ConnectionInfo {
                    state: ConnectionState::Init,
                    buffered_bytes: 0,
                    send_window: self.default_window_size,
                    initial_window_size: self.default_window_size,
                });
                self.inflight_opens += 1;
                Ok(())
            }
            Some(_) => Err("Connection already exists"),
        }
    }
    
    pub fn finalize_open(&mut self, conn_id: u32) -> Result<(), &'static str> {
        if let Some(info) = self.connections.get_mut(&conn_id) {
            if info.state == ConnectionState::Init {
                info.state = ConnectionState::Open;
                if self.inflight_opens > 0 {
                    self.inflight_opens -= 1;
                }
                Ok(())
            } else {
                Err("Connection not in init state")
            }
        } else {
            Err("Connection not found")
        }
    }
    
    pub fn can_send_data(&self, conn_id: u32, data_size: u32) -> bool {
        match self.connections.get(&conn_id) {
            Some(info) => {
                info.state == ConnectionState::Open && info.send_window >= data_size
            }
            None => false,
        }
    }
    
    pub fn consume_send_credits(&mut self, conn_id: u32, data_size: u32) -> Result<(), &'static str> {
        if let Some(info) = self.connections.get_mut(&conn_id) {
            if info.send_window >= data_size {
                info.send_window -= data_size;
                Ok(())
            } else {
                Err("Insufficient send credits")
            }
        } else {
            Err("Connection not found")
        }
    }
    
    pub fn add_send_credits(&mut self, conn_id: u32, credits: u32) -> Result<(), &'static str> {
        if let Some(info) = self.connections.get_mut(&conn_id) {
            // Prevent window overflow
            let max_window = info.initial_window_size * 2;
            let new_window = info.send_window.saturating_add(credits).min(max_window);
            info.send_window = new_window;
            Ok(())
        } else {
            Err("Connection not found")
        }
    }
    
    pub fn get_send_window(&self, conn_id: u32) -> Option<u32> {
        self.connections.get(&conn_id).map(|info| info.send_window)
    }
    
    pub fn should_send_window_update(&self, conn_id: u32) -> bool {
        if let Some(info) = self.connections.get(&conn_id) {
            // Send window update when window drops below 25% of initial size
            info.send_window < (info.initial_window_size / 4)
        } else {
            false
        }
    }
    
    pub fn calculate_window_update(&self, conn_id: u32) -> Option<u32> {
        if let Some(info) = self.connections.get(&conn_id) {
            if self.should_send_window_update(conn_id) {
                // Restore to initial window size
                Some(info.initial_window_size - info.send_window)
            } else {
                None
            }
        } else {
            None
        }
    }
    
    pub fn close_connection(&mut self, conn_id: u32) -> Result<(), &'static str> {
        match self.connections.get_mut(&conn_id) {
            Some(info) => {
                match info.state {
                    ConnectionState::Open => {
                        info.state = ConnectionState::Closing;
                        Ok(())
                    }
                    _ => Err("Invalid state for close"),
                }
            }
            None => Err("Connection not found"),
        }
    }
    
    pub fn finalize_close(&mut self, conn_id: u32) {
        self.connections.remove(&conn_id);
    }
    
    pub fn can_send_data(&self, conn_id: u32) -> bool {
        matches!(self.connections.get(&conn_id), Some(info) if info.state == ConnectionState::Open)
    }
    
    pub fn add_buffered_bytes(&mut self, conn_id: u32, bytes: usize) -> Result<(), &'static str> {
        if let Some(info) = self.connections.get_mut(&conn_id) {
            if info.buffered_bytes + bytes > self.limits.max_buffered_bytes {
                self.metrics.buffer_limit_breached += 1;
                return Err("Buffer limit exceeded");
            }
            info.buffered_bytes += bytes;
            Ok(())
        } else {
            Err("Connection not found")
        }
    }
    
    pub fn remove_buffered_bytes(&mut self, conn_id: u32, bytes: usize) {
        if let Some(info) = self.connections.get_mut(&conn_id) {
            info.buffered_bytes = info.buffered_bytes.saturating_sub(bytes);
        }
    }
    
    pub fn get_state(&self, conn_id: u32) -> Option<ConnectionState> {
        self.connections.get(&conn_id).map(|info| info.state)
    }
    
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }
    
    pub fn inflight_opens(&self) -> usize {
        self.inflight_opens
    }
    
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Hello { version: u8, capability_flags: u32 },
    Open { conn_id: u32, target_host: String, target_port: u16 },
    Close { conn_id: u32, reason: u8 },
    WindowUpdate { conn_id: u32, credits: u32 },
    Error { conn_id: u32, code: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub conn_id: u32,
    pub payload: Vec<u8>,
}

impl DataFrame {
    pub fn new(conn_id: u32, payload: Vec<u8>) -> Self {
        Self { conn_id, payload }
    }
    
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.payload.len());
        buf.extend_from_slice(&self.conn_id.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
    
    pub fn decode(payload: &[u8]) -> Result<Self, std::io::Error> {
        if payload.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Data payload too short",
            ));
        }
        
        let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let data = payload[4..].to_vec();
        
        Ok(DataFrame {
            conn_id,
            payload: data,
        })
    }
}

impl ControlMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        match self {
            ControlMessage::Hello { version, capability_flags } => {
                buf.push(ControlOpcode::Hello as u8);
                buf.push(*version);
                buf.extend_from_slice(&capability_flags.to_be_bytes());
            }
            ControlMessage::Open { conn_id, target_host, target_port } => {
                buf.push(ControlOpcode::Open as u8);
                buf.extend_from_slice(&conn_id.to_be_bytes());
                let host_bytes = target_host.as_bytes();
                buf.push(host_bytes.len() as u8);
                buf.extend_from_slice(host_bytes);
                buf.extend_from_slice(&target_port.to_be_bytes());
            }
            ControlMessage::Close { conn_id, reason } => {
                buf.push(ControlOpcode::Close as u8);
                buf.extend_from_slice(&conn_id.to_be_bytes());
                buf.push(*reason);
            }
            ControlMessage::WindowUpdate { conn_id, credits } => {
                buf.push(ControlOpcode::WindowUpdate as u8);
                buf.extend_from_slice(&conn_id.to_be_bytes());
                buf.extend_from_slice(&credits.to_be_bytes());
            }
            ControlMessage::Error { conn_id, code } => {
                buf.push(ControlOpcode::Error as u8);
                buf.extend_from_slice(&conn_id.to_be_bytes());
                buf.push(*code);
            }
        }
        
        buf
    }
    
    pub fn decode(payload: &[u8]) -> Result<Self, std::io::Error> {
        if payload.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Empty control payload",
            ));
        }
        
        let opcode = payload[0];
        let payload = &payload[1..];
        
        match opcode {
            0x00 => { // Hello
                if payload.len() < 5 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Hello payload too short",
                    ));
                }
                let version = payload[0];
                let capability_flags = u32::from_be_bytes([
                    payload[1], payload[2], payload[3], payload[4]
                ]);
                Ok(ControlMessage::Hello { version, capability_flags })
            }
            0x01 => { // Open
                if payload.len() < 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Control payload too short",
                    ));
                }
                
                let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let payload = &payload[4..];
                
                if payload.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Open payload missing host length",
                    ));
                }
                let host_len = payload[0] as usize;
                let payload = &payload[1..];
                
                if payload.len() < host_len + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Open payload too short for host and port",
                    ));
                }
                
                let target_host = String::from_utf8(payload[..host_len].to_vec())
                    .map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid UTF-8 in host",
                    ))?;
                
                let port_bytes = &payload[host_len..host_len + 2];
                let target_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                
                Ok(ControlMessage::Open { conn_id, target_host, target_port })
            }
            0x02 => { // Close
                if payload.len() < 5 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Close payload too short",
                    ));
                }
                let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let reason = payload[4];
                Ok(ControlMessage::Close { conn_id, reason })
            }
            0x03 => { // WindowUpdate
                if payload.len() < 8 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "WindowUpdate payload too short",
                    ));
                }
                let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let credits = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                Ok(ControlMessage::WindowUpdate { conn_id, credits })
            }
            0x04 => { // Error
                if payload.len() < 5 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Error payload too short",
                    ));
                }
                let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let code = payload[4];
                Ok(ControlMessage::Error { conn_id, code })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid control opcode",
            )),
        }
    }
}

pub struct FrameEncoder;

impl FrameEncoder {
    pub fn encode_frame<W: Write>(
        writer: &mut W,
        version: ProtocolVersion,
        frame_type: FrameType,
        payload: &[u8],
    ) -> IoResult<()> {
        let payload_len = payload.len() as u32;
        if payload_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Frame exceeds maximum size",
            ));
        }
        
        writer.write_all(&payload_len.to_be_bytes())?;
        writer.write_all(&[version])?;
        writer.write_all(&[frame_type as u8])?;
        writer.write_all(payload)?;
        Ok(())
    }
}

pub struct FrameDecoder;

impl FrameDecoder {
    pub fn decode_frame<R: Read>(
        reader: &mut R,
    ) -> IoResult<(ProtocolVersion, FrameType, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let payload_len = u32::from_be_bytes(len_buf);
        
        if payload_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame exceeds maximum size",
            ));
        }
        
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];
        
        let mut frame_type_buf = [0u8; 1];
        reader.read_exact(&mut frame_type_buf)?;
        let frame_type = match frame_type_buf[0] {
            0x01 => FrameType::Control,
            0x02 => FrameType::Data,
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid frame type",
            )),
        };
        
        let mut payload = vec![0u8; payload_len as usize];
        reader.read_exact(&mut payload)?;
        
        Ok((version, frame_type, payload))
    }
}