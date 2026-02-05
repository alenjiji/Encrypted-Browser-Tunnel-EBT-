use std::io::{Read, Write, Result as IoResult};

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
    Open = 0x01,
    Close = 0x02,
    WindowUpdate = 0x03,
    Error = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Open { conn_id: u32, target_host: String, target_port: u16 },
    Close { conn_id: u32, reason: u8 },
    WindowUpdate { conn_id: u32, credits: u32 },
    Error { conn_id: u32, code: u8 },
}

impl ControlMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        match self {
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
        
        if payload.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Control payload too short",
            ));
        }
        
        let conn_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let payload = &payload[4..];
        
        match opcode {
            0x01 => { // Open
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
                if payload.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Close payload missing reason",
                    ));
                }
                let reason = payload[0];
                Ok(ControlMessage::Close { conn_id, reason })
            }
            0x03 => { // WindowUpdate
                if payload.len() < 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "WindowUpdate payload too short",
                    ));
                }
                let credits = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(ControlMessage::WindowUpdate { conn_id, credits })
            }
            0x04 => { // Error
                if payload.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Error payload missing code",
                    ));
                }
                let code = payload[0];
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
        
        let total_len = 2 + payload_len; // version + frame_type + payload
        writer.write_all(&total_len.to_be_bytes())?;
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
        let total_len = u32::from_be_bytes(len_buf);
        
        if total_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame exceeds maximum size",
            ));
        }
        
        if total_len < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame too small",
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
        
        let payload_len = total_len - 2;
        let mut payload = vec![0u8; payload_len as usize];
        reader.read_exact(&mut payload)?;
        
        Ok((version, frame_type, payload))
    }
}