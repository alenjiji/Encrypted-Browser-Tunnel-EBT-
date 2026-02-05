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