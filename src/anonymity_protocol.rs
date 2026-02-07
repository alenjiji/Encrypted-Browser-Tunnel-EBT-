#![deny(deprecated)]

use std::io::Cursor;

use crate::anonymity::mixing::MixingPool;
use crate::relay_protocol::{DataFrame, FrameDecoder, FrameEncoder, FrameType, ProtocolVersion};

const ANONYMITY_PROTOCOL_VERSION: ProtocolVersion = 2;

pub struct AnonymityProtocolEngine {
    outbound_pool: MixingPool,
    inbound_buffer: Vec<u8>,
}

impl Default for AnonymityProtocolEngine {
    fn default() -> Self {
        Self {
            outbound_pool: MixingPool::default(),
            inbound_buffer: Vec::new(),
        }
    }
}

impl AnonymityProtocolEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, payload: Vec<u8>) {
        let frame = DataFrame::new(payload);
        let payload = frame.encode();
        let mut buffer = Vec::new();
        if FrameEncoder::encode_frame(
            &mut buffer,
            ANONYMITY_PROTOCOL_VERSION,
            FrameType::Data,
            &payload,
        )
        .is_ok()
        {
            self.outbound_pool.enqueue(buffer);
        }
    }

    pub fn drain_batch(&mut self, max_frames: usize) -> Vec<Vec<u8>> {
        self.outbound_pool.drain_batch(max_frames)
    }

    pub fn on_transport_bytes(&mut self, data: &[u8]) -> Vec<DataFrame> {
        self.inbound_buffer.extend_from_slice(data);

        let mut frames = Vec::new();
        loop {
            if self.inbound_buffer.len() < 6 {
                break;
            }

            let mut cursor = Cursor::new(&self.inbound_buffer);
            match FrameDecoder::decode_frame(&mut cursor) {
                Ok((version, frame_type, payload)) => {
                    let consumed = cursor.position() as usize;
                    self.inbound_buffer.drain(..consumed);

                    if version != ANONYMITY_PROTOCOL_VERSION || frame_type != FrameType::Data {
                        continue;
                    }

                    if let Ok(frame) = DataFrame::decode(&payload) {
                        frames.push(frame);
                    }
                }
                Err(_) => break,
            }
        }

        frames
    }
}
