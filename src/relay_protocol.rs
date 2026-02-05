pub type ProtocolVersion = u8;

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