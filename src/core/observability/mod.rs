#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityLevel {
    OBS_NONE,
    OBS_SAFE,
    OBS_DEV,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    PROTOCOL_VIOLATION,
    TRANSPORT_IO,
    RESOURCE_LIMIT,
    INTERNAL_ASSERT,
    #[doc(hidden)]
    _Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    OK,
    DEGRADED,
    FAULTED,
    #[doc(hidden)]
    _Private,
}

#[cfg(feature = "obs_none")]
pub const OBS_LEVEL: ObservabilityLevel = ObservabilityLevel::OBS_NONE;

#[cfg(feature = "obs_dev")]
pub const OBS_LEVEL: ObservabilityLevel = ObservabilityLevel::OBS_DEV;

#[cfg(all(not(feature = "obs_none"), not(feature = "obs_dev")))]
pub const OBS_LEVEL: ObservabilityLevel = ObservabilityLevel::OBS_SAFE;

pub const OBS_NONE: bool = matches!(OBS_LEVEL, ObservabilityLevel::OBS_NONE);
pub const OBS_SAFE: bool = matches!(OBS_LEVEL, ObservabilityLevel::OBS_SAFE);
pub const OBS_DEV: bool = matches!(OBS_LEVEL, ObservabilityLevel::OBS_DEV);

use std::sync::atomic::{AtomicU64, Ordering};

static ERROR_CLASS_COUNT: AtomicU64 = AtomicU64::new(0);
static HEALTH_STATE: AtomicU64 = AtomicU64::new(HealthState::OK as u64);

#[inline]
pub fn record_error(_class: ErrorClass) {
    ERROR_CLASS_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn set_health(state: HealthState) {
    HEALTH_STATE.store(state as u64, Ordering::Relaxed);
}

#[inline]
pub fn get_health() -> HealthState {
    match HEALTH_STATE.load(Ordering::Relaxed) {
        x if x == HealthState::OK as u64 => HealthState::OK,
        x if x == HealthState::DEGRADED as u64 => HealthState::DEGRADED,
        x if x == HealthState::FAULTED as u64 => HealthState::FAULTED,
        _ => HealthState::FAULTED,
    }
}

static TOTAL_CONNECTIONS_OPENED: AtomicU64 = AtomicU64::new(0);
static TOTAL_CONNECTIONS_CLOSED: AtomicU64 = AtomicU64::new(0);
static FRAMES_SENT: AtomicU64 = AtomicU64::new(0);
static FRAMES_RECEIVED: AtomicU64 = AtomicU64::new(0);

const BYTE_BUCKETS: usize = 21;
static BYTES_SENT_COARSE: [AtomicU64; BYTE_BUCKETS] = [const { AtomicU64::new(0) }; BYTE_BUCKETS];
static BYTES_RECEIVED_COARSE: [AtomicU64; BYTE_BUCKETS] = [const { AtomicU64::new(0) }; BYTE_BUCKETS];

#[inline]
pub fn record_connection_opened() {
    TOTAL_CONNECTIONS_OPENED.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_connection_closed() {
    TOTAL_CONNECTIONS_CLOSED.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_frame_sent() {
    FRAMES_SENT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_frame_received() {
    FRAMES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_bytes_sent_coarse(byte_len: usize) {
    let idx = coarse_bucket_index(byte_len);
    BYTES_SENT_COARSE[idx].fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_bytes_received_coarse(byte_len: usize) {
    let idx = coarse_bucket_index(byte_len);
    BYTES_RECEIVED_COARSE[idx].fetch_add(1, Ordering::Relaxed);
}

#[inline]
const fn coarse_bucket_index(byte_len: usize) -> usize {
    if byte_len == 0 {
        return 0;
    }
    let mut v = byte_len;
    let mut idx: usize = 0;
    while v > 1 && idx + 1 < BYTE_BUCKETS {
        v >>= 1;
        idx += 1;
    }
    idx
}

#[derive(Debug, Clone)]
pub struct ObservabilitySnapshot {
    pub total_connections_opened: u64,
    pub total_connections_closed: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent_coarse: [u64; BYTE_BUCKETS],
    pub bytes_received_coarse: [u64; BYTE_BUCKETS],
    pub error_class_total: u64,
}

pub fn snapshot() -> ObservabilitySnapshot {
    ObservabilitySnapshot {
        total_connections_opened: TOTAL_CONNECTIONS_OPENED.load(Ordering::Relaxed),
        total_connections_closed: TOTAL_CONNECTIONS_CLOSED.load(Ordering::Relaxed),
        frames_sent: FRAMES_SENT.load(Ordering::Relaxed),
        frames_received: FRAMES_RECEIVED.load(Ordering::Relaxed),
        bytes_sent_coarse: BYTES_SENT_COARSE.map(|c| c.load(Ordering::Relaxed)),
        bytes_received_coarse: BYTES_RECEIVED_COARSE.map(|c| c.load(Ordering::Relaxed)),
        error_class_total: ERROR_CLASS_COUNT.load(Ordering::Relaxed),
    }
}
