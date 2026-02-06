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

#[inline]
pub fn record_error(_class: ErrorClass) {
    ERROR_CLASS_COUNT.fetch_add(1, Ordering::Relaxed);
}
