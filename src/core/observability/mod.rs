#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityLevel {
    OBS_NONE,
    OBS_SAFE,
    OBS_DEV,
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
