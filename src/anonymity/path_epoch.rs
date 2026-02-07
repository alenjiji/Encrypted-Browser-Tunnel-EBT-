use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

pub trait EpochDurationDistribution {
    fn sample_duration(&mut self, rng: &mut dyn RngCore) -> Duration;
}

#[derive(Debug, Clone)]
pub struct UniformEpochDuration {
    min_ns: u64,
    max_ns: u64,
}

impl UniformEpochDuration {
    pub fn new(min: Duration, max: Duration) -> Result<Self, &'static str> {
        if min.is_zero() {
            return Err("min epoch duration must be > 0");
        }
        if max < min {
            return Err("max epoch duration must be >= min epoch duration");
        }
        let min_ns = u64::try_from(min.as_nanos()).map_err(|_| "min duration too large")?;
        let max_ns = u64::try_from(max.as_nanos()).map_err(|_| "max duration too large")?;
        Ok(Self { min_ns, max_ns })
    }
}

impl EpochDurationDistribution for UniformEpochDuration {
    fn sample_duration(&mut self, rng: &mut dyn RngCore) -> Duration {
        let span = self.max_ns.saturating_sub(self.min_ns);
        let offset = if span == 0 {
            0
        } else {
            rng.next_u64() % (span + 1)
        };
        Duration::from_nanos(self.min_ns.saturating_add(offset))
    }
}

pub struct PathEpoch<P, D: EpochDurationDistribution, R: RngCore + CryptoRng = OsRng> {
    paths: Vec<P>,
    distribution: D,
    rng: R,
    current_index: usize,
    next_rotation: Instant,
    epoch_nonce: u64,
}

impl<P, D: EpochDurationDistribution> PathEpoch<P, D, OsRng> {
    pub fn new(paths: Vec<P>, distribution: D) -> Result<Self, &'static str> {
        Self::with_rng(paths, distribution, OsRng)
    }
}

impl<P, D: EpochDurationDistribution, R: RngCore + CryptoRng> PathEpoch<P, D, R> {
    pub fn with_rng(paths: Vec<P>, mut distribution: D, mut rng: R) -> Result<Self, &'static str> {
        if paths.is_empty() {
            return Err("path list must not be empty");
        }
        let current_index = (rng.next_u64() as usize) % paths.len();
        let duration = distribution.sample_duration(&mut rng);
        let duration = if duration.is_zero() {
            Duration::from_nanos(1)
        } else {
            duration
        };
        let next_rotation = Instant::now() + duration;
        let epoch_nonce = rng.next_u64();
        Ok(Self {
            paths,
            distribution,
            rng,
            current_index,
            next_rotation,
            epoch_nonce,
        })
    }

    pub fn current_path(&self) -> &P {
        &self.paths[self.current_index]
    }

    pub fn path_at(&self, index: usize) -> &P {
        &self.paths[index]
    }

    pub fn epoch_nonce(&self) -> u64 {
        self.epoch_nonce
    }

    pub fn is_due(&self, now: Instant) -> bool {
        now >= self.next_rotation
    }

    pub fn next_index(&mut self) -> usize {
        self.select_next_index()
    }

    pub fn schedule_next_rotation(&mut self, now: Instant) {
        let duration = self.distribution.sample_duration(&mut self.rng);
        let duration = if duration.is_zero() {
            Duration::from_nanos(1)
        } else {
            duration
        };
        self.next_rotation = now + duration;
    }

    pub fn commit_rotation(&mut self, next_index: usize, now: Instant) {
        self.current_index = next_index;
        self.epoch_nonce = self.rng.next_u64();
        self.schedule_next_rotation(now);
    }

    pub fn rotate_if_due(&mut self, now: Instant) -> bool {
        if !self.is_due(now) {
            return false;
        }

        let next_index = self.select_next_index();
        self.commit_rotation(next_index, now);
        true
    }

    fn select_next_index(&mut self) -> usize {
        if self.paths.len() == 1 {
            return 0;
        }
        let mut idx = (self.rng.next_u64() as usize) % self.paths.len();
        if idx == self.current_index {
            idx = (idx + 1) % self.paths.len();
        }
        idx
    }
}
