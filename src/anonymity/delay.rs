use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;

use crate::anonymity::mixing::Frame;

pub trait DelayDistribution {
    fn sample_delay(&mut self, rng: &mut OsRng) -> Duration;
}

#[derive(Debug, Clone)]
pub struct UniformDelay {
    min_ns: u64,
    max_ns: u64,
}

impl UniformDelay {
    pub fn new(min: Duration, max: Duration) -> Result<Self, &'static str> {
        if min.is_zero() {
            return Err("min delay must be > 0");
        }
        if max < min {
            return Err("max delay must be >= min delay");
        }
        let min_ns = u64::try_from(min.as_nanos()).map_err(|_| "min delay too large")?;
        let max_ns = u64::try_from(max.as_nanos()).map_err(|_| "max delay too large")?;
        Ok(Self { min_ns, max_ns })
    }
}

impl DelayDistribution for UniformDelay {
    fn sample_delay(&mut self, rng: &mut OsRng) -> Duration {
        let span = self.max_ns.saturating_sub(self.min_ns);
        let offset = if span == 0 {
            0
        } else {
            rng.next_u64() % (span + 1)
        };
        Duration::from_nanos(self.min_ns.saturating_add(offset))
    }
}

#[derive(Debug)]
struct PendingFrame {
    ready_at: Instant,
    nonce: u64,
    frame: Frame,
}

impl PartialEq for PendingFrame {
    fn eq(&self, other: &Self) -> bool {
        self.ready_at == other.ready_at && self.nonce == other.nonce
    }
}

impl Eq for PendingFrame {}

impl PartialOrd for PendingFrame {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingFrame {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ready_at
            .cmp(&other.ready_at)
            .then_with(|| self.nonce.cmp(&other.nonce))
    }
}

pub struct DelayQueue<D: DelayDistribution> {
    distribution: D,
    rng: OsRng,
    pending: BinaryHeap<std::cmp::Reverse<PendingFrame>>,
    ready: VecDeque<Frame>,
}

impl<D: DelayDistribution> DelayQueue<D> {
    pub fn new(distribution: D) -> Self {
        Self {
            distribution,
            rng: OsRng,
            pending: BinaryHeap::new(),
            ready: VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, frame: Frame) {
        let mut delay = self.distribution.sample_delay(&mut self.rng);
        if delay.is_zero() {
            delay = Duration::from_nanos(1);
        }
        let ready_at = Instant::now() + delay;
        let nonce = self.rng.next_u64();
        self.pending.push(std::cmp::Reverse(PendingFrame {
            ready_at,
            nonce,
            frame,
        }));
    }

    pub fn drain_ready(&mut self, max_frames: usize) -> Vec<Frame> {
        if max_frames == 0 {
            return Vec::new();
        }

        self.collect_ready();

        let mut drained = Vec::new();
        while drained.len() < max_frames {
            match self.ready.pop_front() {
                Some(frame) => drained.push(frame),
                None => break,
            }
        }

        drained
    }

    fn collect_ready(&mut self) {
        let now = Instant::now();
        let mut ready = Vec::new();
        while let Some(std::cmp::Reverse(peek)) = self.pending.peek() {
            if peek.ready_at > now {
                break;
            }
            if let Some(std::cmp::Reverse(frame)) = self.pending.pop() {
                ready.push(frame.frame);
            }
        }

        if !ready.is_empty() {
            ready.shuffle(&mut self.rng);
            self.ready.extend(ready);
        }
    }
}
