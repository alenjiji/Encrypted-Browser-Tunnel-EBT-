use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rand::seq::SliceRandom;

pub type Frame = Vec<u8>;

pub struct MixingPool<R: RngCore + CryptoRng = OsRng> {
    current_epoch: Vec<Frame>,
    next_epoch: Vec<Frame>,
    rng: R,
}

impl Default for MixingPool<OsRng> {
    fn default() -> Self {
        Self {
            current_epoch: Vec::new(),
            next_epoch: Vec::new(),
            rng: OsRng,
        }
    }
}

impl MixingPool<OsRng> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<R: RngCore + CryptoRng> MixingPool<R> {
    pub fn with_rng(rng: R) -> Self {
        Self {
            current_epoch: Vec::new(),
            next_epoch: Vec::new(),
            rng,
        }
    }

    pub fn enqueue(&mut self, frame: Frame) {
        self.next_epoch.push(frame);
    }

    pub fn drain_batch(&mut self, max_frames: usize) -> Vec<Frame> {
        if max_frames == 0 {
            return Vec::new();
        }

        let mut drained = Vec::new();
        while drained.len() < max_frames {
            if self.current_epoch.is_empty() {
                if self.next_epoch.is_empty() {
                    break;
                }
                self.rotate_epoch();
            }

            if let Some(frame) = self.current_epoch.pop() {
                drained.push(frame);
            } else {
                break;
            }
        }

        drained
    }

    fn rotate_epoch(&mut self) {
        if self.next_epoch.is_empty() {
            return;
        }
        std::mem::swap(&mut self.current_epoch, &mut self.next_epoch);
        self.current_epoch.shuffle(&mut self.rng);
    }
}
