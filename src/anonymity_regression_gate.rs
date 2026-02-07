use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::{CryptoRng, RngCore};

use crate::anonymity::delay::{DelayQueue, UniformDelay};
use crate::anonymity::mixing::MixingPool;

const INGRESS_WINDOW_TICKS: u64 = 5_000;
const MIN_DELAY_MS: u64 = 1_000;
const MAX_DELAY_MS: u64 = 200_000;
const MAX_MIX_BATCH: usize = 1_024;
const MAX_RELEASE_BATCH: usize = 4_096;
const REGRESSION_THRESHOLD: f64 = 0.05;

#[derive(Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_splitmix(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E3779B97F4A7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_splitmix() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_splitmix()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let value = self.next_u64().to_be_bytes();
            let take = (dest.len() - i).min(value.len());
            dest[i..i + take].copy_from_slice(&value[..take]);
            i += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

fn run_simulation(users: usize, total_frames: usize) -> f64 {
    let frames_per_user_per_tick = total_frames / (users * INGRESS_WINDOW_TICKS as usize);
    assert!(frames_per_user_per_tick > 0, "frames per tick must be > 0");

    let mut mixing = MixingPool::with_rng(DeterministicRng::new(0xA11CE5EED));
    let delay = UniformDelay::new(
        Duration::from_millis(MIN_DELAY_MS),
        Duration::from_millis(MAX_DELAY_MS),
    )
    .expect("invalid delay bounds");
    let mut delay_queue = DelayQueue::with_rng(delay, DeterministicRng::new(0xD1A1A7E));

    let base = Instant::now();
    let max_delay_ticks = MAX_DELAY_MS;
    let end_tick = INGRESS_WINDOW_TICKS + max_delay_ticks + 1;

    let mut next_id: u64 = 1;
    let mut ingress: HashMap<u64, f64> = HashMap::new();
    let mut egress: HashMap<u64, f64> = HashMap::new();
    let mut sent = 0usize;

    for tick in 0..=end_tick {
        let now = base + Duration::from_millis(tick);

        if tick < INGRESS_WINDOW_TICKS && sent < total_frames {
            for _ in 0..frames_per_user_per_tick {
                for _user in 0..users {
                    if sent >= total_frames {
                        break;
                    }
                    let id = next_id;
                    next_id += 1;
                    sent += 1;
                    ingress.insert(id, tick as f64);
                    mixing.enqueue(id.to_be_bytes().to_vec());
                }
                if sent >= total_frames {
                    break;
                }
            }
        }

        let mixed = mixing.drain_batch(MAX_MIX_BATCH);
        for frame in mixed {
            delay_queue.enqueue_at(now, frame);
        }

        let released = delay_queue.drain_ready_at(now, MAX_RELEASE_BATCH);
        for frame in released {
            let id = u64::from_be_bytes(frame[..8].try_into().expect("frame id missing"));
            egress.insert(id, tick as f64);
        }

        if sent == total_frames && egress.len() == total_frames {
            break;
        }
    }

    assert_eq!(sent, total_frames, "failed to enqueue all frames");
    assert_eq!(egress.len(), total_frames, "failed to drain all frames");

    let mut ingress_times = Vec::with_capacity(total_frames);
    let mut egress_times = Vec::with_capacity(total_frames);
    for id in 1..=total_frames as u64 {
        ingress_times.push(*ingress.get(&id).expect("missing ingress time"));
        egress_times.push(*egress.get(&id).expect("missing egress time"));
    }

    pearson_corr(&ingress_times, &egress_times)
}

fn pearson_corr(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    assert_eq!(n, ys.len());
    let n_f = n as f64;
    let mean_x = xs.iter().sum::<f64>() / n_f;
    let mean_y = ys.iter().sum::<f64>() / n_f;
    let mut num = 0.0;
    let mut denom_x = 0.0;
    let mut denom_y = 0.0;
    for i in 0..n {
        let dx = xs[i] - mean_x;
        let dy = ys[i] - mean_y;
        num += dx * dy;
        denom_x += dx * dx;
        denom_y += dy * dy;
    }
    if denom_x == 0.0 || denom_y == 0.0 {
        0.0
    } else {
        num / (denom_x.sqrt() * denom_y.sqrt())
    }
}

#[test]
fn anonymity_regression_gate_single_user() {
    let r = run_simulation(1, 20_000);
    assert!(
        r.abs() <= REGRESSION_THRESHOLD,
        "ANONYMITY REGRESSION: single-user correlation {r} exceeds threshold {REGRESSION_THRESHOLD}"
    );
}

#[test]
fn anonymity_regression_gate_multi_user() {
    let r = run_simulation(5, 100_000);
    assert!(
        r.abs() <= REGRESSION_THRESHOLD,
        "ANONYMITY REGRESSION: multi-user correlation {r} exceeds threshold {REGRESSION_THRESHOLD}"
    );
}
