#![deny(deprecated)]

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::anonymity::delay::{DelayDistribution, DelayQueue};
use crate::anonymity::path_epoch::{EpochDurationDistribution, PathEpoch};
use crate::phase9_protocol::Phase9ProtocolEngine;
use crate::transport_adapter::{TransportAdapter, TransportError};

const MAX_MIX_BATCH: usize = 64;
const MAX_RELEASE_BATCH: usize = 64;

pub trait EpochTransportFactory<P>: Send {
    fn open_transport(&mut self, path: &P) -> Result<Box<dyn TransportAdapter>, TransportError>;
}

pub struct Phase9BindingPump<P, DD, ED, F>
where
    DD: DelayDistribution,
    ED: EpochDurationDistribution,
    F: EpochTransportFactory<P>,
{
    protocol: Arc<Mutex<Phase9ProtocolEngine>>,
    delay: Option<DelayQueue<DD>>,
    path_epoch: Option<PathEpoch<P, ED>>,
    factory: Option<F>,
    running: Arc<Mutex<bool>>,
}

impl<P, DD, ED, F> Phase9BindingPump<P, DD, ED, F>
where
    DD: DelayDistribution,
    ED: EpochDurationDistribution,
    F: EpochTransportFactory<P>,
{
    pub fn new(
        protocol: Arc<Mutex<Phase9ProtocolEngine>>,
        delay: DelayQueue<DD>,
        path_epoch: PathEpoch<P, ED>,
        factory: F,
    ) -> Self {
        Self {
            protocol,
            delay: Some(delay),
            path_epoch: Some(path_epoch),
            factory: Some(factory),
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start(&mut self) {
        *self.running.lock().unwrap() = true;

        let protocol = Arc::clone(&self.protocol);
        let running = Arc::clone(&self.running);
        let mut delay = self.delay.take().expect("delay queue missing");
        let mut path_epoch = self.path_epoch.take().expect("path epoch missing");
        let mut factory = self.factory.take().expect("transport factory missing");
        let mut transport = match factory.open_transport(path_epoch.current_path()) {
            Ok(t) => t,
            Err(_) => {
                *running.lock().unwrap() = false;
                return;
            }
        };

        thread::spawn(move || {
            while *running.lock().unwrap() {
                let now = Instant::now();

                if path_epoch.rotate_if_due(now) {
                    if let Ok(new_transport) = factory.open_transport(path_epoch.current_path()) {
                        transport = new_transport;
                    } else {
                        *running.lock().unwrap() = false;
                        break;
                    }
                }

                let ready = delay.drain_ready_at(now, MAX_RELEASE_BATCH);
                for frame in ready {
                    if transport.send_bytes(&frame).is_err() {
                        *running.lock().unwrap() = false;
                        break;
                    }
                }

                let mixed = {
                    if let Ok(mut engine) = protocol.lock() {
                        engine.drain_batch(MAX_MIX_BATCH)
                    } else {
                        Vec::new()
                    }
                };
                for frame in mixed {
                    delay.enqueue_at(now, frame);
                }

                thread::sleep(Duration::from_millis(1));
            }
        });
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}
