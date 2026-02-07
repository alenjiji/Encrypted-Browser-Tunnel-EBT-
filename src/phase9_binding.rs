#![deny(deprecated)]

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::anonymity::delay::{DelayDistribution, DelayQueue};
use crate::phase9_protocol::Phase9ProtocolEngine;
use crate::transport_adapter::TransportAdapter;

const MAX_MIX_BATCH: usize = 64;
const MAX_RELEASE_BATCH: usize = 64;

pub struct Phase9BindingPump<D: DelayDistribution> {
    protocol: Arc<Mutex<Phase9ProtocolEngine>>,
    delay: Option<DelayQueue<D>>,
    transport: Option<Box<dyn TransportAdapter>>,
    running: Arc<Mutex<bool>>,
}

impl<D: DelayDistribution> Phase9BindingPump<D> {
    pub fn new(
        protocol: Arc<Mutex<Phase9ProtocolEngine>>,
        delay: DelayQueue<D>,
        transport: Box<dyn TransportAdapter>,
    ) -> Self {
        Self {
            protocol,
            delay: Some(delay),
            transport: Some(transport),
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start(&mut self) {
        *self.running.lock().unwrap() = true;

        let protocol = Arc::clone(&self.protocol);
        let running = Arc::clone(&self.running);
        let mut delay = self.delay.take().expect("delay queue missing");
        let mut transport = self.transport.take().expect("transport missing");

        thread::spawn(move || {
            while *running.lock().unwrap() {
                let ready = delay.drain_ready(MAX_RELEASE_BATCH);
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
                    delay.enqueue(frame);
                }

                thread::sleep(Duration::from_millis(1));
            }
        });
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}
