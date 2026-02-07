use ssh2::{Channel, Session};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use crate::transport_adapter::{TransportAdapter, TransportCallbacks, TransportError};

/// Transport adapter that exposes an SSH channel as a raw byte stream.
/// This is intentionally single-channel and does not permit multiplexing.
pub struct SshTransportAdapter {
    _session: Session,
    channel: Arc<Mutex<Channel>>,
}

impl SshTransportAdapter {
    pub fn new(session: Session, channel: Channel) -> Self {
        Self {
            _session: session,
            channel: Arc::new(Mutex::new(channel)),
        }
    }
}

impl TransportAdapter for SshTransportAdapter {
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut channel = self.channel.lock().map_err(|_| TransportError::ConnectionLost)?;
        if channel.eof() || channel.is_closed() {
            return Err(TransportError::ConnectionLost);
        }

        channel.write_all(data).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock => TransportError::WriteBlocked,
            std::io::ErrorKind::TimedOut => TransportError::Timeout,
            _ => TransportError::ConnectionLost,
        })?;
        channel.flush().map_err(|_| TransportError::ConnectionLost)?;
        Ok(())
    }

    fn start_reading(&mut self, callbacks: Arc<Mutex<dyn TransportCallbacks>>) {
        let channel = Arc::clone(&self.channel);
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                let bytes_read = {
                    let mut channel = match channel.lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            if let Ok(mut cb) = callbacks.lock() {
                                cb.on_transport_error(TransportError::ReadError);
                            }
                            break;
                        }
                    };

                    if channel.eof() || channel.is_closed() {
                        break;
                    }

                    match channel.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            let error = match e.kind() {
                                std::io::ErrorKind::WouldBlock => continue,
                                std::io::ErrorKind::TimedOut => TransportError::Timeout,
                                _ => TransportError::ReadError,
                            };
                            if let Ok(mut cb) = callbacks.lock() {
                                cb.on_transport_error(error);
                            }
                            break;
                        }
                    }
                };

                if let Ok(mut cb) = callbacks.lock() {
                    cb.on_bytes_received(&buffer[..bytes_read]);
                }
            }
        });
    }

    fn close_transport(&mut self) {
        if let Ok(mut channel) = self.channel.lock() {
            let _ = channel.close();
            let _ = channel.wait_close();
        }
    }
}
