use crate::transport::{EncryptedTransport, TransportError};
use crate::ssh_transport_adapter::SshTransportAdapter;
use ssh2::Session;
use std::cell::RefCell;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

/// SSH-based encrypted transport
pub struct SshTransport {
    host: String,
    port: u16,
    session: Option<Session>,
    channel: RefCell<Option<ssh2::Channel>>,
    channel_opened: bool,
}

impl SshTransport {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            session: None,
            channel: RefCell::new(None),
            channel_opened: false,
        }
    }

    /// Consume the transport and expose a single-channel adapter for the relay protocol.
    /// This is the only allowed channel; we do not permit multiplexing or additional channels.
    pub fn into_adapter(self) -> Result<SshTransportAdapter, TransportError> {
        if !self.channel_opened {
            return Err(TransportError::ConnectionFailed);
        }
        if self.channel.borrow().is_none() || self.session.is_none() {
            return Err(TransportError::ConnectionFailed);
        }

        let channel = self.channel.into_inner().ok_or(TransportError::ConnectionFailed)?;
        let session = self.session.ok_or(TransportError::ConnectionFailed)?;

        Ok(SshTransportAdapter::new(session, channel))
    }

    fn resolve_username() -> Option<String> {
        env::var("USER").ok().or_else(|| env::var("USERNAME").ok())
    }

    fn resolve_default_key_paths() -> Vec<PathBuf> {
        let home = env::var("USERPROFILE").ok().or_else(|| env::var("HOME").ok());
        let Some(home) = home else {
            return Vec::new();
        };
        vec![
            PathBuf::from(&home).join(".ssh").join("id_ed25519"),
            PathBuf::from(&home).join(".ssh").join("id_rsa"),
        ]
    }
}

impl EncryptedTransport for SshTransport {
    async fn establish_connection(&mut self) -> Result<(), TransportError> {
        // Multiplexing neutralization:
        // We allow exactly one SSH channel for the lifetime of this transport.
        // Any attempt to re-establish or open additional channels is a hard failure.
        if self.session.is_some() || self.channel_opened || self.channel.borrow().is_some() {
            return Err(TransportError::ConnectionFailed);
        }

        let tcp_stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|_| TransportError::ConnectionFailed)?;

        let mut session = Session::new().ok_or(TransportError::ConnectionFailed)?;
        session.set_tcp_stream(tcp_stream);
        session
            .handshake()
            .map_err(|_| TransportError::ConnectionFailed)?;

        let username =
            Self::resolve_username().ok_or(TransportError::ConnectionFailed)?;

        let mut authenticated = session.userauth_agent(&username).is_ok();

        if !authenticated {
            for key_path in Self::resolve_default_key_paths() {
                if key_path.exists() {
                    let result =
                        session.userauth_pubkey_file(&username, None, &key_path, None);
                    if result.is_ok() {
                        authenticated = true;
                        break;
                    }
                }
            }
        }

        if !authenticated || !session.authenticated() {
            return Err(TransportError::ConnectionFailed);
        }

        let channel = session
            .channel_session()
            .map_err(|_| TransportError::ConnectionFailed)?;

        self.channel.replace(Some(channel));
        self.session = Some(session);
        self.channel_opened = true;
        Ok(())
    }

    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut channel_ref = self.channel.borrow_mut();
        let Some(channel) = channel_ref.as_mut() else {
            return Err(TransportError::EncryptionFailed);
        };

        if channel.eof() || channel.is_closed() {
            return Err(TransportError::ConnectionFailed);
        }

        channel
            .write_all(data)
            .map_err(|_| TransportError::ConnectionFailed)?;
        channel
            .flush()
            .map_err(|_| TransportError::ConnectionFailed)?;

        Ok(data.to_vec())
    }

    async fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut channel_ref = self.channel.borrow_mut();
        let Some(channel) = channel_ref.as_mut() else {
            return Err(TransportError::DecryptionFailed);
        };

        if channel.eof() || channel.is_closed() {
            return Err(TransportError::ConnectionFailed);
        }

        let mut buffer = vec![0u8; data.len()];
        channel
            .read_exact(&mut buffer)
            .map_err(|_| TransportError::ConnectionFailed)?;

        Ok(buffer)
    }
}
