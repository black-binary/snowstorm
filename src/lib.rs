pub mod socket;
pub mod stream;

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

pub use socket::NoiseSocket;
pub use socket::PacketPoller;
pub use stream::NoiseStream;

use thiserror::Error;

const TAG_LEN: usize = 16;
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Debug, Error)]
pub enum Error {
    #[error("noise protocol error from snow")]
    SnowError(#[from] snow::Error),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("handshake error")]
    HandshakeError(String),
    #[error("invalid packet")]
    InvalidPacket(String),
}
