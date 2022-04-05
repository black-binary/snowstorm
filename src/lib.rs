#[cfg(feature = "socket")]
pub mod socket;
#[cfg(feature = "stream")]
pub mod stream;
#[cfg(feature = "socket")]
pub mod timer;

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

#[cfg(feature = "socket")]
pub use socket::NoiseSocket;
#[cfg(feature = "socket")]
pub use socket::PacketPoller;
#[cfg(feature = "socket")]
pub use socket::Verifier;
#[cfg(feature = "stream")]
pub use stream::NoiseStream;

use thiserror::Error;

const TAG_LEN: usize = 16;
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Snow error: {0}")]
    SnowError(#[from] snow::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Handshake error: {0}")]
    HandshakeError(String),
    #[error("Malformed packet: {0}")]
    MalformedPacket(String),
    #[error("Invalid nonce: {0:08x}")]
    InvalidNonce(u64),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u32),
}
