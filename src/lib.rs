pub mod socket;
pub mod stream;

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

pub use socket::NoiseSocket;
pub use socket::PacketPoller;
pub use socket::Verifier;
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
    #[error("Duplicated nonce: {0:08x}")]
    DuplicatedNonce(u64),
    #[error("Expired timestamp: {0}, now: {1}")]
    ExpiredTimestamp(u32, u32),
}
