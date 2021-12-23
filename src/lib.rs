pub mod packet;
pub mod stream;

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

pub use packet::NoisePacket;
pub use packet::PacketPoller;
pub use stream::NoiseStream;

use thiserror::Error;

const TAG_LEN: usize = 16;
const MAX_FRAME_LEN: usize = 0xffff;
const HANDSHAKE_FRAME_LEN: usize = 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("noise protocol error from snow")]
    SnowError(#[from] snow::Error),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("handshake state error")]
    HandshakeError(String),
}
