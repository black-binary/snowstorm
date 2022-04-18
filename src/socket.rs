use std::fmt::Debug;
use std::task::Context;
use std::task::Poll;

use bytes::Buf;
use futures_util::future::poll_fn;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use snow::HandshakeState;
use snow::StatelessTransportState;
use tokio::io::ReadBuf;

use crate::timer;
use crate::timer::timestamp;
use crate::SnowstormError;
use crate::SnowstormResult;
use crate::MAX_MESSAGE_LEN;
use crate::TAG_LEN;

const NONCE_LEN: usize = std::mem::size_of::<u64>();
const TIMESTAMP_LEN: usize = std::mem::size_of::<u32>();

type IoResult<T> = std::io::Result<T>;

pub trait PacketPoller {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<()>>;
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>>;
}

pub trait PacketVerifier {
    fn verify_packet(&mut self, timestamp: u32, nonce: u64) -> SnowstormResult<()>;
}

impl PacketVerifier for () {
    fn verify_packet(&mut self, _: u32, _: u64) -> SnowstormResult<()> {
        Ok(())
    }
}

pub trait HandshakeVerifier {
    fn verify_public_key(&mut self, public_key: &[u8]) -> SnowstormResult<()>;
    fn verify_timestamp(&mut self, timestamp: u32) -> SnowstormResult<()>;
    fn verify_handshake_hash(&mut self, handshake_hash: &[u8]) -> SnowstormResult<()>;
}

impl HandshakeVerifier for () {
    fn verify_public_key(&mut self, _: &[u8]) -> SnowstormResult<()> {
        Ok(())
    }

    fn verify_timestamp(&mut self, _: u32) -> SnowstormResult<()> {
        Ok(())
    }

    fn verify_handshake_hash(&mut self, _: &[u8]) -> SnowstormResult<()> {
        Ok(())
    }
}

async fn recv<P: PacketPoller>(p: &mut P, buf: &mut [u8]) -> IoResult<usize> {
    let mut read_buf = ReadBuf::new(buf);
    poll_fn(|cx| p.poll_recv(cx, &mut read_buf)).await?;
    Ok(read_buf.filled().len())
}

async fn send<P: PacketPoller>(p: &mut P, buf: &[u8]) -> IoResult<()> {
    poll_fn(|cx| p.poll_send(cx, buf)).await?;
    Ok(())
}

pub struct NoiseSocket<T, F> {
    inner: T,
    state: StatelessTransportState,
    send_message_buf: Vec<u8>,
    send_payload_buf: Vec<u8>,
    recv_message_buf: Vec<u8>,
    recv_payload_buf: Vec<u8>,
    filter: F,
    rng: StdRng,
}

impl<T: Debug, F: Debug> Debug for NoiseSocket<T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoisePacket")
            .field("inner", &self.inner)
            .field("filter", &self.filter)
            .finish()
    }
}

impl<T, F> NoiseSocket<T, F> {
    pub fn get_inner(&self) -> &T {
        &self.inner
    }

    pub fn get_inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_state(&self) -> &StatelessTransportState {
        &self.state
    }

    pub fn get_state_mut(&mut self) -> &mut StatelessTransportState {
        &mut self.state
    }
}

impl<T: PacketPoller, F: PacketVerifier> NoiseSocket<T, F> {
    pub async fn handshake_with_verifier<V: HandshakeVerifier>(
        mut inner: T,
        mut state: HandshakeState,
        verifier: &mut V,
        filter: F,
    ) -> SnowstormResult<Self> {
        timer::init();

        let mut buf = vec![0; MAX_MESSAGE_LEN];
        loop {
            if state.is_handshake_finished() {
                let state = state.into_stateless_transport_mode()?;

                return Ok(Self {
                    inner,
                    state,
                    send_message_buf: vec![0; NONCE_LEN + MAX_MESSAGE_LEN],
                    send_payload_buf: vec![0; MAX_MESSAGE_LEN],
                    recv_message_buf: vec![0; NONCE_LEN + MAX_MESSAGE_LEN],
                    recv_payload_buf: vec![0; MAX_MESSAGE_LEN],
                    filter,
                    rng: StdRng::from_entropy(),
                });
            }

            if state.is_my_turn() {
                let n =
                    state.write_message(&(timer::timestamp() as u32).to_le_bytes(), &mut buf)?;
                send(&mut inner, &buf[..n]).await?;
            } else {
                let n = recv(&mut inner, &mut buf).await?;
                let mut timestamp = [0; TIMESTAMP_LEN];
                let n = state.read_message(&buf[..n], &mut timestamp)?;
                if n != 4 {
                    return Err(SnowstormError::HandshakeError("message too short".into()));
                }

                let peer_time = u32::from_le_bytes(timestamp);
                verifier.verify_timestamp(peer_time)?;
            }

            let hash = state.get_handshake_hash();
            verifier.verify_handshake_hash(hash)?;

            if let Some(remote_pub) = state.get_remote_static() {
                verifier.verify_public_key(remote_pub)?;
            }
        }
    }

    pub async fn send(&mut self, buf: &[u8]) -> SnowstormResult<usize> {
        let len = buf.len();
        if len + TIMESTAMP_LEN + TAG_LEN > MAX_MESSAGE_LEN {
            return Err(SnowstormError::MalformedPacket("message too long".into()));
        }

        self.send_payload_buf[..TIMESTAMP_LEN].copy_from_slice(&(timestamp() as u32).to_le_bytes());
        self.send_payload_buf[TIMESTAMP_LEN..TIMESTAMP_LEN + len].copy_from_slice(buf);

        let nonce = self.rng.next_u64();
        self.send_message_buf[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
        let n = self.state.write_message(
            nonce,
            &self.send_payload_buf[..len + TIMESTAMP_LEN],
            &mut self.send_message_buf[NONCE_LEN..],
        )?;

        poll_fn(|cx| {
            self.inner
                .poll_send(cx, &self.send_message_buf[..NONCE_LEN + n])
        })
        .await?;

        Ok(len)
    }

    pub async fn recv(&mut self) -> SnowstormResult<&[u8]> {
        let mut read_buf = ReadBuf::new(&mut self.recv_message_buf);
        poll_fn(|cx| self.inner.poll_recv(cx, &mut read_buf)).await?;

        let mut cur = read_buf.filled();
        let nonce = cur.get_u64_le();
        let message = cur;

        // Validate the length
        let n = self
            .state
            .read_message(nonce, message, &mut self.recv_payload_buf)?;
        if n < TIMESTAMP_LEN {
            return Err(SnowstormError::MalformedPacket("short packet".into()));
        }

        // Validate the timestamp
        let ts = (&self.recv_payload_buf[..n]).get_u32_le();

        // Check if this nonce is duplicated
        self.filter.verify_packet(ts, nonce)?;

        Ok(&self.recv_payload_buf[TIMESTAMP_LEN..n])
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use futures_util::ready;
    use tokio::{
        io::ReadBuf,
        net::UdpSocket,
        sync::mpsc::{Receiver, Sender},
    };

    use crate::{NoiseSocket, PacketPoller};

    use super::IoResult;

    impl PacketPoller for UdpSocket {
        fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<()>> {
            UdpSocket::poll_send(self, cx, buf).map_ok(|_| ())
        }
        fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
            UdpSocket::poll_recv(self, cx, buf)
        }
    }

    #[tokio::test]
    async fn udp() {
        static PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s_addr = s.local_addr().unwrap();
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c_addr = c.local_addr().unwrap();

        c.connect(s_addr).await.unwrap();
        s.connect(c_addr).await.unwrap();

        let initiator = snow::Builder::new(PATTERN.parse().unwrap())
            .build_initiator()
            .unwrap();
        let responder = snow::Builder::new(PATTERN.parse().unwrap())
            .build_responder()
            .unwrap();

        tokio::spawn(async move {
            let mut a = NoiseSocket::handshake_with_verifier(s, initiator, &mut (), ())
                .await
                .unwrap();
            let buf = "hello world!".as_bytes().to_vec();

            a.send(&buf).await.unwrap();
        });

        let mut b = NoiseSocket::handshake_with_verifier(c, responder, &mut (), ())
            .await
            .unwrap();
        let buf = b.recv().await.unwrap();
        let s = String::from_utf8_lossy(buf);
        println!("{}", s);
    }

    struct TestChannel {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    }

    impl PacketPoller for TestChannel {
        fn poll_send(&mut self, _: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<()>> {
            self.tx.try_send(buf.to_vec()).unwrap();
            Poll::Ready(Ok(()))
        }
        fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
            let v = ready!(self.rx.poll_recv(cx));
            if let Some(c) = v {
                buf.put_slice(&c);
            }
            Poll::Ready(Ok(()))
        }
    }
}
