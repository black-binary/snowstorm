use std::collections::VecDeque;
use std::fmt::Debug;
use std::task::Context;
use std::task::Poll;

use bytes::Buf;
use futures_util::future::poll_fn;
use rand::prelude::StdRng;
use rand::SeedableRng;
use scalable_cuckoo_filter::DefaultHasher;
use scalable_cuckoo_filter::ScalableCuckooFilter;
use scalable_cuckoo_filter::ScalableCuckooFilterBuilder;
use snow::HandshakeState;
use snow::StatelessTransportState;
use tokio::io::ReadBuf;

use crate::Error;
use crate::MAX_MESSAGE_LEN;
use crate::TAG_LEN;

const NONCE_LEN: usize = std::mem::size_of::<u64>();
const TIMESTAMP_LEN: usize = std::mem::size_of::<u32>();
const EXPIRE_SECS: u32 = 60;

pub trait PacketPoller {
    fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>>;
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

async fn recv<P: PacketPoller>(p: &mut P, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut read_buf = ReadBuf::new(buf);
    poll_fn(|cx| p.poll_recv(cx, &mut read_buf)).await?;
    Ok(read_buf.filled().len())
}

async fn send<P: PacketPoller>(p: &mut P, buf: &[u8]) -> std::io::Result<usize> {
    let n = poll_fn(|cx| p.poll_send(cx, buf)).await?;
    Ok(n)
}

#[inline]
fn now() -> u32 {
    coarsetime::Clock::now_since_epoch().as_secs() as u32
}

pub struct NoiseSocket<T> {
    inner: T,
    transport: StatelessTransportState,
    send_message_buf: Vec<u8>,
    send_payload_buf: Vec<u8>,
    recv_message_buf: Vec<u8>,
    recv_payload_buf: Vec<u8>,
    filter: VecDeque<(u32, ScalableCuckooFilter<u64, DefaultHasher, StdRng>)>,
    peer_time: u32,
}

impl<T: Debug> Debug for NoiseSocket<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoisePacket")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T: PacketPoller> NoiseSocket<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn state(&self) -> &StatelessTransportState {
        &self.transport
    }

    pub fn state_mut(&mut self) -> &mut StatelessTransportState {
        &mut self.transport
    }

    #[inline]
    pub async fn handshake(inner: T, state: HandshakeState) -> Result<Self, Error> {
        Self::handshake_with_verifier(inner, state, |_| true).await
    }

    fn new_filter() -> ScalableCuckooFilter<u64, DefaultHasher, StdRng> {
        ScalableCuckooFilterBuilder::new()
            .rng(StdRng::from_entropy())
            .finish()
    }

    pub async fn handshake_with_verifier<F: FnOnce(&[u8]) -> bool>(
        mut inner: T,
        mut state: HandshakeState,
        verifier: F,
    ) -> Result<Self, Error> {
        let mut last_sent = vec![];
        let mut f = Some(verifier);

        loop {
            if state.is_handshake_finished() {
                let transport = state.into_stateless_transport_mode()?;
                let mut filter = VecDeque::new();
                filter.push_back((0, Self::new_filter()));
                filter.push_back((0, Self::new_filter()));

                return Ok(Self {
                    inner,
                    transport,
                    filter,
                    send_message_buf: vec![0; NONCE_LEN + MAX_MESSAGE_LEN],
                    send_payload_buf: vec![0; MAX_MESSAGE_LEN],
                    recv_message_buf: vec![0; NONCE_LEN + MAX_MESSAGE_LEN],
                    recv_payload_buf: vec![0; MAX_MESSAGE_LEN],
                    peer_time: 0,
                });
            }

            if state.is_my_turn() {
                last_sent.resize(MAX_MESSAGE_LEN, 0);
                let n = state.write_message(&[], &mut last_sent)?;
                last_sent.truncate(n);
                send(&mut inner, &last_sent).await?;
            } else {
                let mut recv_buf = vec![0; MAX_MESSAGE_LEN];
                let n = recv(&mut inner, &mut recv_buf).await?;
                let mut payload_buf = vec![0; MAX_MESSAGE_LEN];
                state.read_message(&recv_buf[..n], &mut payload_buf)?;

                if let Some(remote_pub) = state.get_remote_static() {
                    if let Some(f) = f.take() {
                        if !f(remote_pub) {
                            return Err(Error::HandshakeError("invalid public key".to_string()));
                        }
                    }
                }
            }
        }
    }

    pub async fn send(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let len = buf.len();
        if len + TIMESTAMP_LEN + TAG_LEN > MAX_MESSAGE_LEN {
            return Err(Error::InvalidPacket("message too long".into()));
        }

        self.send_payload_buf[..TIMESTAMP_LEN].copy_from_slice(&now().to_le_bytes());
        self.send_payload_buf[TIMESTAMP_LEN..TIMESTAMP_LEN + len].copy_from_slice(buf);

        let nonce: u64 = rand::random();
        self.send_message_buf[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
        let n = self.transport.write_message(
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

    fn add_nonce(&mut self, nonce: u64) {
        if self.peer_time > self.filter.front().unwrap().0 + EXPIRE_SECS * 2 {
            self.filter.pop_front();
            self.filter.push_back((self.peer_time, Self::new_filter()));
        }
        self.filter.back_mut().unwrap().1.insert(&nonce);
    }

    pub async fn recv(&mut self) -> Result<&[u8], Error> {
        let mut read_buf = ReadBuf::new(&mut self.recv_message_buf);
        poll_fn(|cx| self.inner.poll_recv(cx, &mut read_buf)).await?;

        let mut cur = read_buf.filled();
        let nonce = cur.get_u64_le();
        let message = cur;

        // Check if this nonce is duplicated
        if self
            .filter
            .iter()
            .any(|(_, filter)| filter.contains(&nonce))
        {
            return Err(Error::InvalidPacket(format!("duplicated nonce: {}", nonce)));
        }

        // Validate the length
        let n = self
            .transport
            .read_message(nonce, message, &mut self.recv_payload_buf)?;
        if n < TIMESTAMP_LEN {
            return Err(Error::InvalidPacket("short packet".into()));
        }

        // Validate the timestamp
        let ts = (&self.recv_payload_buf[..n]).get_u32_le();
        if self.peer_time > ts + EXPIRE_SECS {
            return Err(Error::InvalidPacket(format!(
                "expired packet {}, current: {}",
                ts, self.peer_time
            )));
        }

        self.peer_time = self.peer_time.max(ts);
        self.add_nonce(nonce);

        Ok(&self.recv_payload_buf[TIMESTAMP_LEN..n])
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use futures_util::ready;
    use rand::Rng;
    use tokio::{
        io::ReadBuf,
        net::UdpSocket,
        sync::mpsc::{channel, Receiver, Sender},
    };

    use crate::{NoiseSocket, PacketPoller};

    impl PacketPoller for UdpSocket {
        fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            UdpSocket::poll_send(self, cx, buf)
        }
        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
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
            let mut a = NoiseSocket::handshake(s, initiator).await.unwrap();
            let buf = "hello world!".as_bytes().to_vec();

            a.send(&buf).await.unwrap();
        });

        let mut b = NoiseSocket::handshake(c, responder).await.unwrap();
        let buf = b.recv().await.unwrap();
        let s = String::from_utf8_lossy(buf);
        println!("{}", s);
    }

    struct TestChannel {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    }

    impl PacketPoller for TestChannel {
        fn poll_send(&mut self, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            self.tx.try_send(buf.to_vec()).unwrap();
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let v = ready!(self.rx.poll_recv(cx));
            if let Some(c) = v {
                buf.put_slice(&c);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl TestChannel {
        fn new_pair() -> (Self, Self) {
            let (tx1, rx1) = channel(0x100);
            let (tx2, rx2) = channel(0x100);
            (Self { tx: tx1, rx: rx2 }, Self { tx: tx2, rx: rx1 })
        }
    }

    #[tokio::test]
    async fn attack() {
        static PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let (a, b) = TestChannel::new_pair();
        let a_tx = a.tx.clone();

        let initiator = snow::Builder::new(PATTERN.parse().unwrap())
            .build_initiator()
            .unwrap();
        let responder = snow::Builder::new(PATTERN.parse().unwrap())
            .build_responder()
            .unwrap();

        let h = tokio::spawn(async move {
            let a = NoiseSocket::handshake(a, initiator).await.unwrap();
            a
        });

        let mut b = NoiseSocket::handshake(b, responder).await.unwrap();
        let a = h.await.unwrap();

        let t = super::now();

        // Replay
        for _ in 0..2 {
            let mut buf = vec![0; 1000];
            buf[0] = 233;
            let n = a
                .transport
                .write_message(233, &t.to_le_bytes(), &mut buf[8..])
                .unwrap();
            a_tx.send(buf[..8 + n].to_vec()).await.unwrap();
        }

        b.recv().await.unwrap();
        println!("{:?}", b.recv().await.unwrap_err());

        // Malformed
        a_tx.send(b"11111111111111111111111".to_vec())
            .await
            .unwrap();
        println!("{}", b.recv().await.unwrap_err());

        // Short
        let mut buf = vec![0; 1000];
        buf[0] = 1;
        let n = a.transport.write_message(1, b"123", &mut buf[8..]).unwrap();
        a_tx.send(buf[..8 + n].to_vec()).await.unwrap();
        println!("{:?}", b.recv().await.unwrap_err());

        // Replay expired
        buf[0] = 1;
        let n = a
            .transport
            .write_message(1, &(t - 1000).to_le_bytes(), &mut buf[8..])
            .unwrap();
        a_tx.send(buf[..8 + n].to_vec()).await.unwrap();
        println!("{:?}", b.recv().await.unwrap_err());

        // Update
        let packets = (0..100)
            .map(|_| {
                let mut buf = vec![0; 1000];
                let delta = rand::thread_rng().gen_range(0..super::EXPIRE_SECS / 2);
                let t = t + delta;
                let nonce = rand::random();
                let n = a
                    .transport
                    .write_message(nonce, &t.to_le_bytes(), &mut buf[8..])
                    .unwrap();
                buf[..8].copy_from_slice(&nonce.to_le_bytes());

                buf[..n + 8].to_vec()
            })
            .collect::<Vec<_>>();

        for p in packets.into_iter() {
            a_tx.send(p).await.unwrap();
            b.recv().await.unwrap();
        }
    }
}
