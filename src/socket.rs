use std::fmt::Debug;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use bytes::Buf;
use exponential_backoff::Backoff;
use futures_util::future::poll_fn;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use snow::HandshakeState;
use snow::StatelessTransportState;
use tokio::io::ReadBuf;

use crate::Error;
use crate::MAX_MESSAGE_LEN;

const NONCE_LEN: usize = 8;

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

pub struct NoiseSocket<T> {
    inner: T,
    transport: StatelessTransportState,
    rng: ChaCha20Rng,
    send_buf: Vec<u8>,
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
    pub async fn handshake(
        inner: T,
        state: HandshakeState,
        min_resend_interval: Duration,
        max_retires: u32,
    ) -> Result<Self, Error> {
        Self::handshake_with_verifier(inner, state, min_resend_interval, max_retires, |_| true)
            .await
    }

    pub async fn handshake_with_verifier<F: FnOnce(&[u8]) -> bool>(
        mut inner: T,
        mut state: HandshakeState,
        min_resend_interval: Duration,
        max_retires: u32,
        verifier: F,
    ) -> Result<Self, Error> {
        let mut last_sent = vec![];
        let mut f = Some(verifier);

        loop {
            if state.is_handshake_finished() {
                let transport = state.into_stateless_transport_mode()?;
                let rng = rand_chacha::ChaCha20Rng::from_entropy();
                return Ok(Self {
                    inner,
                    transport,
                    rng,
                    send_buf: vec![0; NONCE_LEN + MAX_MESSAGE_LEN],
                });
            }

            if state.is_my_turn() {
                last_sent.resize(MAX_MESSAGE_LEN, 0);
                let n = state.write_message(&[], &mut last_sent)?;
                last_sent.truncate(n);
                send(&mut inner, &last_sent).await?;
            } else {
                let backoff = Backoff::new(max_retires, min_resend_interval, None);
                let mut recv_buf = vec![0; MAX_MESSAGE_LEN];
                let mut ok = false;

                for duration in backoff.into_iter() {
                    let result = tokio::time::timeout(duration, async {
                        recv(&mut inner, &mut recv_buf).await
                    })
                    .await;
                    match result {
                        Ok(r) => {
                            let n = r?;
                            let mut payload_buf = vec![0; MAX_MESSAGE_LEN];
                            match state.read_message(&recv_buf[..n], &mut payload_buf) {
                                Ok(_) => {
                                    ok = true;
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("recv invalid packet while handshaking {}", e);
                                    continue;
                                }
                            }
                        }
                        Err(_) => {
                            // Timeout, resend packet
                            if !last_sent.is_empty() {
                                send(&mut inner, &last_sent).await?;
                            }
                        }
                    }
                }

                if !ok {
                    return Err(Error::HandshakeError("handshake timeout".to_string()));
                }

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
        let nonce = self.rng.next_u64();
        self.send_buf[..8].copy_from_slice(&nonce.to_le_bytes());
        let n = self
            .transport
            .write_message(nonce, buf, &mut self.send_buf[8..])?;
        poll_fn(|cx| self.inner.poll_send(cx, &self.send_buf[..8 + n])).await?;
        Ok(buf.len())
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut recv_buf = vec![0; 8 + MAX_MESSAGE_LEN];
        let mut read_buf = ReadBuf::new(&mut recv_buf);
        poll_fn(|cx| self.inner.poll_recv(cx, &mut read_buf)).await?;

        let mut cur = read_buf.filled();
        let nonce = cur.get_u64_le();
        let message = cur;

        let n = self.transport.read_message(nonce, message, buf)?;

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::{io::ReadBuf, net::UdpSocket};

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
            let mut a = NoiseSocket::handshake(s, initiator, Duration::from_secs(1), 3)
                .await
                .unwrap();
            a.send(b"hello world!").await.unwrap();
        });

        let mut b = NoiseSocket::handshake(c, responder, Duration::from_secs(1), 3)
            .await
            .unwrap();
        let mut buf = vec![0; 0x100];
        let n = b.recv(&mut buf).await.unwrap();
        let s = String::from_utf8_lossy(&buf[..n]);
        println!("{}", s);
    }
}
