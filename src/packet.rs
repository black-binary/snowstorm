use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use bytes::Buf;
use futures_util::future::poll_fn;
use rand::Rng;
use snow::HandshakeState;
use snow::StatelessTransportState;
use tokio::io::ReadBuf;

use crate::Error;
use crate::HANDSHAKE_FRAME_LEN;
use crate::MAX_FRAME_LEN;

pub trait PacketPoller {
    type MetaInfo: Clone + PartialEq;

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        meta: Self::MetaInfo,
    ) -> Poll<std::io::Result<usize>>;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<Self::MetaInfo>>;
}

async fn recv_from<P: PacketPoller<MetaInfo = M>, M: Clone>(
    p: &P,
    buf: &mut [u8],
) -> std::io::Result<(usize, M)> {
    let mut read_buf = ReadBuf::new(buf);
    let meta = poll_fn(|cx| p.poll_recv_from(cx, &mut read_buf)).await?;
    Ok((read_buf.filled().len(), meta))
}

async fn send_to<P: PacketPoller<MetaInfo = M>, M: Clone>(
    p: &P,
    buf: &[u8],
    m: M,
) -> std::io::Result<usize> {
    let n = poll_fn(|cx| p.poll_send_to(cx, buf, m.clone())).await?;
    Ok(n)
}

pub struct NoisePacket<T> {
    inner: T,
    transport: StatelessTransportState,
}

impl<T: PacketPoller> NoisePacket<T> {
    pub async fn handshake(
        inner: T,
        mut state: HandshakeState,
        meta: T::MetaInfo,
        timeout: Duration,
        mut max_retry: usize,
    ) -> Result<Self, Error> {
        let mut last_sent = vec![];
        loop {
            if state.is_handshake_finished() {
                let transport = state.into_stateless_transport_mode()?;
                return Ok(Self { inner, transport });
            }

            if state.is_my_turn() {
                last_sent.resize(HANDSHAKE_FRAME_LEN, 0);
                let n = state.write_message(&[], &mut last_sent)?;
                last_sent.truncate(n);
                send_to(&inner, &last_sent, meta.clone()).await?;
            } else {
                let mut recv_buf = vec![0; HANDSHAKE_FRAME_LEN];

                let result =
                    tokio::time::timeout(timeout, async { recv_from(&inner, &mut recv_buf).await })
                        .await;

                if max_retry == 0 {
                    return Err(Error::HandshakeError("handshake timeout".to_string()));
                }

                match result {
                    Ok(r) => {
                        let (n, m) = r?;
                        if m != meta {
                            continue;
                        }
                        let mut payload_buf = vec![0; HANDSHAKE_FRAME_LEN];
                        state.read_message(&recv_buf[..n], &mut payload_buf)?;
                    }
                    Err(_) => {
                        max_retry -= 1;
                        if !last_sent.is_empty() {
                            send_to(&inner, &last_sent, meta.clone()).await?;
                        }
                    }
                }
            }
        }
    }

    pub async fn send_to(&self, buf: &[u8], meta: T::MetaInfo) -> Result<usize, Error> {
        let mut message = vec![0; 8 + MAX_FRAME_LEN];
        let nonce: u64 = rand::thread_rng().gen();
        message[..8].copy_from_slice(&nonce.to_le_bytes());
        let n = self
            .transport
            .write_message(nonce, buf, &mut message[8..])?;
        poll_fn(|cx| self.inner.poll_send_to(cx, &message[..8 + n], meta.clone())).await?;
        Ok(buf.len())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, T::MetaInfo), Error> {
        let mut recv_buf = vec![0; 8 + MAX_FRAME_LEN];
        let mut read_buf = ReadBuf::new(&mut recv_buf);
        let meta = poll_fn(|cx| self.inner.poll_recv_from(cx, &mut read_buf)).await?;

        let mut cur = read_buf.filled();
        let nonce = cur.get_u64_le();
        let message = cur;

        let n = self.transport.read_message(nonce, message, buf)?;

        Ok((n, meta))
    }
}

//impl<T: Clone, P: PacketPoller<MetaInfo = T>> P {}

//impl PacketPoller for UdpSocket {
//    type MetaInfo = SocketAddr;
//
//    fn poll_send_to(
//        &self,
//        cx: &mut Context<'_>,
//        buf: &[u8],
//        meta: Self::MetaInfo,
//    ) -> Poll<std::io::Result<usize>> {
//        self.poll_send_to(cx, buf, meta)
//    }
//
//    fn poll_recv_from(
//        &self,
//        cx: &mut Context<'_>,
//        buf: &mut ReadBuf<'_>,
//    ) -> Poll<std::io::Result<Self::MetaInfo>> {
//        self.poll_recv_from(cx, buf)
//    }
//}
