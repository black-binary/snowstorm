use std::{
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::ready;
use pin_project::pin_project;
use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

use crate::{Error, HANDSHAKE_FRAME_LEN, MAX_FRAME_LEN, TAG_LEN};

#[derive(Debug)]
enum ReadState {
    Idle,
    ReadLen(usize, [u8; 2]),
    ReadMessage(usize, Vec<u8>),
    ServePayload(BytesMut),
}

#[derive(Debug)]
enum WriteState {
    Idle,
    WriteMessage(BytesMut),
}

#[pin_project]
pub struct NoiseStream<T> {
    #[pin]
    inner: T,
    transport: TransportState,
    read_state: ReadState,
    write_state: WriteState,
    write_clean_waker: Option<Waker>,
}

impl<T> NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(mut inner: T, mut state: HandshakeState) -> Result<Self, Error> {
        loop {
            if state.is_handshake_finished() {
                let transport = state.into_transport_mode()?;
                return Ok(Self {
                    inner,
                    transport,
                    read_state: ReadState::Idle,
                    write_state: WriteState::Idle,
                    write_clean_waker: None,
                });
            }

            let mut message = [0; HANDSHAKE_FRAME_LEN];
            let mut read_buf = [0; HANDSHAKE_FRAME_LEN];
            if state.is_my_turn() {
                let len = state.write_message(&[], &mut message)?;
                inner.write_u16_le(len as u16).await?;
                inner.write_all(&message[..len]).await?;
            } else {
                let len = inner.read_u16_le().await? as usize;
                inner.read_exact(&mut message[..len]).await?;
                state.read_message(&message[..len], &mut read_buf)?;
            }
        }
    }
}

impl<T> AsyncWrite for NoiseStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        let mut inner = this.inner;
        let state = this.write_state;
        let transport = this.transport;

        loop {
            match state {
                WriteState::Idle => {
                    let mut cur = buf;
                    // TODO optimization
                    let mut buf = vec![0; MAX_FRAME_LEN];

                    let mut message = BytesMut::new();

                    while cur.has_remaining() {
                        let n = cur.remaining().min(MAX_FRAME_LEN - TAG_LEN);
                        let msg_len = transport
                            .write_message(&cur[..n], &mut buf)
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                        message.put_u16_le(msg_len as u16);
                        message.put_slice(&buf[..msg_len]);
                        cur.advance(n);
                    }
                    *state = WriteState::WriteMessage(message);
                }
                WriteState::WriteMessage(message) => {
                    let n = ready!(Pin::new(&mut inner).poll_write(cx, message))?;
                    message.advance(n);

                    if !message.has_remaining() {
                        *state = WriteState::Idle;
                        if let Some(waker) = this.write_clean_waker.take() {
                            waker.wake();
                        }
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        if let WriteState::Idle = this.write_state {
            return Poll::Ready(Ok(()));
        }

        *this.write_clean_waker = Some(cx.waker().clone());
        ready!(this.inner.poll_flush(cx))?;
        Poll::Pending
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<T> AsyncRead for NoiseStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        let mut inner = this.inner;
        let state = this.read_state;
        let transport = this.transport;

        loop {
            match state {
                ReadState::Idle => *state = ReadState::ReadLen(0, [0; 2]),
                ReadState::ReadLen(read_len, mut buf) => {
                    if *read_len == 2 {
                        let message_len = u16::from_le_bytes(buf) as usize;
                        *state = ReadState::ReadMessage(0, vec![0; message_len]);
                    } else {
                        let mut read_buf = ReadBuf::new(&mut buf);
                        read_buf.advance(*read_len);

                        ready!(Pin::new(&mut inner).poll_read(cx, &mut read_buf))?;
                        let n = read_buf.filled().len();
                        *state = ReadState::ReadLen(n, buf);
                    }
                }
                ReadState::ReadMessage(read_len, buf) => {
                    if *read_len == buf.len() {
                        let mut plaintext = BytesMut::new();
                        plaintext.resize(buf.len() - TAG_LEN, 0);

                        let n = transport
                            .read_message(buf, &mut plaintext)
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

                        plaintext.truncate(n);

                        *state = ReadState::ServePayload(plaintext);
                    } else {
                        let mut read_buf = ReadBuf::new(buf);
                        read_buf.advance(*read_len);

                        ready!(Pin::new(&mut inner).poll_read(cx, &mut read_buf))?;
                        let n = read_buf.filled().len();
                        *read_len += n;
                    }
                }
                ReadState::ServePayload(buf) => {
                    let read_buf_remaining = read_buf.remaining();
                    let buf_remaining = buf.remaining();

                    if read_buf_remaining >= buf_remaining {
                        read_buf.put_slice(buf);
                        *state = ReadState::Idle;
                    } else {
                        read_buf.put_slice(&buf[..read_buf_remaining]);
                        buf.advance(read_buf_remaining);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use snow::Builder;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::NoiseStream;

    #[tokio::test]
    async fn tcp() -> anyhow::Result<()> {
        static PATTERN: &str = "Noise_NX_25519_ChaChaPoly_BLAKE2s";
        let client_key = Builder::new(PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_key = Builder::new(PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:23333").await.unwrap();
        tokio::spawn(async move {
            let initiator = Builder::new(PATTERN.parse().unwrap())
                .local_private_key(&client_key.private)
                .remote_public_key(&server_key.public)
                .build_initiator()
                .unwrap();
            let stream = TcpStream::connect("127.0.0.1:23333").await.unwrap();
            let mut stream = NoiseStream::handshake(stream, initiator).await.unwrap();
            stream.write_all(b"hello world").await.unwrap();
        });

        let responder = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&server_key.private)
            .remote_public_key(&client_key.public)
            .build_responder()
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = NoiseStream::handshake(stream, responder).await.unwrap();
        let mut buf = vec![0; 0x1000];
        let n = stream.read(&mut buf).await.unwrap();

        let s = String::from_utf8(buf[..n].to_vec()).unwrap();
        println!("{}", s);

        Ok(())
    }

    #[test]
    fn snow() -> Result<(), Box<dyn std::error::Error>> {
        static PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
        let mut initiator = snow::Builder::new(PATTERN.parse()?).build_initiator()?;
        let mut responder = snow::Builder::new(PATTERN.parse()?).build_responder()?;

        let (mut read_buf, mut first_msg, mut second_msg) = ([0u8; 1024], [0u8; 1024], [0u8; 1024]);

        // -> e
        let len = initiator.write_message(&[], &mut first_msg)?;

        // responder processes the first message...
        responder.read_message(&first_msg[..len], &mut read_buf)?;

        println!("first {:?}", &first_msg[..len]);

        // <- e, ee
        let len = responder.write_message(&[], &mut second_msg)?;

        println!("second {:?}", &second_msg[..len]);

        // initiator processes the response...
        initiator.read_message(&second_msg[..len], &mut read_buf)?;

        // NN handshake complete, transition into transport mode.
        let _initiator = initiator.into_transport_mode().unwrap();
        let _responder = responder.into_transport_mode().unwrap();
        Ok(())
    }
}
