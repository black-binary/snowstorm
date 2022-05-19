use std::{
    fmt::Debug,
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use futures_util::ready;
use pin_project::pin_project;
use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub use snow;
pub use snow::params::NoiseParams;
pub use snow::Builder;
pub use snow::Keypair;

use crate::{SnowstormError, MAX_MESSAGE_LEN, TAG_LEN};

const LENGTH_FIELD_LEN: usize = std::mem::size_of::<u16>();

#[derive(Debug)]
enum ReadState {
    ShuttingDown,
    Idle,
    ReadingLen(usize, [u8; 2]),
    ReadingMessage(usize),
    ServingPayload(usize),
}

#[derive(Debug)]
enum WriteState {
    ShuttingDown,
    Idle,
    WritingMessage(usize, usize),
}

#[pin_project]
pub struct NoiseStream<T> {
    #[pin]
    inner: T,

    transport: TransportState,
    read_state: ReadState,
    write_state: WriteState,
    write_clean_waker: Option<Waker>,

    read_message_buffer: Vec<u8>,
    read_payload_buffer: Vec<u8>,

    write_message_buffer: Vec<u8>,
}

impl<T: Debug> Debug for NoiseStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseStream")
            .field("inner", &self.inner)
            .field("read_state", &self.read_state)
            .field("write_state", &self.write_state)
            .field("write_clean_waker", &self.write_clean_waker)
            .finish()
    }
}

impl<T> NoiseStream<T> {
    pub fn get_inner(&self) -> &T {
        &self.inner
    }

    pub fn get_inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_state(&self) -> &TransportState {
        &self.transport
    }

    pub fn get_state_mut(&mut self) -> &mut TransportState {
        &mut self.transport
    }
}

impl<T> NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake_with_verifier<F: FnOnce(&[u8]) -> bool>(
        mut inner: T,
        mut state: HandshakeState,
        verifier: F,
    ) -> Result<Self, SnowstormError> {
        let mut f = Some(verifier);
        loop {
            if state.is_handshake_finished() {
                let transport = state.into_transport_mode()?;
                return Ok(Self {
                    inner,
                    transport,
                    read_state: ReadState::Idle,
                    write_state: WriteState::Idle,
                    write_clean_waker: None,
                    read_message_buffer: vec![0; MAX_MESSAGE_LEN],
                    read_payload_buffer: vec![0; MAX_MESSAGE_LEN],
                    write_message_buffer: vec![0; LENGTH_FIELD_LEN + MAX_MESSAGE_LEN],
                });
            }

            let mut message = vec![0; MAX_MESSAGE_LEN];
            let mut payload = vec![0; MAX_MESSAGE_LEN];

            if state.is_my_turn() {
                let len = state.write_message(&[], &mut message)?;
                inner.write_u16_le(len as u16).await?;
                inner.write_all(&message[..len]).await?;
                inner.flush().await?;
            } else {
                let len = inner.read_u16_le().await? as usize;
                inner.read_exact(&mut message[..len]).await?;
                state.read_message(&message[..len], &mut payload)?;
                if let Some(pubkey) = state.get_remote_static() {
                    if let Some(verifier) = f.take() {
                        if !verifier(pubkey) {
                            return Err(SnowstormError::HandshakeError(
                                "invalid public key".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub async fn handshake(inner: T, state: HandshakeState) -> Result<Self, SnowstormError> {
        Self::handshake_with_verifier(inner, state, |_| true).await
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
        let write_message_buffer = this.write_message_buffer;

        loop {
            match state {
                WriteState::ShuttingDown => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
                WriteState::Idle => {
                    let payload_len = buf.len().min(MAX_MESSAGE_LEN - TAG_LEN);
                    let buf = &buf[..payload_len];

                    // Safety: This is safe because this buffer is initialized with length LENGTH_FIELD_LEN + MAX_MESSAGE_LEN
                    unsafe {
                        write_message_buffer.set_len(LENGTH_FIELD_LEN + MAX_MESSAGE_LEN);
                    }

                    let message_len = transport
                        .write_message(buf, &mut write_message_buffer[LENGTH_FIELD_LEN..])
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                    write_message_buffer[..LENGTH_FIELD_LEN]
                        .copy_from_slice(&(message_len as u16).to_le_bytes());
                    write_message_buffer.truncate(LENGTH_FIELD_LEN + message_len);
                    *state = WriteState::WritingMessage(0, payload_len);
                }
                WriteState::WritingMessage(start, payload_len) => {
                    let n = ready!(
                        Pin::new(&mut inner).poll_write(cx, &write_message_buffer[*start..])
                    )?;
                    *start += n;

                    if *start == write_message_buffer.len() {
                        let n = *payload_len;
                        *state = WriteState::Idle;
                        if let Some(waker) = this.write_clean_waker.take() {
                            waker.wake();
                        }
                        return Poll::Ready(Ok(n));
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        match this.write_state {
            WriteState::ShuttingDown | WriteState::Idle => {
                return Poll::Ready(Ok(()));
            }
            _ => {}
        }

        *this.write_clean_waker = Some(cx.waker().clone());
        ready!(this.inner.poll_flush(cx))?;
        Poll::Pending
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        if let Some(waker) = this.write_clean_waker.take() {
            waker.wake();
        }
        *this.write_state = WriteState::ShuttingDown;
        this.inner.poll_shutdown(cx)
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

        let read_message_buffer = this.read_message_buffer;
        let read_payload_buffer = this.read_payload_buffer;

        loop {
            match state {
                ReadState::ShuttingDown => {
                    return Poll::Ready(Ok(()));
                }
                ReadState::Idle => *state = ReadState::ReadingLen(0, [0; LENGTH_FIELD_LEN]),
                ReadState::ReadingLen(read_len, mut buf) => {
                    if *read_len == LENGTH_FIELD_LEN {
                        let message_len = u16::from_le_bytes(buf);

                        // Safety: This is safe because message_len <= MAX_MESSAGE_LEN
                        unsafe {
                            read_message_buffer.set_len(message_len as usize);
                        }
                        *state = ReadState::ReadingMessage(0);
                    } else {
                        let mut read_buf = ReadBuf::new(&mut buf);
                        read_buf.advance(*read_len);

                        ready!(Pin::new(&mut inner).poll_read(cx, &mut read_buf))?;
                        let n = read_buf.filled().len();
                        if n == 0 {
                            // EOF
                            *state = ReadState::ShuttingDown;
                        } else {
                            *state = ReadState::ReadingLen(n, buf);
                        }
                    }
                }
                ReadState::ReadingMessage(start) => {
                    if *start == read_message_buffer.len() {
                        // Safety: This is safe because this buffer is initialized with MAX_MESSAGE_LEN
                        unsafe {
                            read_payload_buffer.set_len(MAX_MESSAGE_LEN);
                        }

                        let n = transport
                            .read_message(read_message_buffer, read_payload_buffer)
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                        read_payload_buffer.truncate(n);
                        *state = ReadState::ServingPayload(0);
                    } else {
                        let mut read_buf = ReadBuf::new(&mut read_message_buffer[*start..]);

                        ready!(Pin::new(&mut inner).poll_read(cx, &mut read_buf))?;
                        let n = read_buf.filled().len();
                        if n == 0 {
                            // EOF
                            *state = ReadState::ShuttingDown;
                        } else {
                            *start += n;
                        }
                    }
                }
                ReadState::ServingPayload(start) => {
                    let read_buf_remaining = read_buf.remaining();
                    let buf_remaining = read_payload_buffer.len() - *start;

                    if buf_remaining <= read_buf_remaining {
                        read_buf.put_slice(&read_payload_buffer[*start..]);
                        *state = ReadState::Idle;
                    } else {
                        read_buf
                            .put_slice(&read_payload_buffer[*start..*start + read_buf_remaining]);
                        *start += read_buf_remaining;
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
        static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
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
            let payload = (0..0x20000).map(|a| a as u8).collect::<Vec<_>>();
            stream.write_all(&payload).await.unwrap();
        });

        let responder = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&server_key.private)
            .remote_public_key(&client_key.public)
            .build_responder()
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = NoiseStream::handshake(stream, responder).await.unwrap();
        println!("{:?}", stream);
        let mut payload = vec![0; 0x20000];
        stream.read_exact(&mut payload).await.unwrap();

        payload.iter().enumerate().for_each(|(i, v)| {
            assert_eq!(i as u8, *v);
        });

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
