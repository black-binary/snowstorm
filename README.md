# Snowstorm

Minimalistic encryption protocol for rust async streams, based on [noise protocol](http://www.noiseprotocol.org/) and [snow](https://crates.io/crates/snow).

## Quick Start

Snowstorm allows you to secure any streams implemented `AsyncRead + AsyncWrite + Unpin`.

### Client 

```rust
static PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

let stream = TcpStream::connect("127.0.0.1:12345").await?;

let initiator = snowstorm::Builder::new(PATTERN.parse()?)
    .local_private_key(local_private_key)
    .remote_public_key(remote_public_key)
    .build_initiator()?;

let mut secured_stream = NoiseStream::handshake(stream, initiator).await?;

secured_stream.write_all(b"hello world").await?;
```

### Server

```rust
static PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

let listener = TcpListener::bind("127.0.0.1:12345").await?;
let (stream, _) = listener.accept().await?;

let responder = snowstorm::Builder::new(PATTERN.parse()?)
    .local_private_key(local_private_key)
    .remote_public_key(remote_public_key)
    .build_responder()?;

let mut secured_stream = NoiseStream::handshake(stream, responder).await?;

let mut buf = [0; 1024];
secured_stream.read(&mut buf).await?;

```

## Spec

[ `length` (2 bytes, little endian) ] [ `noise message` (`length` bytes) ]

## Todo

- [ ] UDP Support
- [ ] Documentation
- [ ] Benchmarks
- [ ] Async-std support

