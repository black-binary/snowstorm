# Snowstorm

A minimalistic encryption protocol for rust async streams, based on [noise protocol](http://www.noiseprotocol.org/) and [snow](https://crates.io/crates/snow).

## Quick Start

Snowstorm allows you to secure any streams implemented `AsyncRead + AsyncWrite + Unpin`.

## Generate Key Pair

```rust
// Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
static PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s"; 

// Generate the private and the public key
let key_pair = snowstorm::Builder::new(PATTERN.parse()?).generate_keypair().unwrap()
```

### Client 

```rust

// Connect to the peer
let stream = TcpStream::connect("127.0.0.1:12345").await?;

// The client should build an initiator to launch the handshake process
let initiator = snowstorm::Builder::new(PATTERN.parse()?)
    .local_private_key(local_private_key)
    .remote_public_key(remote_public_key)
    .build_initiator()?;

// Start handshaking
let mut secured_stream = NoiseStream::handshake(stream, initiator).await?;

// A secured stream `NoiseStream<T>` will be return once the handshake is done
secured_stream.write_all(b"hello world").await?;
```

### Server

```rust

// Accept a `TcpStream` from the listener
let listener = TcpListener::bind("127.0.0.1:12345").await?;
let (stream, _) = listener.accept().await?;

// The server needs a responder to handle handshake reqeusts from clients
let responder = snowstorm::Builder::new(PATTERN.parse()?)
    .local_private_key(local_private_key)
    .remote_public_key(remote_public_key)
    .build_responder()?;

// Start handshaking
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

