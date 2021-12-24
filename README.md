# Snowstorm

A minimalistic encryption protocol for rust async streams / packets, based on [noise protocol](http://www.noiseprotocol.org/) and [snow](https://crates.io/crates/snow).

## Quickstart

Snowstorm allows you to secure any streams implemented `AsyncRead + AsyncWrite + Unpin`. For example, `TcpStream` in Tokio. Note that the underlying connections **need to be reliable**.

### Create a Key Pair

```rust
// Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
// Use `KK` to enable bidirectional identity verification
static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s"; 

// Generate a private / public key pair
let key_pair = snowstorm::Builder::new(PATTERN.parse()?).generate_keypair().unwrap()
```

#### Client 

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

#### Server

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

### Stream

[ `length` (2 bytes, little endian) ] [ `noise message` (`length` bytes) ]

### Packet

[ `nonce` (8 bytes) ] [ `noise message` ]

## Todo

- [x] UDP Support
- [ ] Documentation
- [x] Benchmarks
- [ ] Async-std support

