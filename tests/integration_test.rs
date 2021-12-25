use anyhow::Result;
use snowstorm::NoiseStream;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

#[tokio::test]
async fn wrong_remote_pubkey() {
    // Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
    static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

    // Generate a private / public key pair
    let key_pair1 = snowstorm::Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    let key_pair1_pub = key_pair1.public.clone();

    // Generate another private / public key pair
    let key_pair2 = snowstorm::Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    let server = tokio::spawn(async move {
        // Accept a `TcpStream` from the listener
        let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        // The server needs a responder to handle handshake reqeusts from clients
        let responder = snowstorm::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&key_pair1.private)
            .remote_public_key(&key_pair1.public) // Wrong remote public key
            .build_responder()
            .unwrap();

        // Start handshaking
        // Should fail beacuse of a wrong remote public key
        assert!(NoiseStream::handshake(stream, responder).await.is_err());
    });

    let client = tokio::spawn(async move {
        // Connect to the peer
        let stream = TcpStream::connect("127.0.0.1:12345").await.unwrap();

        // The client should build an initiator to launch the handshake process
        let initiator = snowstorm::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&key_pair2.private)
            .remote_public_key(&key_pair1_pub) // This is RIGHT
            .build_initiator()
            .unwrap();

        // Start handshaking
        assert!(NoiseStream::handshake(stream, initiator).await.is_err());
    });

    let (server_res, client_res) = tokio::join!(server, client);
    assert!(server_res.is_ok());
    assert!(client_res.is_ok());
}

async fn relay_to_tcp<A: ToSocketAddrs, S: AsyncRead + AsyncWrite + Unpin>(
    addr: A,
    mut input: S,
) -> Result<()> {
    let mut conn = TcpStream::connect(addr).await?;
    copy_bidirectional(&mut conn, &mut input).await?;
    Ok(())
}

async fn echo_server<A: ToSocketAddrs>(bind_addr: A) -> Result<()> {
    let l = TcpListener::bind(bind_addr).await?;
    while let Ok((mut conn, _)) = l.accept().await {
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = conn.read(&mut buf).await {
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}

#[tokio::test]
async fn test_relay() {
    const ECHO_SERVER_BIND_ADDR: &str = "127.0.0.1:8080";
    const NOISE_SERVER_BIND_ADDR: &str = "127.0.0.1:12346";

    tokio::spawn(echo_server(ECHO_SERVER_BIND_ADDR));

    static PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

    // Generate a private / public key pair
    let key_pair1 = snowstorm::Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    // Generate another private / public key pair
    let key_pair2 = snowstorm::Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();

    let server = tokio::spawn(async move {
        // Accept a `TcpStream` from the listener
        let listener = TcpListener::bind(NOISE_SERVER_BIND_ADDR).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        // The server needs a responder to handle handshake reqeusts from clients
        let responder = snowstorm::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&key_pair1.private)
            .build_responder()
            .unwrap();

        // Start handshaking
        // Should fail beacuse of a wrong remote public key
        let conn = NoiseStream::handshake(stream, responder).await.unwrap();
        relay_to_tcp(ECHO_SERVER_BIND_ADDR, conn).await.unwrap();
    });

    let client = tokio::spawn(async move {
        // Connect to the peer
        let stream = TcpStream::connect(NOISE_SERVER_BIND_ADDR).await.unwrap();

        // The client should build an initiator to launch the handshake process
        let initiator = snowstorm::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&key_pair2.private)
            .build_initiator()
            .unwrap();

        // Start handshaking
        let mut conn = NoiseStream::handshake(stream, initiator).await.unwrap();
        conn.write_all("hello".as_bytes()).await.unwrap();
    });

    let (server_res, client_res) = tokio::join!(server, client);
    assert!(server_res.is_ok());
    assert!(client_res.is_ok());
}
