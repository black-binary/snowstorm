use snowstorm::NoiseStream;
use tokio::net::{TcpListener, TcpStream};

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
