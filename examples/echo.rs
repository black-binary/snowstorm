use std::{sync::Arc, time::Duration};

use anyhow::Result;
use snowstorm::{Builder, NoiseStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

static PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

async fn server(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12345").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let responder = snowstorm::Builder::new(PATTERN.parse()?)
            .local_private_key(local_private_key)
            .remote_public_key(remote_public_key)
            .build_responder()?;
        let _: JoinHandle<Result<()>> = tokio::spawn(async move {
            let mut stream = NoiseStream::handshake(stream, responder).await?;
            loop {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf).await?;
                stream.write_all(&buf).await?
            }
        });
    }
}

async fn client(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<()> {
    let stream = TcpStream::connect("127.0.0.1:12345").await?;
    let initiator = snowstorm::Builder::new(PATTERN.parse()?)
        .local_private_key(local_private_key)
        .remote_public_key(remote_public_key)
        .build_initiator()?;

    let mut stream = NoiseStream::handshake(stream, initiator).await?;

    stream.write_all(b"hello world").await?;
    let mut buf = [0; 1024];
    let n = stream.read(&mut buf).await?;

    let s = String::from_utf8_lossy(&buf[..n]);
    println!("{}", s);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let server_key = Arc::new(Builder::new(PATTERN.parse()?).generate_keypair().unwrap());
    let client_key = Arc::new(Builder::new(PATTERN.parse()?).generate_keypair().unwrap());

    {
        let client_key = client_key.clone();
        let server_key = server_key.clone();
        tokio::spawn(async move {
            server(&server_key.private, &client_key.public)
                .await
                .unwrap()
        });
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    let j = tokio::spawn(async move {
        client(&server_key.private, &client_key.public)
            .await
            .unwrap()
    });

    j.await.unwrap();

    Ok(())
}
