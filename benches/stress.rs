use criterion::Criterion;
use criterion::Throughput;
use criterion::{criterion_group, criterion_main};
use snowstorm::Builder;
use snowstorm::NoiseStream;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

async fn bench_transfer(
    mut a: NoiseStream<TcpStream>,
    mut b: NoiseStream<TcpStream>,
    payload: &[u8],
) {
    let n = payload.len();
    tokio::spawn(async move {
        let mut buf = vec![0; n];
        b.read_exact(&mut buf).await.unwrap();
    });
    a.write_all(payload).await.unwrap();
}

async fn get_pair(p: &str) -> (NoiseStream<TcpStream>, NoiseStream<TcpStream>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();

    let a = TcpStream::connect(addr).await.unwrap();
    let b = l.accept().await.unwrap().0;

    let i = Builder::new(p.parse().unwrap()).build_initiator().unwrap();
    let r = Builder::new(p.parse().unwrap()).build_responder().unwrap();
    let h = tokio::spawn(async move { NoiseStream::handshake(a, r).await.unwrap() });
    let b = NoiseStream::handshake(b, i).await.unwrap();
    (h.await.unwrap(), b)
}

fn bench_throughput(c: &mut Criterion) {
    const PAYLOAD_LEN: usize = 256 * 1024 * 1024;
    const PAYLOAD: &[u8] = &[0; PAYLOAD_LEN];
    let PATTERNS: &[&str] = &[
        "Noise_NN_25519_ChaChaPoly_BLAKE2s",
        "Noise_NN_25519_ChaChaPoly_BLAKE2b",
        "Noise_NN_25519_AESGCM_BLAKE2s",
        "Noise_NN_25519_AESGCM_BLAKE2b",
    ];

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    for s in PATTERNS {
        group.bench_with_input(s.to_string(), s, |b, s| {
            b.to_async(&rt).iter(|| async move {
                let (p, q) = get_pair(s).await;
                bench_transfer(p, q, PAYLOAD).await;
            });
        });
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
