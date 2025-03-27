use std::{net::SocketAddr, time::Duration};

use server::udp::UdpResolver;
use server::Resolver;
use tracing::info;

mod server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .with_writer(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("./dns.log")
                .unwrap(),
        )
        .with_ansi(false)
        .init();

    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("Usage: {} <port>", args[0]);
        return;
    }

    let port = args[1].parse().unwrap();
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let mut server = UdpResolver::new(addr, Duration::from_secs(30)).await;

    info!("DNS Server running on 0.0.0.0:{}", addr.port());
    let _ = server.launch().await;
}
