use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::info;

#[derive(Debug)]
struct DnsRecord {
    address: String,
    timestamp: Instant,
}

struct DnsServer {
    records: HashMap<String, DnsRecord>,
    ttl: Duration,
}

impl DnsServer {
    fn new(ttl: Duration) -> Self {
        DnsServer {
            records: HashMap::new(),
            ttl,
        }
    }

    fn update_record(&mut self, domain: String, address: String) {
        let now = Instant::now();
        self.records.insert(
            domain,
            DnsRecord {
                address,
                timestamp: now,
            },
        );
    }

    fn query_record(&self, domain: &str) -> Option<(String, u64)> {
        if let Some(record) = self.records.get(domain) {
            if record.timestamp.elapsed() < self.ttl {
                let elapsed = record.timestamp.elapsed().as_secs();
                return Some((record.address.clone(), elapsed));
            }
        }
        None
    }

    fn cleanup_expired_records(&mut self) {
        let now = Instant::now();
        self.records
            .retain(|_, record| now.duration_since(record.timestamp) < self.ttl);
    }
}

async fn run_dns_server(socket: UdpSocket, mut server: DnsServer) {
    let mut buffer = [0; 512];
    let mut cleanup_interval = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                server.cleanup_expired_records();
            }
            result = socket.recv_from(&mut buffer) => {
                let (size, address) = result.expect("Failed to receive data");
                info!("Received request from {:?}", address);
                let request = String::from_utf8_lossy(&buffer[..size]).to_string();
                let response = handle_request(&request, &mut server);
                socket.send_to(response.as_bytes(), &address).await.expect("Failed to send data");
            }
        }
    }
}

fn handle_request(request: &str, server: &mut DnsServer) -> String {
    let parts: Vec<&str> = request.split_whitespace().collect();
    info!("Received request: {}", request);
    match parts.as_slice() {
        ["REPORT", domain, address] => {
            server.update_record(domain.to_string(), address.to_string());
            "OK".to_string()
        }
        ["QUERY", domain] => {
            if let Some((address, elapsed)) = server.query_record(domain) {
                format!("{} {}", address, elapsed)
            } else {
                "Not Found".to_string()
            }
        }
        _ => "Invalid Request".to_string(),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
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
    let socket = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
    let server = DnsServer::new(Duration::from_secs(30));

    info!("DNS Server running on 0.0.0.0:{}", port);
    run_dns_server(socket, server).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_and_query_record() {
        let mut server = DnsServer::new(Duration::from_secs(30));

        // 更新记录
        server.update_record("example.com".to_string(), "192.168.1.1".to_string());

        // 查询记录
        let result = server.query_record("example.com");
        assert!(result.is_some());
        let (address, elapsed) = result.unwrap();
        assert_eq!(address, "192.168.1.1");
        assert!(elapsed < 1); // 刚更新，时间差应该小于1秒

        // 查询不存在的记录
        let result = server.query_record("unknown.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_record_expiration() {
        let mut server = DnsServer::new(Duration::from_secs(1));

        // 更新记录
        server.update_record("example.com".to_string(), "192.168.1.1".to_string());

        // 查询记录，应该存在
        let result = server.query_record("example.com");
        assert!(result.is_some());

        // 模拟时间流逝，超过TTL
        std::thread::sleep(Duration::from_secs(2));

        // 查询记录，应该不存在
        let result = server.query_record("example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_refresh_record() {
        let mut server = DnsServer::new(Duration::from_secs(2));

        // 更新记录
        server.update_record("example.com".to_string(), "192.168.1.1".to_string());

        // 模拟时间流逝，接近TTL
        std::thread::sleep(Duration::from_secs(1));

        // 刷新记录
        server.update_record("example.com".to_string(), "192.168.1.1".to_string());

        // 再次模拟时间流逝，超过原来的TTL
        std::thread::sleep(Duration::from_secs(1));

        // 查询记录，应该仍然存在
        let result = server.query_record("example.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_cleanup_expired_records() {
        let mut server = DnsServer::new(Duration::from_secs(1));

        // 更新记录
        server.update_record("example.com".to_string(), "192.168.1.1".to_string());
        server.update_record("another.com".to_string(), "192.168.1.2".to_string());

        // 模拟时间流逝，超过TTL
        std::thread::sleep(Duration::from_secs(2));

        // 清理过期记录
        server.cleanup_expired_records();

        // 查询记录，应该都不存在
        let result1 = server.query_record("example.com");
        assert!(result1.is_none());

        let result2 = server.query_record("another.com");
        assert!(result2.is_none());
    }
}
