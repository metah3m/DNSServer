// use std::{net::SocketAddr, time::Duration};

// use server::udp::UdpResolver;
// use server::Resolver;
// use tracing::info;

// mod server;

// #[tokio::main]
// async fn main() {
//     tracing_subscriber::fmt()
//         .with_max_level(tracing::level_filters::LevelFilter::TRACE)
//         .with_writer(
//             std::fs::OpenOptions::new()
//                 .create(true)
//                 .write(true)
//                 .truncate(true)
//                 .open("./dns.log")
//                 .unwrap(),
//         )
//         .with_ansi(false)
//         .init();

//     let args = std::env::args().collect::<Vec<_>>();
//     if args.len() != 2 {
//         println!("Usage: {} <port>", args[0]);
//         return;
//     }

//     let port = args[1].parse().unwrap();
//     let addr = SocketAddr::from(([0, 0, 0, 0], port));
//     let mut server = UdpResolver::new(addr, Duration::from_secs(30)).await;

//     info!("DNS Server running on 0.0.0.0:{}", addr.port());
//     let _ = server.launch().await;
// }
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::{
    collections::{HashMap, HashSet},
    io,
};
use tower_http::cors::{Any, CorsLayer};

// DNS 记录结构
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRecord {
    domain: String,
    ip: String,
}

// 共享应用状态
#[derive(Clone)]
struct AppState {
    dns_records: Arc<Mutex<HashMap<String, String>>>,
    api_keys: Arc<Mutex<HashSet<String>>>,
}

// GET 请求查询参数
#[derive(Debug, Deserialize)]
struct GetQuery {
    domain: String,
}

// POST 请求 JSON 结构
#[derive(Debug, Deserialize)]
struct PostPayload {
    domain: String,
    ip: String,
}

// 认证错误类型
#[derive(Debug)]
struct AuthError;

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "Invalid API key").into_response()
    }
}

// 认证中间件
async fn auth_middleware(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<(), AuthError> {
    let api_key = headers
        .get("X-API-Key")
        .ok_or(AuthError)?
        .to_str()
        .map_err(|_| AuthError)?;

    let valid_keys = state.api_keys.lock().unwrap();
    valid_keys.contains(api_key).then_some(()).ok_or(AuthError)
}

#[tokio::main]
async fn main() {
    // 初始化共享状态
    let state = AppState {
        dns_records: Arc::new(Mutex::new(HashMap::new())),
        api_keys: Arc::new(Mutex::new({
            let mut keys = HashSet::new();
            keys.insert("secret-api-key".to_string());
            keys
        })),
    };

    // 配置 CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([http::Method::GET, http::Method::POST]);

    // 创建路由
    let app = Router::new()
        .route("/get", get(handle_get))
        .route("/report", post(handle_post))
        .with_state(state)
        .layer(cors);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

// GET 处理函数
async fn handle_get(
    Query(query): Query<GetQuery>,
    State(state): State<AppState>,
) -> Result<Json<DnsRecord>, impl IntoResponse> {
    let records = state.dns_records.lock().unwrap();
    match records.get(&query.domain) {
        Some(ip) => Ok(Json(DnsRecord {
            domain: query.domain,
            ip: ip.clone(),
        })),
        None => Err((StatusCode::NOT_FOUND, "DNS record not found")),
    }
}

// POST 处理函数（集成认证）
async fn handle_post(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<PostPayload>,
) -> Result<Json<DnsRecord>, Response> {
    // 执行认证检查
    if auth_middleware(headers, State(state.clone()))
        .await
        .is_err()
    {
        return Err(AuthError.into_response());
    };

    let mut records = state.dns_records.lock().unwrap();

    if !is_valid_domain(&payload.domain) {
        return Err((StatusCode::BAD_REQUEST, "Invalid domain format").into_response());
    }

    if !is_valid_ip(&payload.ip) {
        return Err((StatusCode::BAD_REQUEST, "Invalid IP address format").into_response());
    }

    records.insert(payload.domain.clone(), payload.ip.clone());
    Ok(Json(DnsRecord {
        domain: payload.domain,
        ip: payload.ip,
    }))
}

// 简单的域名验证
fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.len() <= 253 && domain.split('.').count() >= 2
}

// 简单的 IP 地址验证
fn is_valid_ip(ip: &str) -> bool {
    ip.split('.').count() == 4 && ip.split('.').all(|octet| octet.parse::<u8>().is_ok())
}

// 新增函数：加载 TLS 配置
async fn load_tls_config() -> io::Result<rustls::ServerConfig> {
    // 加载证书链
    let cert = include_bytes!("../server.cert");
    let key = include_bytes!("../server.key");

    let key = PrivateKey(keys.remove(0));

    // 构建 TLS 配置
    Ok(rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?)
}
// curl -X POST http://localhost:3000/report \
//   -H "X-API-Key: wrong-key" \
//   -H "Content-Type: application/json" \
//   -d '{"domain": "example.com", "ip": "192.168.1.1"}'

// curl -X POST http://localhost:3000/get?domain=example.com
