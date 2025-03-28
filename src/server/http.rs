use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
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

// API 密钥认证结构
struct ApiKey;

#[async_trait]
impl<S> axum::extract::FromRequestParts<S> for ApiKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        // 从请求头获取 API 密钥
        let api_key = parts
            .headers
            .get("X-API-Key")
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing API key").into_response())?
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid API key format").into_response())?;

        // 从扩展数据获取应用状态
        let app_state = parts
            .extensions
            .get::<AppState>()
            .expect("AppState missing in extensions");

        // 验证 API 密钥
        let valid_keys = app_state.api_keys.lock().unwrap();
        if valid_keys.contains(api_key) {
            Ok(ApiKey)
        } else {
            Err((StatusCode::UNAUTHORIZED, "Invalid API key").into_response())
        }
    }
}

#[tokio::main]
async fn main() {
    // 初始化共享状态（包含预置的 API 密钥）
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

// GET 处理函数（无需认证）
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

// POST 处理函数（需要认证）
async fn handle_post(
    _: ApiKey, // 触发认证检查
    State(state): State<AppState>,
    Json(payload): Json<PostPayload>,
) -> Result<Json<DnsRecord>, impl IntoResponse> {
    let mut records = state.dns_records.lock().unwrap();

    if !is_valid_domain(&payload.domain) {
        return Err((StatusCode::BAD_REQUEST, "Invalid domain format"));
    }

    if !is_valid_ip(&payload.ip) {
        return Err((StatusCode::BAD_REQUEST, "Invalid IP address format"));
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
