pub mod http;
pub mod udp;

use async_trait::async_trait;

#[async_trait]
pub trait Resolver {
    async fn launch(&mut self) -> std::io::Result<()>;
}
