use std::sync::Arc;

use anyhow::Result;
use tfreg::oauth::GithubAuthenticator;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let config = tfreg::app_config::load()?;

    let authenticator = Arc::new(GithubAuthenticator::new(&config)?);
    let app = tfreg::router(&config, authenticator).await?;

    let listener = tokio::net::TcpListener::bind(&config.addr).await.unwrap();
    info!("listening on {}", config.addr);

    axum::serve(listener, app).await?;
    Ok(())
}
