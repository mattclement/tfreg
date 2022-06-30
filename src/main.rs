use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde_json::json;
use tracing::info;

mod app_config;
mod app_tracing;
mod auth;
mod download;
mod github;
mod middleware;
mod oauth;
mod provider_registry;
mod signature;

const PROVIDER_ROUTE_PREFIX: &str = "/providers/v1/";
const AUTH_ROUTE_PREFIX: &str = "/oauth";
const DOWNLOAD_ROUTE_PREFIX: &str = "/downloads/";

#[tokio::main]
async fn main() -> Result<()> {
    let config = app_config::load()?;
    let authenticator = Arc::new(oauth::Authenticator::new(&config)?);

    app_tracing::init(&config)?;

    let app = Router::new()
        .route(
            "/.well-known/terraform.json",
            get(service_discovery_handler),
        )
        .nest(
            PROVIDER_ROUTE_PREFIX,
            provider_registry::router(&config, authenticator.clone()).await?,
        )
        .nest(AUTH_ROUTE_PREFIX, auth::router(authenticator.clone())?)
        .merge(download::router(
            &config,
            DOWNLOAD_ROUTE_PREFIX,
            authenticator.clone(),
        ))
        .layer(app_tracing::opentelemetry_tracing_layer());

    // run it
    info!("listening on {}", config.addr);
    axum::Server::bind(&config.addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

// https://www.terraform.io/internals/provider-registry-protocol#service-discovery
async fn service_discovery_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "providers.v1": PROVIDER_ROUTE_PREFIX,
            "login.v1": {
                "client": "terraform-cli",
                "grant_types": ["authz_code"],
                "authz": format!("{}/{}", AUTH_ROUTE_PREFIX, "authz"),
                "token": format!("{}/{}", AUTH_ROUTE_PREFIX, "token"),
                "ports": [10009, 10010],
            }
        })),
    )
}
