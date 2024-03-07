use std::sync::Arc;

use anyhow::Result;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use oauth::Authenticate;
use serde_json::json;

pub mod app_config;
mod app_tracing;
mod auth;
mod download;
mod github;
mod middleware;
pub mod oauth;
mod provider_registry;
mod signature;

pub const PROVIDER_ROUTE_PREFIX: &str = "/providers/v1/";
pub const AUTH_ROUTE_PREFIX: &str = "/oauth";
pub const DOWNLOAD_ROUTE_PREFIX: &str = "/downloads/";
pub const SERVICE_DISCOVERY_PATH: &str = "/.well-known/terraform.json";

pub async fn router<T: Authenticate>(
    config: &app_config::AppConfig,
    authenticator: Arc<T>,
) -> Result<Router> {
    app_tracing::init(config)?;

    let registry_router = provider_registry::router(config, authenticator.clone()).await?;
    let auth_router = auth::router(authenticator.clone())?;
    let download_router = download::router(config, DOWNLOAD_ROUTE_PREFIX, authenticator.clone());

    Ok(Router::new()
        .route(SERVICE_DISCOVERY_PATH, get(service_discovery_handler))
        .nest(PROVIDER_ROUTE_PREFIX, registry_router)
        .nest(AUTH_ROUTE_PREFIX, auth_router)
        .merge(download_router)
        .layer(app_tracing::opentelemetry_tracing_layer()))
}

// https://www.terraform.io/internals/provider-registry-protocol#service-discovery
pub async fn service_discovery_handler() -> impl IntoResponse {
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
