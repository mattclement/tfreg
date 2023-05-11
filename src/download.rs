use std::sync::Arc;

use axum::{middleware, Extension, Router};
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;

use crate::oauth::Authenticator;

pub fn router(
    config: &crate::app_config::AppConfig,
    path: &str,
    auth: Arc<Authenticator>,
) -> Router {
    Router::new()
        .nest_service(path, ServeDir::new(&config.cache_dir))
        .route_layer(middleware::from_fn(crate::middleware::query_param_auth))
        .layer(CompressionLayer::new())
        .layer(Extension(auth))
}
