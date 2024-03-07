use std::sync::Arc;

use axum::{Extension, Router};
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;

use crate::middleware;
use crate::oauth::Authenticate;

pub fn router<T: Authenticate>(
    config: &crate::app_config::AppConfig,
    path: &str,
    auth: Arc<T>,
) -> Router {
    let query_middleware = axum::middleware::from_fn(middleware::query_param_auth::<T>);
    Router::new()
        .nest_service(path, ServeDir::new(&config.cache_dir))
        .route_layer(query_middleware)
        .layer(CompressionLayer::new())
        .layer(Extension(auth))
}
