use std::sync::Arc;

use axum::{middleware, Extension, Router};
use axum_extra::routing::SpaRouter;
use tower_http::compression::CompressionLayer;

use crate::oauth::Authenticator;

pub fn router(
    config: &crate::app_config::AppConfig,
    path: &str,
    auth: Arc<Authenticator>,
) -> Router {
    Router::new()
        .merge(SpaRouter::new(path, &config.cache_dir))
        .route_layer(middleware::from_fn(crate::middleware::query_param_auth))
        .layer(CompressionLayer::new())
        .layer(Extension(auth))
}
