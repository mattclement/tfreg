use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Form, Query},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::{json, Value};
use tracing::error;

use crate::oauth::{types::AuthFlow, Authenticator, OAuth2Error, TokenRequest};

pub fn router(auth: Arc<Authenticator>) -> Result<Router> {
    Ok(Router::new()
        .route("/authz", get(auth_flow_handler))
        .route("/token", post(token_handler))
        .layer(Extension(auth)))
}

async fn auth_flow_handler(
    Query(params): Query<AuthFlow>,
    Extension(authenticator): Extension<Arc<Authenticator>>,
) -> Result<Redirect, StatusCode> {
    match authenticator.start_auth_flow(params).await {
        Ok(url) => Ok(Redirect::to(&url)),
        Err(OAuth2Error::PkceValidation(e)) => {
            error!("{}", e);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("{}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn token_handler(
    Form(params): Form<TokenRequest>,
    Extension(authenticator): Extension<Arc<Authenticator>>,
) -> Result<Json<Value>, StatusCode> {
    match authenticator.exchange_code_for_token(params).await {
        Ok(c) => Ok(Json(json!({ "access_token": c }))),
        Err(e) => {
            error!("{}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
