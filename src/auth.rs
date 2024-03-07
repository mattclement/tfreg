use std::sync::Arc;

use crate::oauth::Authenticate;
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

use crate::oauth::{types::AuthFlow, OAuth2Error, TokenRequest};

pub fn router<T: Authenticate>(auth: Arc<T>) -> Result<Router> {
    Ok(Router::new()
        .route("/authz", get(auth_flow_handler::<T>))
        .route("/token", post(token_handler::<T>))
        .layer(Extension(auth)))
}

async fn auth_flow_handler<T: Authenticate>(
    Query(params): Query<AuthFlow>,
    Extension(authenticator): Extension<Arc<T>>,
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

async fn token_handler<T: Authenticate>(
    Extension(authenticator): Extension<Arc<T>>,
    Form(params): Form<TokenRequest>,
) -> Result<Json<Value>, StatusCode> {
    match authenticator.exchange_code_for_token(params).await {
        Ok(c) => Ok(Json(json!({ "access_token": c }))),
        Err(e) => {
            error!("{}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
