use crate::{middleware, oauth::Authenticate};
use anyhow::Result;
use axum::{
    extract::Path,
    http::{self, StatusCode},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{error, instrument};

use crate::{
    github::{Download, GPGKey},
    signature::GPGSigner,
};

pub async fn router<T: Authenticate>(
    config: &crate::app_config::AppConfig,
    auth: Arc<T>,
) -> Result<Router> {
    let signer = GPGSigner::new()?;
    let client = crate::github::Client::new(
        config.cache_dir.clone(),
        GPGKey::new(signer.fingerprint(), signer.ascii_armor()?),
    )
    .await?;

    let query_middleware = axum::middleware::from_fn(middleware::query_param_auth::<T>);
    let header_middleware = axum::middleware::from_fn(middleware::header_auth::<T>);

    let sig_router = Router::new()
        .route("/:namespace/:provider/:version/signature", Signature::get())
        .route_layer(query_middleware);

    let provider_router = Router::new()
        .route("/:namespace/:provider/versions", ListVersions::get())
        .route(
            "/:namespace/:provider/:version/download/:os/:arch",
            FindPackage::get::<T>(),
        )
        .route_layer(header_middleware);

    let r = Router::new()
        .merge(sig_router)
        .merge(provider_router)
        .layer(Extension(Arc::new(signer)))
        .layer(Extension(Arc::new(client)))
        .layer(Extension(auth));

    Ok(r)
}

// https://www.terraform.io/internals/provider-registry-protocol#list-available-versions
#[derive(Deserialize)]
struct ListVersions {
    namespace: String,
    provider: String,
}

impl ListVersions {
    pub fn get() -> axum::routing::MethodRouter {
        get(Self::handler)
    }

    #[instrument(skip_all, name = "list_versions")]
    async fn handler(
        Path(params): Path<Self>,
        Extension(token): Extension<String>,
        Extension(client): Extension<Arc<crate::github::Client>>,
    ) -> Result<Json<Value>, http::StatusCode> {
        match client
            .get_versions(token, params.namespace, params.provider)
            .await
        {
            Some(r) => Ok(Json(json!({ "versions": r }))),
            None => Err(StatusCode::NOT_FOUND),
        }
    }
}

// https://www.terraform.io/internals/provider-registry-protocol#find-a-provider-package
#[derive(Serialize, Deserialize)]
pub struct FindPackage {
    pub namespace: String,
    pub provider: String,
    pub version: String,
    pub os: String,
    pub arch: String,
}

impl FindPackage {
    pub fn get<T: Authenticate>() -> axum::routing::MethodRouter {
        get(Self::handler::<T>)
    }

    #[instrument(skip_all, name = "find_package")]
    async fn handler<T: Authenticate>(
        Path(params): Path<Self>,
        Extension(token): Extension<String>,
        Extension(authenticator): Extension<Arc<T>>,
        Extension(client): Extension<Arc<crate::github::Client>>,
    ) -> Result<Json<Download>, http::StatusCode> {
        // generate new time limited, single use session based off of this one that will
        // be added as a query parameter to the download url here.

        let mut download = client
            .get_provider_info(
                token.clone(),
                params.namespace,
                params.provider,
                params.version,
                params.os,
                params.arch,
            )
            .await
            .ok_or(StatusCode::NOT_FOUND)?;

        for url in [
            &mut download.asset.download_url,
            &mut download.asset.shasums_url,
            &mut download.asset.shasums_signature_url,
        ] {
            let t = authenticator
                .generate_single_use_token(token.clone(), url.clone(), None)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let qs = serde_urlencoded::to_string(&[("token", t)]).map_err(|e| {
                error!("{}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            let qs = &format!("?{}", qs);
            url.push_str(qs);
        }
        Ok(Json(download))
    }
}

// https://www.terraform.io/internals/provider-registry-protocol#find-a-provider-package
#[derive(Deserialize)]
struct Signature {
    namespace: String,
    provider: String,
    version: String,
}

impl Signature {
    pub fn get() -> axum::routing::MethodRouter {
        get(Self::handler)
    }

    #[instrument(skip_all, name = "signature")]
    async fn handler(
        Path(params): Path<Self>,
        Extension(signer): Extension<Arc<GPGSigner>>,
        Extension(client): Extension<Arc<crate::github::Client>>,
    ) -> Result<Vec<u8>, http::StatusCode> {
        let repo = crate::github::Repo::new(params.namespace, params.provider);
        let checksums = client
            .load_sha256sums(&repo, &params.version)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        signer
            .sign(&checksums)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}
