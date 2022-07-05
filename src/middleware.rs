use std::sync::Arc;

use axum::{
    http::{self, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{error, info, instrument};

use crate::{github::Repo, oauth::Authenticator};

// Determine whether the passed API key in the authorization header has read access to the github
// repository indicated by the first two segments of the URL path (e.g.
// /mattclement/example/foo/bar checks against github.com/mattclement/example).
pub async fn header_auth<B>(mut req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let authenticator: &Arc<Authenticator> = req
        .extensions()
        .get()
        .expect("Authenticator is unavailable as an request extension");
    let token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim_start_matches("Bearer ")
        .to_string();

    let repo = repo_from_path(req.uri().path()).ok_or(StatusCode::BAD_REQUEST)?;

    match authenticator.decrypt_token(token) {
        Ok(s) => {
            check_repo_permissions(s.clone(), &repo).await?;
            req.extensions_mut().insert(s);
        }
        Err(e) => {
            error!("{}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    Ok(next.run(req).await)
}

#[derive(Debug, Deserialize)]
struct TokenQS {
    token: String,
}
// query param auth values are only valid for a single use.
pub async fn query_param_auth<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let authenticator: &Arc<Authenticator> = req
        .extensions()
        .get()
        .expect("Authenticator is unavailable as an request extension");

    let qs = req.uri().query().ok_or(StatusCode::UNAUTHORIZED)?;
    let token = serde_urlencoded::from_str::<TokenQS>(qs)
        .map_err(|e| {
            error!("{}", e);
            StatusCode::UNAUTHORIZED
        })?
        .token;

    let repo = repo_from_path(req.uri().path()).ok_or(StatusCode::BAD_REQUEST)?;

    match authenticator
        .verify_single_use_token(&token, req.uri().path())
        .await
    {
        Ok(t) => {
            check_repo_permissions(t.token.clone(), &repo).await?;
        }
        Err(e) => {
            error!("{}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    Ok(next.run(req).await)
}

#[instrument(skip_all)]
async fn check_repo_permissions(token: String, repo: &Repo) -> Result<(), StatusCode> {
    octocrab::Octocrab::builder()
        .personal_token(token)
        .build()
        .map_err(|_| StatusCode::NOT_FOUND)?
        .repos(&repo.org, &repo.name)
        .get()
        .await
        .map_err(|e| {
            error!(
                "Error during repo {}/{} permission check: {}",
                repo.org, repo.name, e
            );
            StatusCode::NOT_FOUND
        })?;

    info!("Token has access to {}/{}", repo.org, repo.name);
    Ok(())
}

/// Extract the repo specified in the given URL path. This is designed to handle paths that point
/// at either the downloads API or the provider API.
fn repo_from_path(path: &str) -> Option<Repo> {
    let repo_components_in_url_path = path
        .trim_start_matches('/')
        .trim_start_matches("downloads/")
        .splitn(3, '/')
        .take(2)
        .collect::<Vec<&str>>();
    if repo_components_in_url_path.len() != 2 {
        return None;
    }
    Some(Repo::new(
        repo_components_in_url_path.first()?.to_string(),
        repo_components_in_url_path.last()?.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_from_path() {
        let expected = Repo::new("org".to_string(), "name".to_string());

        assert_eq!(
            expected,
            repo_from_path("/downloads/org/terraform-provider-name/2.3.4/SHA256SUMS").unwrap()
        );

        assert_eq!(
            expected,
            repo_from_path("/org/terraform-provider-name/2.3.4/SHA256SUMS").unwrap()
        )
    }
}
