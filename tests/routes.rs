use anyhow::Result;
use axum::{body::Body, http::Request, Router};
use http_body_util::BodyExt;
use orion::hazardous::hash::sha2::sha256::Sha256;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tfreg::{
    app_config::{self, AppConfig},
    oauth::shared_pat::SharedPATAuthenticator,
    SERVICE_DISCOVERY_PATH,
};
use tower::ServiceExt;

fn test_config() -> AppConfig {
    let mut f = app_config::load().unwrap();
    f.log_level = "disabled".to_string();

    f.validate().expect("Invalid config");
    f
}

// Setting this environment variable and using the SharedPATAuthenticator will let us bypass all of
// the oauth2 auth flow and send the shared personal access token instead of the end-user, which we
// don't have in a test.
fn get_shared_pat() -> Result<String> {
    Ok(std::env::var("TFREG_TEST_PAT")?)
}

async fn app() -> Result<Router> {
    let c = test_config();
    tfreg::router(
        &c,
        Arc::new(SharedPATAuthenticator::with_github_pat(get_shared_pat()?)),
    )
    .await
}

#[tokio::test]
async fn buildable() {
    assert!(app().await.is_ok());
}

#[tokio::test]
async fn service_discovery() -> Result<()> {
    let app = app().await?;
    let req = Request::builder()
        .uri(SERVICE_DISCOVERY_PATH)
        .body(Body::empty())?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), 200);

    let body = res.into_body().collect().await?.to_bytes();
    let body: Value = serde_json::from_slice(&body)?;
    assert!(body.is_object());

    let body = body.as_object().unwrap();
    assert!(body
        .keys()
        .all(|k| ["providers.v1", "login.v1"].contains(&k.as_str())));

    Ok(())
}

#[tokio::test]
async fn test_download_flow() -> Result<()> {
    let app = app().await?;
    let org = "cortexapps";
    let provider = "cortex";
    let namespace = format!("{org}/{provider}/");
    let version_url = url::Url::parse("http://localhost")?
        .join(tfreg::PROVIDER_ROUTE_PREFIX)?
        .join(&namespace)?
        .join("versions")?;
    let version_req = Request::builder()
        .uri(version_url.as_str())
        .header("Authorization", "Bearer foo")
        .body(Body::empty())?;

    // Get versions
    let version_res = app.clone().oneshot(version_req).await?;
    assert_eq!(version_res.status(), 200);

    let body = version_res.into_body().collect().await?.to_bytes();
    let body: HashMap<String, Vec<tfreg::github::ProviderVersion>> = serde_json::from_slice(&body)?;

    assert!(body.keys().len() == 1);
    assert!(body.get("versions").is_some());

    let version = body.get("versions").unwrap().iter().last().unwrap();
    let platform = version.platforms.last().unwrap();

    // Download the version info for one platform
    let download_info_url = url::Url::parse("http://localhost")?
        .join(tfreg::PROVIDER_ROUTE_PREFIX)?
        .join(&namespace)?
        .join(&format!(
            "{}/download/{}/{}",
            version.version, platform.os, platform.arch
        ))?;
    let download_info_req = Request::builder()
        .uri(download_info_url.as_str())
        .header("Authorization", "Bearer foo")
        .body(Body::empty())?;
    let download_info_res = app.clone().oneshot(download_info_req).await?;
    assert_eq!(download_info_res.status(), 200);

    let body = download_info_res.into_body().collect().await?.to_bytes();
    let body: tfreg::github::Download = serde_json::from_slice(&body)?;
    let checksum = hex::decode(body.asset.shasum)?;

    // download package
    let download_url = url::Url::parse("http://localhost")?.join(&body.asset.download_url)?;
    let download_req = Request::builder()
        .uri(download_url.as_str())
        .body(Body::empty())?;

    let download_res = app.clone().oneshot(download_req).await?;
    assert!(download_res.status() == 200, "{}", download_res.status());
    let body = download_res.into_body().collect().await?.to_bytes();

    // Verify the downloaded body's sha256 digest matches what was reported earlier
    let digest = Sha256::digest(&body)?;
    assert!(digest.as_ref() == checksum);

    Ok(())
}
