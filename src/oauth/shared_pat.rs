use async_trait::async_trait;
use tracing::debug;

use super::{Authenticate, Result};

#[derive(Debug, Clone)]
pub struct SharedPATAuthenticator(String);

impl SharedPATAuthenticator {
    pub fn new(_config: &crate::app_config::AppConfig) -> Self {
        Self(String::new())
    }
    pub fn with_github_pat(pat: String) -> Self {
        Self(pat.clone())
    }
}

#[async_trait]
impl Authenticate for SharedPATAuthenticator {
    async fn start_auth_flow(&self, _auth_params: super::AuthFlow) -> Result<String> {
        debug!("start auth flow");
        Ok("".to_string())
    }

    async fn exchange_code_for_token(&self, _request: super::TokenRequest) -> Result<String> {
        debug!("exchange code for token");
        Ok(self.0.clone())
    }

    fn encrypt_token(&self, _token: String) -> Result<String> {
        debug!("encrypt token");
        Ok(self.0.clone())
    }

    fn decrypt_token(&self, _ciphertext: String) -> Result<String> {
        debug!("decrypt token");
        Ok(self.0.clone())
    }

    async fn generate_single_use_token(
        &self,
        _token: String,
        _url: String,
        _duration: Option<std::time::Duration>,
    ) -> Result<String> {
        debug!("generate single use token");
        Ok(self.0.clone())
    }

    async fn verify_single_use_token(
        &self,
        token: String,
        url: String,
    ) -> Result<super::SingleUseToken> {
        debug!("verify single use token");
        Ok(super::SingleUseToken {
            token,
            url,
            expires_at: u64::MAX,
        })
    }

    async fn save_pkce_challenge(&self, _challenge: String) {
        debug!("save pkce challenge");
    }

    async fn verify_pkce_challenge(&self, _code_verifier: String) -> Result<()> {
        debug!("verify pkce challenge");
        Ok(())
    }

    fn auth_url_for_session(&self, _token: String, _redirect_url: String) -> Result<String> {
        debug!("auth url for session");
        Ok("".to_string())
    }
}
