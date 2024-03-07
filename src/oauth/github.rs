use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use orion::aead;
use tokio::sync::RwLock;

use super::types::*;
use super::*;
use crate::app_config::AppConfig;

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

type Result<T> = std::result::Result<T, OAuth2Error>;

/// Responsible for managing authentication.
#[derive(Debug, Clone)]
pub struct GithubAuthenticator {
    /// Exchanges code for token
    oauth2_client: oauth2::basic::BasicClient,

    /// Used for symmetric encryption of tokens.
    secret_key: Arc<aead::SecretKey>,

    /// Set of active PKCE challenges.
    pkce_challenges: Arc<RwLock<HashSet<String>>>,

    /// Active single use tokens. Keys are base64url encoded random bytes.
    download_tokens: Arc<RwLock<HashMap<String, SingleUseToken>>>,
}

impl GithubAuthenticator {
    /// Create a new authenticator for the given app configuration.
    pub fn new(config: &AppConfig) -> Result<Self> {
        let oauth2_client = utils::build_oauth2_client_from_config(config, AUTH_URL, TOKEN_URL)?;
        let secret_key = utils::build_secret_key(&config.secret_key)?;
        Ok(Self {
            oauth2_client,
            pkce_challenges: Arc::new(RwLock::new(HashSet::new())),
            download_tokens: Arc::new(RwLock::new(HashMap::new())),
            secret_key,
        })
    }
}

#[async_trait]
impl Authenticate for GithubAuthenticator {
    /// Begin an OAuth2 Authorization Code flow with PKCE. Returns the URL to redirect the
    /// user-agent to, where they can provide consent.
    async fn start_auth_flow(&self, auth_params: AuthFlow) -> Result<String> {
        auth_params.validate()?;
        let redirect_uri = auth_params.redirect_uri.clone();
        self.save_pkce_challenge(auth_params.code_challenge).await;
        self.auth_url_for_session(auth_params.state, redirect_uri)
    }

    /// Verify the PKCE challenge and exchange the code from the end user for a Github token.
    /// Returns a symmetrically encrypted token so the user can't use it directly, and we don't have
    /// rely on an external storage system for tokens.
    async fn exchange_code_for_token(&self, request: TokenRequest) -> Result<String> {
        self.verify_pkce_challenge(request.code_verifier).await?;

        match self
            .oauth2_client
            .exchange_code(AuthorizationCode::new(request.code))
            .request_async(oauth2::reqwest::async_http_client)
            .await
        {
            Ok(t) => Ok(self.encrypt_token(t.access_token().secret().to_string())?),
            Err(e) => Err(OAuth2Error::TokenExchange(e.to_string())),
        }
    }

    /// Encrypt and base64url encode the token.
    fn encrypt_token(&self, token: String) -> Result<String> {
        aead::seal(&self.secret_key, &token.into_bytes())
            .map_err(OAuth2Error::Encryption)
            .map(utils::base64url_encode)
    }

    /// Base64url decode and decrypt the token.
    fn decrypt_token(&self, ciphertext: String) -> Result<String> {
        let bytes = utils::base64url_decode(ciphertext)
            .map_err(|e| OAuth2Error::Decryption(e.to_string()))?;

        let decrypted_bytes = aead::open(&self.secret_key, &bytes)
            .map_err(|e| OAuth2Error::Decryption(e.to_string()))?;

        String::from_utf8(decrypted_bytes).map_err(|e| OAuth2Error::Decryption(e.to_string()))
    }

    /// Generate a short-lived (default 60s) single-use token that can be used for a single URL.
    async fn generate_single_use_token(
        &self,
        token: String,
        url: String,
        duration: Option<Duration>,
    ) -> Result<String> {
        // generate some random bytes to use as the key we send the user. This keeps the size down
        // a bit. If we want to support horizontal scaling of this server (lol) we will have to
        // write the actual token out so any other instance that has the secret key can use the
        // token.
        let key_bytes = utils::generate_random_key()?;

        let key = utils::base64url_encode(key_bytes);
        let expires_at =
            utils::current_epoch() + duration.unwrap_or(Duration::from_secs(60)).as_secs();
        let data = SingleUseToken {
            token,
            url,
            expires_at,
        };

        if self
            .download_tokens
            .write()
            .await
            .insert(key.clone(), data)
            .is_some()
        {
            panic!("A randomly generated 32 byte key has collided. Go buy a lottery ticket.");
        }

        Ok(key)
    }

    /// Verify whether a single use token is valid for the given URL. This will consume the token's
    /// single possible use.
    async fn verify_single_use_token(&self, token: String, url: String) -> Result<SingleUseToken> {
        let token = self
            .download_tokens
            .write()
            .await
            .remove(&token)
            .ok_or_else(|| OAuth2Error::SingleUseToken("Token does not exist".to_string()))?;

        if utils::current_epoch() >= token.expires_at {
            return Err(OAuth2Error::SingleUseToken("Token is expired".to_string()));
        }

        // The binary download urls get /downloads/ prefixed on them, but the signature/sha256sum
        // urls do not. This seems to be because req.uri().path() is not showing the full url when
        // an axum router is nested under a path.
        if !token.url.ends_with(&url) {
            return Err(OAuth2Error::SingleUseToken(
                "Invalid URL for token".to_string(),
            ));
        }

        Ok(token)
    }

    // Save the PKCE challenge. We will verify this later.
    async fn save_pkce_challenge(&self, challenge: String) {
        self.pkce_challenges.write().await.insert(challenge);
    }

    // Verify that sha256(code_verifier) exists in recorded challenges. It is immediately removed if
    // found.
    async fn verify_pkce_challenge(&self, code_verifier: String) -> Result<()> {
        let v = PkceCodeVerifier::new(code_verifier);
        let c = PkceCodeChallenge::from_code_verifier_sha256(&v);

        if !self.pkce_challenges.write().await.remove(c.as_str()) {
            return Err(OAuth2Error::PkceValidation(
                "Failed code verifier challenge".to_string(),
            ));
        }

        Ok(())
    }

    // Generate an authentication URL for the user-agent to give consent at for the scopes we're
    // requesting here. We send the session_id so that we can look up the correct session on
    // callback.
    fn auth_url_for_session(&self, token: String, redirect_url: String) -> Result<String> {
        let redirect_url =
            RedirectUrl::new(redirect_url).map_err(|e| OAuth2Error::AuthFlow(e.to_string()))?;

        Ok(self
            .oauth2_client
            .authorize_url(|| CsrfToken::new(token))
            .set_redirect_uri(Cow::Owned(redirect_url))
            .add_scope(oauth2::Scope::new("repo".to_string()))
            .url()
            .0
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::app_config::LogFormat;

    use super::*;

    fn build_test_authenticator() -> GithubAuthenticator {
        GithubAuthenticator::new(&AppConfig {
            client_id: "a".into(),
            client_secret: "b".into(),
            addr: "127.0.0.1:50000".parse().unwrap(),
            log_level: "no".into(),
            cache_dir: "./no".into(),
            secret_key: "11111111111111111111111111111111".into(),
            otlp_endpoint: None,
            log_format: LogFormat::Json,
            otlp_headers: None,
        })
        .unwrap()
    }

    #[test]
    fn encrypt_decrypt() {
        let auth = build_test_authenticator();
        let plaintext = "test".to_string();

        let ciphertext = auth.encrypt_token(plaintext.clone()).unwrap();
        assert_ne!(plaintext, ciphertext);

        let decrypted = auth.decrypt_token(ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn auth_flow_handles_pkce_challenge() {
        let auth = build_test_authenticator();
        let p = AuthFlow {
            code_challenge: "asdf".to_string(),
            code_challenge_method: "S256".to_string(),
            redirect_uri: "localhost:1234".to_string(),
            state: "random".to_string(),
        };

        let url = auth.start_auth_flow(p).await;
        assert!(url.is_ok());
        assert!(auth.pkce_challenges.read().await.len() == 1);
    }

    #[tokio::test]
    async fn exchange_code_for_token_checks_pkce_challenge() {
        let auth = build_test_authenticator();
        auth.save_pkce_challenge("challenge".into()).await;
        assert!(auth.pkce_challenges.read().await.len() == 1);

        let res = auth
            .exchange_code_for_token(TokenRequest {
                code: "1234".to_string(),
                code_verifier: "this.needs.to.be.at.least.43.characters.long".to_string(),
            })
            .await;

        assert!(matches!(res, Err(OAuth2Error::PkceValidation(_))));
        assert!(auth.pkce_challenges.read().await.len() == 1);
    }

    #[tokio::test]
    async fn successful_pkce_validation_removes_from_set() {
        let auth = build_test_authenticator();
        let verifier = "this.needs.to.be.at.least.43.characters.long".to_string();
        let v = PkceCodeVerifier::new(verifier.clone());
        let hash = PkceCodeChallenge::from_code_verifier_sha256(&v);

        auth.save_pkce_challenge(hash.as_str().to_string()).await;
        assert!(auth.pkce_challenges.read().await.len() == 1);

        let verify_result = auth.verify_pkce_challenge(verifier).await;
        assert!(verify_result.is_ok());
        assert!(auth.pkce_challenges.read().await.len() == 0);
    }

    #[tokio::test]
    async fn single_use_token_missing() {
        let auth = build_test_authenticator();
        let token = auth
            .verify_single_use_token("token".to_string(), "url".to_string())
            .await;
        assert!(token.unwrap_err().to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn single_use_token_expired() {
        let auth = build_test_authenticator();
        let url = "http://things".to_string();
        let gh_token = "token".to_string();

        let encrypted_token = auth
            .generate_single_use_token(gh_token.clone(), url.clone(), Some(Duration::default()))
            .await;
        assert!(encrypted_token.is_ok());
        assert!(auth.download_tokens.read().await.len() == 1);

        let token = auth
            .verify_single_use_token(encrypted_token.unwrap(), url)
            .await;
        assert!(token.unwrap_err().to_string().contains("expired"));
        assert!(auth.download_tokens.read().await.len() == 0);
    }

    #[tokio::test]
    async fn single_use_token_bad_url() {
        let auth = build_test_authenticator();
        let url = "http://things".to_string();
        let gh_token = "token".to_string();

        let encrypted_token = auth
            .generate_single_use_token(gh_token.clone(), url.clone(), None)
            .await;
        assert!(encrypted_token.is_ok());
        assert!(auth.download_tokens.read().await.len() == 1);

        let token = auth
            .verify_single_use_token(encrypted_token.unwrap(), "bad url".to_string())
            .await;
        assert!(token.unwrap_err().to_string().contains("Invalid URL"));
        assert!(auth.download_tokens.read().await.len() == 0);
    }

    #[tokio::test]
    async fn single_use_token_valid_returns_token() {
        let auth = build_test_authenticator();
        let url = "http://things".to_string();
        let gh_token = "token".to_string();

        let encrypted_token = auth
            .generate_single_use_token(gh_token.clone(), url.clone(), None)
            .await;
        assert!(encrypted_token.is_ok());
        assert!(auth.download_tokens.read().await.len() == 1);

        let token = auth
            .verify_single_use_token(encrypted_token.unwrap(), url)
            .await
            .unwrap();
        assert!(auth.download_tokens.read().await.len() == 0);

        assert!(token.token == gh_token);
    }
}
