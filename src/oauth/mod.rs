use std::time::Duration;

pub mod github;
use async_trait::async_trait;
pub use github::*;
pub mod types;
pub use types::*;
pub mod shared_pat;

mod utils;

pub type Result<T> = std::result::Result<T, OAuth2Error>;

#[async_trait]
pub trait Authenticate: Send + Sync + 'static {
    /// Begin an OAuth2 Authorization Code flow with PKCE. Returns the URL to redirect the
    /// user-agent to, where they can provide consent.
    async fn start_auth_flow(&self, auth_params: AuthFlow) -> Result<String>;

    /// Verify the PKCE challenge and exchange the code from the end user for a Github token.
    /// Returns a symmetrically encrypted token so the user can't use it directly, and we don't have
    /// rely on an external storage system for tokens.
    async fn exchange_code_for_token(&self, request: TokenRequest) -> Result<String>;

    /// Encrypt and base64url encode the token.
    fn encrypt_token(&self, token: String) -> Result<String>;

    /// Base64url decode and decrypt the token.
    fn decrypt_token(&self, ciphertext: String) -> Result<String>;

    /// Generate a short-lived (default 60s) single-use token that can be used for a single URL.
    async fn generate_single_use_token(
        &self,
        token: String,
        url: String,
        duration: Option<Duration>,
    ) -> Result<String>;

    /// Verify whether a single use token is valid for the given URL. This will consume the token's
    /// single possible use.
    async fn verify_single_use_token(&self, token: String, url: String) -> Result<SingleUseToken>;

    // Save the PKCE challenge. We will verify this later.
    async fn save_pkce_challenge(&self, challenge: String);

    // Verify that sha256(code_verifier) exists in recorded challenges. It is immediately removed if
    // found.
    async fn verify_pkce_challenge(&self, code_verifier: String) -> Result<()>;

    // Generate an authentication URL for the user-agent to give consent at for the scopes we're
    // requesting here. We send the session_id so that we can look up the correct session on
    // callback.
    fn auth_url_for_session(&self, token: String, redirect_url: String) -> Result<String>;
}
