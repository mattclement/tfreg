use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Information that is required to construct a single use token.
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleUseToken {
    pub token: String,
    pub url: String,
    pub expires_at: u64,
}

/// Information needed to verify a PKCE challenge and exchange for a token.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub code: String,
    pub code_verifier: String,
}

/// This info is the required data to start an OAuth2 Authorization Code flow with PKCE.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthFlow {
    /// A SHA256 hashed string from the client. This will be verified in the final step of the
    /// OAuth2 flow in order for the client to prove that they're the same client that started
    /// this flow.
    pub code_challenge: String,

    /// Indicates the method the client intends to use for PKCE. We only support S256 here.
    pub code_challenge_method: String,

    /// The URI where we will redirect the user-agent after authentication.
    pub redirect_uri: String,

    /// Opaque data from the user, used for validation. The client expects this parameter to be
    /// returned from github, so that it knows we are the ones requesting access.
    pub state: String,
}

impl AuthFlow {
    /// Validate the auth flow parameters. We require a SHA256 PKCE code challenge.
    pub fn validate(&self) -> Result<(), OAuth2Error> {
        if self.code_challenge.is_empty() {
            return Err(OAuth2Error::PkceValidation(
                "No code challenge presented".to_string(),
            ));
        }
        if self.code_challenge_method != "S256" {
            return Err(OAuth2Error::PkceValidation(
                "Only S256 challenge method is allowed".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone)]
pub enum OAuth2Error {
    /// Configuration error of the OAuth2 client.
    #[error("Error while configuring oauth2 client: {0}")]
    ClientConfig(#[from] oauth2::url::ParseError),

    /// Error during the auth flow
    #[error("OAuth2 flow error: {0}")]
    AuthFlow(String),

    /// Error validating the PKCE code.
    #[error("PKCE error: {0}")]
    PkceValidation(String),

    /// An error occuring while exchanging a code from the user for a token from GitHub.
    #[error("Error exchanging code for token: {0}")]
    TokenExchange(String),

    /// Error with the encryption of the token.
    #[error("Token encryption error: {0}")]
    Encryption(#[from] orion::errors::UnknownCryptoError),

    /// Error with the decryption of the token.
    #[error("Token decryption error: {0}")]
    Decryption(String),

    /// Error with a single use token.
    #[error("Single use token error: {0}")]
    SingleUseToken(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_challenge_presence() {
        let p = AuthFlow::default();
        let res = p.validate();
        assert!(res.is_err());
    }

    #[test]
    fn validate_challenge_method() {
        let p = AuthFlow {
            code_challenge: "not_empty".to_string(),
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_with_all_required_params() {
        let p = AuthFlow {
            code_challenge: "not_empty".to_string(),
            code_challenge_method: "S256".to_string(),
            ..Default::default()
        };
        assert!(p.validate().is_ok());
    }
}
