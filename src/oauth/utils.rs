use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl};
use orion::aead;

use crate::app_config::AppConfig;

use super::{OAuth2Error, Result, AUTH_URL, TOKEN_URL};

const BASE64_FORMAT: base64::Config = base64::URL_SAFE;

pub fn base64url_encode<T: AsRef<[u8]>>(key_bytes: T) -> String {
    base64::encode_config(key_bytes, BASE64_FORMAT)
}

pub fn base64url_decode<T: AsRef<[u8]>>(
    key_bytes: T,
) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(key_bytes, BASE64_FORMAT)
}

pub fn build_secret_key(secret_key: &str) -> Result<Arc<aead::SecretKey>> {
    aead::SecretKey::from_slice(secret_key.as_bytes())
        .map(Arc::new)
        .map_err(OAuth2Error::Encryption)
}

pub fn build_oauth2_client_from_config(config: &AppConfig) -> Result<BasicClient> {
    Ok(BasicClient::new(
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
        AuthUrl::new(AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    ))
}

pub fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn generate_random_key() -> Result<[u8; 64]> {
    let mut key_bytes = [0u8; 64];
    orion::util::secure_rand_bytes(&mut key_bytes).map_err(OAuth2Error::Encryption)?;
    Ok(key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        let key = generate_random_key().unwrap();
        let encoded = base64url_encode(key);
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(key.to_vec(), decoded);
    }
}
