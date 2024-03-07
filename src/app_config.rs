use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{env, fs, net::SocketAddr, path::PathBuf};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    pub client_id: String,
    pub client_secret: String,
    pub addr: SocketAddr,
    pub log_level: String,
    pub cache_dir: PathBuf,
    pub secret_key: String,
    pub otlp_endpoint: Option<String>,
    pub otlp_headers: Option<String>,
    pub log_format: LogFormat,
}

impl AppConfig {
    pub fn merge_source_config(&mut self, c: ConfigSource) {
        if let Some(addr) = c.addr {
            self.addr = addr;
        }
        if let Some(log_level) = c.log_level {
            self.log_level = log_level;
        }
        if let Some(log_format) = c.log_format {
            self.log_format = log_format;
        }
        if let Some(cache_dir) = c.cache_dir {
            self.cache_dir = cache_dir;
        }
        if let Some(client_id) = c.client_id {
            self.client_id = client_id;
        }
        if let Some(client_secret) = c.client_secret {
            self.client_secret = client_secret;
        }
        if let Some(secret_key) = c.secret_key {
            self.secret_key = secret_key;
        }
        if let Some(otlp_endpoint) = c.otlp_endpoint {
            self.otlp_endpoint = Some(otlp_endpoint);
        }
        if let Some(otlp_headers) = c.otlp_headers {
            self.otlp_headers = Some(otlp_headers);
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.client_id.is_empty() {
            anyhow::bail!("Client ID must be set");
        }
        if self.client_secret.is_empty() {
            anyhow::bail!("Client secret must be set");
        }
        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        let cache_dir = match env::current_dir() {
            Ok(dir) => dir,
            Err(_) => env::temp_dir(),
        }
        .join("cache");
        Self {
            client_id: "".to_string(),
            client_secret: "".to_string(),
            addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            log_level: "tfreg=debug,tower_http=debug".into(),
            cache_dir,
            secret_key: "".to_string(),
            otlp_endpoint: None,
            otlp_headers: None,
            log_format: LogFormat::Compact,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, clap::ValueEnum, PartialEq)]
pub enum LogFormat {
    Compact,
    Pretty,
    Json,
}

#[derive(Parser, Serialize, Deserialize, Debug, Default)]
#[clap(author, version, about)]
pub struct ConfigSource {
    /// TOML configuration file to read
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_CONFIG")]
    pub config: Option<PathBuf>,

    /// socket address to listen on
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_ADDR")]
    pub addr: Option<SocketAddr>,

    /// Set log level in RUST_LOG format
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// Log format to use on stdout.
    #[clap(long, hide_env_values(true), value_enum, env = "TFREG_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// Directory to cache downloadable assets in
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Github OAuth2 app client id
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_CLIENT_ID")]
    pub client_id: Option<String>,

    /// Github OAuth2 app client secret
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    /// 32 byte secret key used for token encryption
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_SECRET_KEY")]
    pub secret_key: Option<String>,

    /// URL to send OTLP traces to. Will only send traces if this property is specified.
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Additional headers in k=v,k=v format to send with OTLP traces.
    #[clap(long, hide_env_values(true), value_parser, env = "TFREG_OTLP_HEADERS")]
    pub otlp_headers: Option<String>,
}

pub fn load() -> Result<AppConfig> {
    let cli_args = ConfigSource::parse();
    let mut conf = AppConfig::default();

    if let Some(p) = &cli_args.config {
        let file_conf: ConfigSource = toml::from_str(&fs::read_to_string(p)?)?;
        conf.merge_source_config(file_conf);
    }

    conf.merge_source_config(cli_args);
    conf.validate()?;

    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_none_does_nothing() {
        let mut base = AppConfig::default();
        let layer = ConfigSource {
            ..Default::default()
        };
        base.merge_source_config(layer);
        assert_eq!(base, AppConfig::default());
    }

    #[test]
    fn merge_some_unwraps_and_overwrites() {
        let mut base = AppConfig::default();
        let layer = ConfigSource {
            log_level: Some("test".to_string()),
            ..Default::default()
        };
        base.merge_source_config(layer);
        assert_ne!(base, AppConfig::default());
        assert_eq!(base.log_level, "test".to_string());
    }

    #[test]
    fn merge_multiple_layers() {
        let mut base = AppConfig::default();
        let layer = ConfigSource {
            log_level: Some("test".to_string()),
            ..Default::default()
        };
        let second_layer = ConfigSource {
            log_level: Some("second_test".to_string()),
            client_id: Some("id".to_string()),
            ..Default::default()
        };

        base.merge_source_config(layer);
        assert_ne!(base, AppConfig::default());
        assert_eq!(base.log_level, "test".to_string());
        assert!(base.client_id.is_empty());

        base.merge_source_config(second_layer);
        assert_eq!(base.log_level, "second_test".to_string());
        assert_eq!(base.client_id, "id".to_string());
    }

    #[test]
    fn validate_fails_with_missing_client_id() {
        let base = AppConfig::default();
        let res = base.validate();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "Client ID must be set");
    }

    #[test]
    fn validate_fails_with_missing_client_secret() {
        let base = AppConfig {
            client_id: "not_empty".to_string(),
            ..Default::default()
        };
        let res = base.validate();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "Client secret must be set");
    }

    #[test]
    fn validate_passes_with_both_client_fields() {
        let base = AppConfig {
            client_id: "not_empty".to_string(),
            client_secret: "not_empty".to_string(),
            ..Default::default()
        };
        let res = base.validate();
        assert!(res.is_ok());
    }
}
