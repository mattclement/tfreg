use anyhow::{anyhow, Result};
use std::path::PathBuf;
use tokio::fs;
use tracing::debug;

use super::{ReleaseTag, Repo};

#[derive(Debug)]
pub struct AssetCache {
    base_dir: PathBuf,
}

impl AssetCache {
    pub async fn new(base_dir: PathBuf) -> Result<Self> {
        let cache = Self { base_dir };
        cache.create_cache_dir().await?;
        Ok(cache)
    }

    async fn create_cache_dir(&self) -> Result<()> {
        debug!("Creating cache_dir at {}", self.base_dir.display());
        fs::create_dir_all(&self.base_dir)
            .await
            .map_err(|err| anyhow!(err))
    }

    pub fn build_asset_path(&self, repo: &Repo, tag: &ReleaseTag, filename: &str) -> PathBuf {
        self.base_dir
            .clone()
            .as_path()
            .join(&repo.org)
            .join(&repo.name)
            .join(tag)
            .join(&filename)
    }

    pub async fn get_asset(&self, repo: &Repo, tag: &ReleaseTag, name: &str) -> Result<Vec<u8>> {
        let path = self.build_asset_path(repo, &tag.trim_start_matches('v').to_string(), name);
        Ok(fs::read(path).await?)
    }
}
