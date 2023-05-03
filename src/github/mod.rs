use anyhow::{anyhow, Result};
use futures::{future::join_all, stream::TryStreamExt};
use octocrab::{models::repos::Release, Page};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tokio::sync::RwLock;
use tokio_util::io::StreamReader;
use tracing::{error, info, instrument};

use self::cache::AssetCache;

mod cache;

type ReleaseTag = String;
type BinaryName = String;
type Checksum = String;
type Assets = HashMap<ReleaseTag, Vec<ProviderAsset>>;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repo {
    pub org: String,
    pub name: String,
}

impl Repo {
    pub fn new(organization: String, mut repository: String) -> Self {
        if !repository.starts_with("terraform-provider-") {
            repository = format!("terraform-provider-{}", repository);
        };
        Self {
            org: organization,
            name: repository,
        }
    }
}

#[derive(Debug)]
pub struct Client {
    /// List of assets by repo that are available for download. We store them here so that we don't
    /// have to re-download the entire list on each /download call. Since our flow assumes that the
    /// terraform CLI is calling it and as such will ask for /versions before /download, we re-fetch
    /// on /versions so that changed versions appear as such to /download.
    pub assets: RwLock<HashMap<Repo, Assets>>,

    /// A reference to a local file based cache directory.
    pub cache: AssetCache,

    /// TODO: is this used?
    pub signing_key: GPGKey,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct OsArch {
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProviderVersion {
    pub version: String,
    pub protocols: Vec<String>,
    pub platforms: Vec<OsArch>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Download {
    pub signing_keys: SigningKey,

    #[serde(flatten)]
    pub asset: ProviderAsset,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProviderAsset {
    #[serde(flatten)]
    pub os_arch: OsArch,

    pub filename: String,
    pub download_url: String,
    pub shasum: String,
    pub shasums_url: String,
    pub shasums_signature_url: String,
    pub protocols: Vec<String>,

    // used to download asset when download metadata is requested by the user.
    github_asset_url: reqwest::Url,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigningKey {
    pub gpg_public_keys: Vec<GPGKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GPGKey {
    pub key_id: String,
    pub ascii_armor: String,
}

impl GPGKey {
    pub fn new(key_id: String, ascii_armor: String) -> Self {
        Self {
            key_id,
            ascii_armor,
        }
    }
}

// Client contains a local registry and cache of terraform provider binaries.
impl Client {
    pub async fn new(cache_dir: PathBuf, signing_key: GPGKey) -> Result<Self> {
        Ok(Self {
            assets: RwLock::new(HashMap::new()),
            cache: AssetCache::new(cache_dir).await?,
            signing_key,
        })
    }

    /// Return a list of available provider versions for a given repository.
    #[instrument(skip_all)]
    pub async fn get_versions(
        &self,
        token: String,
        github_org: String,
        repo_name: String,
    ) -> Option<Vec<ProviderVersion>> {
        let key = Repo::new(github_org, repo_name);

        let assets_map = self
            .load_available_versions(token, key.clone())
            .await
            .ok()?;

        let versions = assets_map
            .iter()
            .map(|(version, assets)| ProviderVersion {
                version: version.to_string(),
                protocols: vec!["5.0".to_string()],
                platforms: assets.iter().map(|x| x.os_arch.clone()).collect(),
            })
            .collect::<Vec<ProviderVersion>>();

        // Put the map into an in-memory cache so we don't have to rebuild it when the user tries
        // to download a specific version.
        self.assets.write().await.insert(key, assets_map);

        if versions.is_empty() {
            return None;
        }
        Some(versions)
    }

    /// Return information on a single provider.
    #[instrument(skip_all)]
    pub async fn get_provider_info(
        &self,
        token: String,
        namespace: String,
        provider: String,
        version: String,
        os: String,
        arch: String,
    ) -> Option<Download> {
        let key = Repo::new(namespace, provider);
        let requested_os_arch = OsArch { os, arch };
        let asset = self
            .assets
            .read()
            .await
            .get(&key)?
            .get(version.trim_start_matches('v'))?
            .iter()
            .find(|asset| asset.os_arch == requested_os_arch)?
            .clone();

        if let Err(e) = self.download_asset(token, key, version, &asset).await {
            error!("{}", e);
            return None;
        }

        Some(Download {
            signing_keys: SigningKey {
                gpg_public_keys: vec![self.signing_key.clone()],
            },
            asset,
        })
    }

    /// Load all available provider versions for a given repo. A version is determined to be
    /// available by the following criteria:
    ///
    /// 1. There is a github release with a tag that follows a narrow subset of semver: x.y.z with
    ///    an optional `v` prefix (e.g. `v1.2.3` or `1.2.3`).
    /// 2. There is a checksum file provided as a release asset. The checksum file itself may be
    ///    named either `SHA256SUMS` or `terraform-provider-xyz_1.2.3_SHA256SUMS` where the
    ///    provider name matches the repo name and the version matches the tag (no `v` allowed).
    /// 3. Downloadable assets are zip files with the following scheme:
    ///    `terraform-provider-xyz_1.2.3_linux_amd64.zip` where all underscore-separted components
    ///    indicate which (repo / version / operating system / architecture) the zipped asset
    ///    contains.
    #[instrument(skip_all)]
    async fn load_available_versions(&self, token: String, repo: Repo) -> Result<Assets> {
        let releases = self.load_release_metadata(token.clone(), &repo).await?;

        let mut futures = vec![];

        for release in releases
            .into_iter()
            .filter(|r| r.assets.iter().any(|a| a.name.ends_with("SHA256SUMS")))
        {
            futures.push(self.find_release_assets_from_checksum(&token, &repo, release));
        }

        let res = join_all(futures).await;

        Ok(res.into_iter().filter_map(|x| x.ok()).collect::<Assets>())
    }

    #[instrument(skip_all)]
    async fn find_release_assets_from_checksum(
        &self,
        token: &str,
        repo: &Repo,
        release: Release,
    ) -> Result<(ReleaseTag, Vec<ProviderAsset>)> {
        let mut assets = vec![];
        self.download_release_sha256sums(token.to_string(), repo, &release)
            .await?;
        let checksums = self.parse_checksums(repo, &release).await?;
        let version = release.tag_name.trim_start_matches('v');
        let download_base = Path::new("/downloads")
            .join(&repo.org)
            .join(&repo.name)
            .join(version);

        for release_asset in &release.assets {
            let shasum = match checksums.get(&release_asset.name) {
                Some(s) => s.to_string(),
                None => continue,
            };

            // Asset name must be binary-name_version_os_arch.zip
            //     e.g. terraform-provider-random_1.0.0_linux_amd64.zip
            let parts: Vec<&str> = release_asset
                .name
                .trim_end_matches(".zip")
                .rsplitn(3, '_')
                .collect();
            let arch = parts.first();
            let os = parts.get(1);
            if os.is_none() || arch.is_none() {
                continue;
            }

            // This points to our signing url that fetches the release's sha256sum and signs it
            // with an in-memory gpg key generated on startup.
            let sig_url = format!(
                "/providers/v1/{}/{}/{}/signature",
                repo.org, repo.name, version
            );

            let asset = ProviderAsset {
                protocols: vec!["5.0".to_string()],
                os_arch: OsArch {
                    os: os.unwrap().to_string(),
                    arch: arch.unwrap().to_string(),
                },
                filename: release_asset.name.clone(),
                download_url: download_base
                    .join(&release_asset.name)
                    .display()
                    .to_string(),
                shasum,
                shasums_url: download_base.join("SHA256SUMS").display().to_string(),
                shasums_signature_url: sig_url.to_string(),
                github_asset_url: release_asset.url.clone(),
            };
            assets.push(asset);
        }
        Ok((release.tag_name.trim_start_matches('v').to_string(), assets))
    }

    // Load releases from github.
    #[instrument(skip(self, token))]
    async fn load_release_metadata(&self, token: String, repo: &Repo) -> Result<Page<Release>> {
        let client = octocrab::Octocrab::builder()
            .personal_token(token)
            .build()?;

        client
            .repos(&repo.org, &repo.name)
            .releases()
            .list()
            .per_page(100)
            .page(1u32)
            .send()
            .await
            .map_err(|e| anyhow!(e))
    }

    // Download a file with client's API key.
    #[instrument(skip_all)]
    async fn download_file(&self, token: String, url: Url, destination: PathBuf) -> Result<()> {
        if destination.exists() {
            return Ok(());
        }
        let client = octocrab::Octocrab::builder()
            .personal_token(token)
            .build()?;
        let res = client._get(url.to_string()).await?;
        tokio::fs::create_dir_all(destination.parent().unwrap()).await?;
        let mut out = tokio::fs::File::create(destination).await?;

        let mut download_stream = StreamReader::new(
            res.into_body()
                .into_stream()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
        );
        tokio::io::copy(&mut download_stream, &mut out).await?;
        Ok(())
    }

    /// Download a single asset from github.
    #[instrument(skip_all, fields(asset=%asset.filename))]
    async fn download_asset(
        &self,
        token: String,
        repo: Repo,
        version: String,
        asset: &ProviderAsset,
    ) -> Result<()> {
        let dest = self
            .cache
            .build_asset_path(&repo, &version, &asset.filename);
        info!(
            "Downloading {} to {} ({})",
            &asset.filename,
            dest.display(),
            &asset.download_url
        );

        self.download_file(token, asset.github_asset_url.clone(), dest)
            .await?;
        Ok(())
    }

    // Download SHA256SUMS file from a release. Always stores as SHA256SUMS, regardless of whether
    // it contains the repo/version prefix on the asset name in github.
    #[instrument(skip_all, fields(release=%release.tag_name))]
    async fn download_release_sha256sums(
        &self,
        token: String,
        repo: &Repo,
        release: &Release,
    ) -> Result<()> {
        let checksum = release
            .assets
            .iter()
            .find(|a| a.name.ends_with("SHA256SUMS"))
            .ok_or_else(|| anyhow!("No sha256sums found"))?;

        let dest = self.cache.build_asset_path(
            repo,
            &release.tag_name.trim_start_matches('v').to_string(),
            "SHA256SUMS",
        );

        self.download_file(token.clone(), checksum.url.clone(), dest)
            .await?;

        Ok(())
    }

    /// Load SHA256SUMS from disk. This supports reading a file named either:
    /// 1. SHA256SUMS                              (exact)
    /// 2. terraform-provider-xxx_0.0.0_SHA256SUMS (where repo / semver match args values)
    #[instrument(skip_all)]
    pub async fn load_sha256sums(&self, repo: &Repo, release: &str) -> Result<Vec<u8>> {
        if let Ok(short_name) = self
            .cache
            .get_asset(repo, &release.to_owned(), "SHA256SUMS")
            .await
        {
            return Ok(short_name);
        }
        let long_name = format!(
            "{}_{}_SHA256SUMS",
            repo.name,
            release.trim_start_matches('v')
        );
        self.cache
            .get_asset(repo, &release.to_owned(), &long_name)
            .await
    }

    /// Parse the SHA256SUMS file. It is expected to be in the standard text format as
    /// generated by running `sha256sums *` on the command line.
    #[instrument(skip_all)]
    pub async fn parse_checksums(
        &self,
        repo: &Repo,
        release: &Release,
    ) -> Result<HashMap<BinaryName, Checksum>> {
        let res = self.load_sha256sums(repo, &release.tag_name).await?;

        Ok(String::from_utf8(res)?
            .lines()
            .filter_map(|x| x.split_once("  "))
            .map(|(hash, filename)| (filename.to_string(), hash.to_string()))
            .collect())
    }
}
