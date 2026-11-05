//! A small OCI distribution client: resolve a reference, read its config
//! and download its layers.
//!
//! Image references come from job definitions, so the client only ever
//! talks to public addresses (its DNS resolver and redirect policy both
//! refuse anything else) and only anonymously: a credential here would be
//! shared with every job.

use std::{
    collections::HashMap,
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use reqwest::{
    StatusCode, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Self> {
        let (rest, digest) = match s.split_once('@') {
            Some((r, d))
                if d.len() == 71
                    && d.starts_with("sha256:")
                    && d[7..]
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                (r, Some(d.to_string()))
            }
            Some(_) => bail!("image {s:?}: only sha256 digests are supported"),
            None => (s, None),
        };
        // A tag is after the last ':' that follows the last '/'.
        let slash = rest.rfind('/').map_or(0, |i| i + 1);
        let (name, tag) = match rest[slash..].rfind(':') {
            Some(i) => (&rest[..slash + i], Some(rest[slash + i + 1..].to_string())),
            None => (rest, None),
        };
        let (registry, mut repository) = match name.split_once('/') {
            Some((h, r)) if h.contains('.') || h.contains(':') || h == "localhost" => {
                (h.to_string(), r.to_string())
            }
            _ => ("docker.io".to_string(), name.to_string()),
        };
        if registry == "docker.io" && !repository.contains('/') {
            repository = format!("library/{repository}");
        }
        if repository.is_empty()
            || !repository
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/".contains(c))
        {
            bail!("image {s:?}: invalid repository name");
        }
        let tag = if tag.is_none() && digest.is_none() {
            Some("latest".into())
        } else {
            tag
        };
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The canonical name, used as the cache key for tags.
    pub fn name(&self) -> String {
        let mut s = format!("{}/{}", self.registry, self.repository);
        if let Some(t) = &self.tag {
            s += &format!(":{t}");
        }
        if let Some(d) = &self.digest {
            s += &format!("@{d}");
        }
        s
    }

    fn api_host(&self) -> &str {
        if self.registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            &self.registry
        }
    }

    fn reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }
}

/// The parts of an image config ember uses.
#[derive(Debug, Default, Clone, Deserialize, serde::Serialize)]
pub struct ImageConfig {
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
    #[serde(rename = "User", default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

/// A resolved image: what the tag pointed at, the platform manifest, its
/// config and layers.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub head: String,
    pub digest: String,
    pub config: ImageConfig,
    pub layers: Vec<Descriptor>,
}

pub struct Client {
    http: reqwest::Client,
    tokens: Mutex<HashMap<String, String>>,
}

pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    }
}

impl Client {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("ember/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(PublicResolver))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else if let Err(e) = check_url(attempt.url()) {
                    attempt.error(e.to_string())
                } else {
                    attempt.follow()
                }
            }))
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            http,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    /// Sends a request, following the anonymous Bearer token flow on 401.
    async fn send(
        &self,
        r: &Reference,
        method: reqwest::Method,
        url: &str,
        accept: &str,
    ) -> Result<reqwest::Response> {
        let url = Url::parse(url)?;
        check_url(&url)?;
        let key = format!("{}/{}", r.registry, r.repository);
        for attempt in 0..2 {
            let mut req = self
                .http
                .request(method.clone(), url.clone())
                .header(ACCEPT, accept);
            if let Some(t) = self.tokens.lock().unwrap().get(&key) {
                req = req.header(AUTHORIZATION, format!("Bearer {t}"));
            }
            let resp = req.send().await?;
            if resp.status() != StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(resp);
            }
            let challenge = resp
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    anyhow!(
                        "{} asks for credentials; ember pulls anonymously",
                        r.registry
                    )
                })?
                .to_string();
            let token = self.token(&challenge, r).await?;
            self.tokens.lock().unwrap().insert(key.clone(), token);
        }
        unreachable!()
    }

    async fn token(&self, challenge: &str, r: &Reference) -> Result<String> {
        let params = parse_challenge(challenge);
        let realm = params
            .get("realm")
            .ok_or_else(|| anyhow!("auth challenge without realm"))?;
        let mut url = Url::parse(realm)?;
        check_url(&url)?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = params.get("service") {
                q.append_pair("service", s);
            }
            q.append_pair("scope", &format!("repository:{}:pull", r.repository));
        }
        #[derive(Deserialize)]
        struct Token {
            token: Option<String>,
            access_token: Option<String>,
        }
        let resp = self.http.get(url).send().await?.error_for_status()?;
        let t: Token =
            serde_json::from_slice(&read_capped(resp, 64 << 10).await?).context("token")?;
        t.token
            .or(t.access_token)
            .ok_or_else(|| anyhow!("token endpoint returned no token"))
    }

    fn manifest_url(r: &Reference, reference: &str) -> String {
        format!(
            "https://{}/v2/{}/manifests/{reference}",
            r.api_host(),
            r.repository
        )
    }

    /// What the reference points at now, by a HEAD request (registries such
    /// as Docker Hub do not count those against pull limits).
    pub async fn head(&self, r: &Reference) -> Result<String> {
        let resp = self
            .send(
                r,
                reqwest::Method::HEAD,
                &Self::manifest_url(r, r.reference()),
                MANIFEST_TYPES,
            )
            .await?;
        let resp = resp.error_for_status()?;
        resp.headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .ok_or_else(|| anyhow!("registry sent no Docker-Content-Digest"))
    }

    async fn get_manifest(&self, r: &Reference, reference: &str) -> Result<(String, Manifest)> {
        let resp = self
            .send(
                r,
                reqwest::Method::GET,
                &Self::manifest_url(r, reference),
                MANIFEST_TYPES,
            )
            .await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("{}: manifest {reference}: {status}", r.name());
        }
        let body = read_capped(resp, 4 << 20).await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if reference.starts_with("sha256:") && digest != reference {
            bail!("manifest digest mismatch: got {digest}, want {reference}");
        }
        Ok((digest, serde_json::from_slice(&body).context("manifest")?))
    }

    /// Resolves r to this host's platform.
    pub async fn resolve(&self, r: &Reference) -> Result<Resolved> {
        let (head, mut m) = self.get_manifest(r, r.reference()).await?;
        let mut digest = head.clone();
        if !m.manifests.is_empty()
            || m.media_type.contains("index")
            || m.media_type.contains("list")
        {
            let d = m
                .manifests
                .iter()
                .find(|d| {
                    d.platform
                        .as_ref()
                        .is_some_and(|p| p.os == "linux" && p.architecture == arch())
                })
                .ok_or_else(|| anyhow!("{} has no linux/{} image", r.name(), arch()))?
                .digest
                .clone();
            (digest, m) = self.get_manifest(r, &d).await?;
        }
        let config = m.config.ok_or_else(|| anyhow!("manifest has no config"))?;
        let mut raw = Vec::new();
        self.blob(r, &config, 4 << 20, &mut raw).await?;
        #[derive(Deserialize, Default)]
        struct ConfigFile {
            #[serde(default)]
            config: Option<ImageConfig>,
        }
        let cf: ConfigFile = serde_json::from_slice(&raw).context("image config")?;
        Ok(Resolved {
            head,
            digest,
            config: cf.config.unwrap_or_default(),
            layers: m.layers,
        })
    }

    /// Downloads a blob into w, verifying its digest and refusing more than
    /// limit bytes.
    pub async fn blob(
        &self,
        r: &Reference,
        d: &Descriptor,
        limit: u64,
        w: &mut impl Write,
    ) -> Result<()> {
        if d.size > limit {
            bail!("blob {} is {} MiB, over the limit", d.digest, d.size >> 20);
        }
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            r.api_host(),
            r.repository,
            d.digest
        );
        let resp = self
            .send(r, reqwest::Method::GET, &url, "*/*")
            .await?
            .error_for_status()?;
        let mut hasher = Sha256::new();
        let mut n = 0u64;
        let mut body = resp.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            n += chunk.len() as u64;
            if n > limit {
                bail!("blob {} exceeds the size limit", d.digest);
            }
            hasher.update(&chunk);
            w.write_all(&chunk)?;
        }
        let got = format!("sha256:{}", hex::encode(hasher.finalize()));
        if got != d.digest {
            bail!("blob digest mismatch: got {got}, want {}", d.digest);
        }
        Ok(())
    }
}

/// Reads a response body, refusing more than limit bytes: a hostile
/// registry must not make ember buffer gigabytes.
async fn read_capped(resp: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > limit {
            bail!("registry response over {limit} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn parse_challenge(h: &str) -> HashMap<String, String> {
    let rest = h.trim_start_matches("Bearer").trim();
    let mut out = HashMap::new();
    let mut s = rest;
    while let Some((k, v)) = s.split_once('=') {
        let k = k.trim().trim_start_matches(',').trim().to_string();
        let v = v.trim_start();
        let (val, tail) = if let Some(v) = v.strip_prefix('"') {
            let end = v.find('"').unwrap_or(v.len());
            (&v[..end], &v[(end + 1).min(v.len())..])
        } else {
            let end = v.find(',').unwrap_or(v.len());
            (&v[..end], &v[end..])
        };
        out.insert(k, val.to_string());
        s = tail;
    }
    out
}

/// Refuses URLs that are not https or that name a non-public IP literal.
/// Names are checked by the resolver.
fn check_url(u: &Url) -> Result<()> {
    if u.scheme() != "https" {
        bail!("refusing {} URL {u}: registries must use https", u.scheme());
    }
    let ip = match u.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => return Ok(()),
    };
    if !public(ip) {
        bail!("refusing to contact non-public address {ip}");
    }
    Ok(())
}

struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 443))
                .await?
                .collect();
            let ok: Vec<SocketAddr> = addrs.iter().copied().filter(|a| public(a.ip())).collect();
            if ok.is_empty() {
                let msg =
                    format!("refusing to contact {host}: it resolves only to non-public addresses");
                return Err(msg.into());
            }
            Ok(Box::new(ok.into_iter()) as Addrs)
        })
    }
}

/// Whether ip is a globally routable unicast address.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public4(v4);
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64
                || v6 == Ipv6Addr::UNSPECIFIED)
        }
    }
}

fn public4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT, the tailnet
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking
        || o[0] >= 240)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(r.name(), "docker.io/library/alpine:latest");
        let r = Reference::parse("docker.io/library/node:24-trixie").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str(), r.tag.as_deref()),
            ("docker.io", "library/node", Some("24-trixie"))
        );
        let r = Reference::parse("ghcr.io/o/r:v1").unwrap();
        assert_eq!(r.api_host(), "ghcr.io");
        let r = Reference::parse("127.0.0.1:8317/x:y").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.tag.as_deref()),
            ("127.0.0.1:8317", Some("y"))
        );
        let d = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("alpine@{d}")).unwrap();
        assert_eq!((r.tag, r.digest), (None, Some(d)));
        assert!(Reference::parse("UPPER/case").is_err());
    }

    #[test]
    fn public_addresses() {
        for (ip, want) in [
            ("1.1.1.1", true),
            ("2606:4700::1111", true),
            ("127.0.0.1", false),
            ("10.1.2.3", false),
            ("192.168.1.11", false),
            ("172.30.0.1", false),
            ("100.100.100.100", false),
            ("169.254.169.254", false),
            ("::1", false),
            ("fd7a:115c:a1e0::1", false),
            ("fe80::1", false),
            ("::ffff:127.0.0.1", false),
            ("0.0.0.0", false),
            ("64:ff9b::a00:1", false),
        ] {
            assert_eq!(public(ip.parse().unwrap()), want, "{ip}");
        }
    }

    #[test]
    fn urls() {
        assert!(check_url(&Url::parse("https://127.0.0.1:8317/v2/").unwrap()).is_err());
        assert!(check_url(&Url::parse("http://example.com/").unwrap()).is_err());
        assert!(check_url(&Url::parse("https://[::1]/").unwrap()).is_err());
        assert!(check_url(&Url::parse("https://registry-1.docker.io/v2/").unwrap()).is_ok());
    }

    #[test]
    fn challenge() {
        let c = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        );
        assert_eq!(c["realm"], "https://auth.docker.io/token");
        assert_eq!(c["service"], "registry.docker.io");
    }
}
