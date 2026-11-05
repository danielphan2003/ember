//! Turns OCI images into bootable ext4 root filesystems, cached by digest.
//!
//! A cached image is built once: the layers are unpacked into a directory
//! (whiteouts applied, every write confined by cap-std), the guest agent is
//! added at /.ember/agent, and `mke2fs -d` writes the filesystem from that
//! directory inside a user namespace where the current user is root.
//! `debugfs` then restores the few owners and modes an unprivileged unpack
//! cannot. Each VM boots from a copy-on-write clone of the result.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::CString,
    fs::{self, File, Permissions},
    io::{self, Read, Seek, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use cap_std::{ambient_authority, fs::Dir};
use futures_util::{FutureExt, future::Shared};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    agent::tarfs::clean,
    registry::{Client, Descriptor, Reference},
};

/// A cached, bootable root filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    pub reference: String,
    pub digest: String,
    #[serde(skip)]
    pub rootfs: PathBuf,
    pub env: Vec<String>,
    pub working_dir: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefEntry {
    digest: String,
    head: String,
    checked: SystemTime,
}

pub type Progress = Arc<dyn Fn(String) + Send + Sync>;
type Pull = Shared<futures_util::future::BoxFuture<'static, Result<Image, Arc<anyhow::Error>>>>;

pub struct Store {
    dir: PathBuf,
    agent: &'static [u8],
    agent_id: String,
    refresh: Duration,
    min_bytes: u64,
    max_bytes: u64,
    client: Arc<Client>,
    pulls: Mutex<HashMap<String, Pull>>,
    refs_lock: Mutex<()>,
    /// One image build at a time: each can need tens of GiB of scratch
    /// space on a disk shared with the host's services.
    builds: tokio::sync::Semaphore,
    min_free: u64,
}

impl Store {
    pub fn new(
        dir: PathBuf,
        agent: &'static [u8],
        refresh: Duration,
        min_gib: u32,
        max_mib: u64,
        min_free_gib: u64,
    ) -> Result<Arc<Self>> {
        let agent_id = hex::encode(&Sha256::digest(agent)[..6]);
        Ok(Arc::new(Self {
            dir,
            agent,
            agent_id,
            refresh,
            min_bytes: u64::from(min_gib) << 30,
            max_bytes: max_mib << 20,
            client: Arc::new(Client::new()?),
            pulls: Mutex::new(HashMap::new()),
            refs_lock: Mutex::new(()),
            builds: tokio::sync::Semaphore::new(1),
            min_free: min_free_gib << 30,
        }))
    }

    fn refs_path(&self) -> PathBuf {
        self.dir.join("refs.json")
    }

    fn load_refs(&self) -> HashMap<String, RefEntry> {
        fs::read(self.refs_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_ref(&self, name: &str, e: RefEntry) {
        let _g = self.refs_lock.lock().unwrap();
        let mut refs = self.load_refs();
        refs.insert(name.into(), e);
        let tmp = self.refs_path().with_extension("tmp");
        if fs::write(&tmp, serde_json::to_vec_pretty(&refs).unwrap_or_default()).is_ok() {
            let _ = fs::rename(tmp, self.refs_path());
        }
    }

    /// An image's cache directory is named after its digest and the agent
    /// baked into it, so upgrading ember rebuilds images with the new agent.
    fn dir_for(&self, digest: &str) -> PathBuf {
        self.dir.join(format!(
            "{}-agent-{}",
            digest.replace(':', "-"),
            self.agent_id
        ))
    }

    fn load(&self, digest: &str) -> Result<Image> {
        let dir = self.dir_for(digest);
        let mut img: Image = serde_json::from_slice(&fs::read(dir.join("meta.json"))?)?;
        img.rootfs = dir.join("rootfs.ext4");
        fs::metadata(&img.rootfs)?;
        // Marks the image as recently used for pruning.
        let _ = File::open(&dir).and_then(|f| f.set_modified(SystemTime::now()));
        Ok(img)
    }

    /// Returns the cached image for reference, pulling and building it if
    /// needed. A pull is shared by every job waiting for the same image and
    /// is not aborted when one of them is cancelled.
    pub async fn ensure(self: &Arc<Self>, reference: &str, progress: Progress) -> Result<Image> {
        let r = Reference::parse(reference)?;
        let name = r.name();
        if let Some(d) = &r.digest {
            if let Ok(img) = self.load(d) {
                return Ok(img);
            }
        } else if let Some(e) = self.load_refs().get(&name)
            && e.checked.elapsed().unwrap_or(Duration::MAX) < self.refresh
            && let Ok(img) = self.load(&e.digest)
        {
            return Ok(img);
        }

        let pull = {
            let mut pulls = self.pulls.lock().unwrap();
            pulls
                .entry(name.clone())
                .or_insert_with(|| {
                    let store = self.clone();
                    let (r, name) = (r.clone(), name.clone());
                    let task = tokio::spawn(async move {
                        // Forget this pull however the task ends, panics included.
                        let _forget = Forget(store.clone(), name);
                        // Dropping the pull on timeout sets the flag, which stops
                        // the unpack and kills mke2fs or debugfs.
                        let cancel = Cancel::default();
                        tokio::time::timeout(
                            Duration::from_secs(1800),
                            store.refresh_or_pull(&r, progress, cancel.flag()),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Err(anyhow!("pulling {} took over 30 minutes", r.name()))
                        })
                    });
                    async move {
                        task.await
                            .map_err(|e| Arc::new(anyhow!(e)))?
                            .map_err(Arc::new)
                    }
                    .boxed()
                    .shared()
                })
                .clone()
        };
        match pull.await {
            Ok(img) => Ok(img),
            Err(e) => {
                // A registry outage should not stop jobs whose image is cached.
                if let Some(entry) = self.load_refs().get(&name)
                    && let Ok(img) = self.load(&entry.digest)
                {
                    return Ok(img);
                }
                Err(anyhow!("{e:#}"))
            }
        }
    }

    async fn refresh_or_pull(
        self: &Arc<Self>,
        r: &Reference,
        progress: Progress,
        cancel: Arc<AtomicBool>,
    ) -> Result<Image> {
        let name = r.name();
        if let Some(e) = self.load_refs().get(&name).cloned()
            && let Ok(head) = self.client.head(r).await
            && head == e.head
            && let Ok(img) = self.load(&e.digest)
        {
            self.save_ref(
                &name,
                RefEntry {
                    checked: SystemTime::now(),
                    ..e
                },
            );
            return Ok(img);
        }
        self.pull(r, progress, cancel).await
    }

    async fn pull(
        self: &Arc<Self>,
        r: &Reference,
        progress: Progress,
        cancel: Arc<AtomicBool>,
    ) -> Result<Image> {
        let resolved = self
            .client
            .resolve(r)
            .await
            .with_context(|| format!("resolve {}", r.name()))?;
        let entry = RefEntry {
            digest: resolved.digest.clone(),
            head: resolved.head.clone(),
            checked: SystemTime::now(),
        };
        if let Ok(img) = self.load(&resolved.digest) {
            self.save_ref(&r.name(), entry);
            return Ok(img);
        }
        let _build = match self.builds.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                progress("waiting for another image build to finish".into());
                self.builds.acquire().await?
            }
        };
        self.check_free_space(0)?;
        progress(format!("pulling {} ({})", r.name(), resolved.digest));
        let started = std::time::Instant::now();
        fs::create_dir_all(&self.dir)?;
        let tmp = tempfile::Builder::new()
            .prefix(".build-")
            .tempdir_in(&self.dir)?;
        let tree = tmp.path().join("tree");
        fs::create_dir(&tree)?;

        let mut unpack = Unpack::new(&tree, self.max_bytes, cancel.clone())?;
        // Compressed layers count against the same budget as the unpacked
        // image, so a hostile image cannot fill the disk with downloads.
        let mut downloaded = 0u64;
        for (i, layer) in resolved.layers.iter().enumerate() {
            let mut blob = tempfile::tempfile_in(tmp.path())?;
            let budget = self.max_bytes.saturating_sub(downloaded);
            self.client.blob(r, layer, budget, &mut blob).await?;
            downloaded += blob.metadata()?.len();
            blob.rewind()?;
            let (layer, n) = (layer.clone(), resolved.layers.len());
            unpack = tokio::task::spawn_blocking(move || -> Result<Unpack> {
                unpack.layer(decompress(&layer, blob)?)?;
                Ok(unpack)
            })
            .await??;
            if n > 1 {
                progress(format!("layer {}/{n} unpacked", i + 1));
            }
        }
        let (fixups, size) = unpack.finish(self.agent)?;
        progress(format!(
            "building root filesystem ({} MiB, {} ownership fixups)",
            size >> 20,
            fixups.len()
        ));

        // Leave room for the job: at least disk_gib, and half again the content.
        let fs_bytes = self.min_bytes.max(size + size / 2 + (512 << 20));
        // The new filesystem must fit above the floor too. It is sparse, so
        // it takes about the content's size, not its nominal size.
        self.check_free_space(size)?;
        let ext4 = tmp.path().join("rootfs.ext4");
        let (tree2, ext42) = (tree.clone(), ext4.clone());
        tokio::task::spawn_blocking(move || build_ext4(&tree2, &ext42, fs_bytes, &fixups, &cancel))
            .await??;
        fs::remove_dir_all(&tree).context("remove unpacked tree")?;

        let img = Image {
            reference: r.name(),
            digest: resolved.digest.clone(),
            rootfs: PathBuf::new(),
            env: resolved.config.env.unwrap_or_default(),
            working_dir: resolved.config.working_dir.unwrap_or_default(),
            user: resolved.config.user.unwrap_or_default(),
        };
        fs::write(
            tmp.path().join("meta.json"),
            serde_json::to_vec_pretty(&img)?,
        )?;
        let final_dir = self.dir_for(&resolved.digest);
        let tmp_path = tmp.keep();
        if let Err(e) = fs::rename(&tmp_path, &final_dir) {
            let _ = fs::remove_dir_all(&tmp_path);
            // Another process may have won the race; use its copy if whole.
            if self.load(&resolved.digest).is_err() {
                return Err(e).context("install image");
            }
        }
        self.save_ref(&r.name(), entry);
        progress(format!(
            "image ready in {:.1}s",
            started.elapsed().as_secs_f64()
        ));
        self.load(&resolved.digest)
    }

    /// Refuses to go on unless `need` bytes fit above min_free_gib in the
    /// cache's filesystem.
    fn check_free_space(&self, need: u64) -> Result<()> {
        let c = CString::new(self.dir.as_os_str().as_encoded_bytes())?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
            let free = st.f_bavail * st.f_frsize;
            if free < self.min_free.saturating_add(need) {
                bail!(
                    "only {} GiB free for images, {} GiB needed above min_free_gib {}; not building",
                    free >> 30,
                    need.div_ceil(1 << 30),
                    self.min_free >> 30
                );
            }
        }
        Ok(())
    }

    /// Removes cached images not used within keep, and stale build
    /// directories. Returns what it removed.
    pub fn prune(&self, keep: Duration) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return vec![];
        };
        let mut removed = vec![];
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(md) = e.metadata() else { continue };
            if !md.is_dir() {
                continue;
            }
            let age = md
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .unwrap_or_default();
            let limit = if name.starts_with(".build-") {
                Duration::from_secs(86400)
            } else {
                keep
            };
            if age > limit && fs::remove_dir_all(e.path()).is_ok() {
                removed.push(name);
            }
        }
        removed
    }
}

/// Removes a pull from the in-flight table when dropped.
struct Forget(Arc<Store>, String);

impl Drop for Forget {
    fn drop(&mut self) {
        self.0.pulls.lock().unwrap().remove(&self.1);
    }
}

/// Sets its flag when dropped, so blocking work for an abandoned pull stops.
#[derive(Default)]
struct Cancel(Arc<AtomicBool>);

impl Cancel {
    fn flag(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
}

impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn decompress(d: &Descriptor, f: File) -> Result<Box<dyn Read + Send>> {
    let t = d.media_type.as_str();
    Ok(if t.ends_with("gzip") || t.ends_with("+gzip") {
        Box::new(flate2::read::MultiGzDecoder::new(io::BufReader::new(f)))
    } else if t.ends_with("zstd") {
        Box::new(
            ruzstd::decoding::StreamingDecoder::new(io::BufReader::new(f))
                .map_err(|e| anyhow!("zstd: {e}"))?,
        )
    } else if t.ends_with(".tar") || t.ends_with("layer.v1.tar") {
        Box::new(f)
    } else {
        bail!("unsupported layer type {t:?}")
    })
}

/// Metadata the unprivileged unpack could not reproduce; debugfs writes it
/// into the finished filesystem.
#[derive(Debug, Clone, PartialEq)]
pub struct Fixup {
    pub path: String,
    pub uid: u64,
    pub gid: u64,
    pub mode: u32, // full st_mode, type bits included
}

/// Applies image layers to a directory.
///
/// Files are written with owner-writable modes so the tree stays removable;
/// mke2fs later records every file as root's, so entries that need another
/// owner or a mode the unpack relaxed become fixups. Device nodes are
/// skipped (the guest mounts devtmpfs), and so are extended attributes.
pub struct Unpack {
    root: Dir,
    fixups: BTreeMap<PathBuf, Fixup>,
    size: u64,
    limit: u64,
    cancel: Arc<AtomicBool>,
}

/// Largest GNU long name or PAX header accepted. The tar crate would read
/// any size into memory; these are a few hundred bytes in real images.
const MAX_META: u64 = 1 << 20;
const PATH_MAX: usize = 4096;

impl Unpack {
    pub fn new(tree: &Path, limit: u64, cancel: Arc<AtomicBool>) -> Result<Self> {
        Ok(Self {
            root: Dir::open_ambient_dir(tree, ambient_authority())?,
            fixups: BTreeMap::new(),
            size: 0,
            limit,
            cancel,
        })
    }

    fn remove(&mut self, p: &Path) {
        if self.root.symlink_metadata(p).is_err() {
            return; // nothing there, so no fixups under it either
        }
        if self.root.remove_dir_all(p).is_err() {
            let _ = self.root.remove_file(p);
        }
        // Fixups at or below p sort together, from p onwards.
        let doomed: Vec<PathBuf> = self
            .fixups
            .range(p.to_path_buf()..)
            .map(|(k, _)| k)
            .take_while(|k| k.starts_with(p))
            .cloned()
            .collect();
        for k in doomed {
            self.fixups.remove(&k);
        }
    }

    /// Creates a directory and any missing ancestors as 0755, whatever the
    /// process umask: layers often omit entries for parent directories.
    fn ensure_dir(&self, dir: &Path) -> Result<()> {
        // A loop, not recursion: a hostile path may have thousands of
        // components.
        let missing: Vec<&Path> = dir
            .ancestors()
            .take_while(|a| !a.as_os_str().is_empty() && self.root.symlink_metadata(a).is_err())
            .collect();
        for d in missing.into_iter().rev() {
            if let Err(e) = self.root.create_dir(d)
                && e.kind() != io::ErrorKind::AlreadyExists
            {
                return Err(e.into());
            }
            self.root.set_permissions(d, perms(0o755))?;
        }
        Ok(())
    }

    /// Applies one layer. GNU long names and PAX headers are handled here,
    /// with a size cap, rather than by the tar crate.
    pub fn layer(&mut self, r: impl Read) -> Result<()> {
        let mut ar = tar::Archive::new(r);
        let mut added: HashSet<PathBuf> = HashSet::new();
        let (mut long_name, mut long_link): (Option<PathBuf>, Option<PathBuf>) = (None, None);
        let mut pax_size: Option<u64> = None;
        // Owners too large for the header field (over 2097151) come in PAX.
        let (mut pax_uid, mut pax_gid): (Option<u64>, Option<u64>) = (None, None);
        for entry in ar.entries()?.raw(true) {
            if self.cancel.load(Ordering::Relaxed) {
                bail!("cancelled");
            }
            let mut e = entry?;
            let kind = e.header().entry_type();
            // Registry layers never use sparse members; refuse rather than
            // silently drop or misread them.
            if kind.is_gnu_sparse() {
                bail!("sparse tar members are not supported");
            }
            if kind.is_gnu_longname()
                || kind.is_gnu_longlink()
                || kind.is_pax_local_extensions()
                || kind.is_pax_global_extensions()
            {
                if e.header().size()? > MAX_META {
                    bail!("tar metadata entry over {MAX_META} bytes");
                }
                let mut buf = Vec::new();
                (&mut e).take(MAX_META).read_to_end(&mut buf)?;
                let text = |b: &[u8]| {
                    use std::os::unix::ffi::OsStrExt;
                    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                    PathBuf::from(std::ffi::OsStr::from_bytes(&b[..end]))
                };
                if kind.is_gnu_longname() {
                    long_name = Some(text(&buf));
                } else if kind.is_gnu_longlink() {
                    long_link = Some(text(&buf));
                } else if kind.is_pax_local_extensions() {
                    for ext in tar::PaxExtensions::new(&buf) {
                        let ext = ext?;
                        match ext.key() {
                            Ok("path") => long_name = Some(text(ext.value_bytes())),
                            Ok("linkpath") => long_link = Some(text(ext.value_bytes())),
                            Ok(k @ ("uid" | "gid")) => {
                                let v = ext.value().ok().and_then(|v| v.parse().ok());
                                let v = Some(v.ok_or_else(|| anyhow!("unparseable PAX {k}"))?);
                                if k == "uid" {
                                    pax_uid = v;
                                } else {
                                    pax_gid = v;
                                }
                            }
                            Ok("size") => {
                                let v = ext.value().ok().and_then(|v| v.parse().ok());
                                pax_size = Some(v.ok_or_else(|| anyhow!("unparseable PAX size"))?);
                            }
                            _ => {}
                        }
                    }
                }
                continue;
            }
            if let Some(size) = pax_size.take()
                && size != e.header().size()?
            {
                bail!("PAX size {size} disagrees with the tar header");
            }
            let path = match long_name.take() {
                Some(p) => p,
                None => e.path()?.into_owned(),
            };
            let link = match long_link.take() {
                Some(p) => Some(p),
                None => e.link_name()?.map(|l| l.into_owned()),
            };
            // The kernel cannot use longer paths anyway.
            for p in std::iter::once(&path).chain(link.as_ref()) {
                if p.as_os_str().len() > PATH_MAX {
                    bail!("tar entry path over {PATH_MAX} bytes");
                }
            }
            let owner = (pax_uid.take(), pax_gid.take());
            let shown = path.display().to_string();
            self.entry(&mut e, &path, link, owner, &mut added)
                .with_context(|| format!("unpack {shown}"))?;
        }
        Ok(())
    }

    fn entry<R: Read>(
        &mut self,
        e: &mut tar::Entry<R>,
        raw_path: &Path,
        link: Option<PathBuf>,
        owner: (Option<u64>, Option<u64>),
        added: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        {
            let h = e.header().clone();
            let path = clean(raw_path);
            let Some(base) = path.file_name().map(|b| b.to_string_lossy().into_owned()) else {
                return Ok(());
            };
            if path.starts_with(".ember") {
                return Ok(()); // ember's own directory
            }
            let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();

            // Whiteouts hide entries from lower layers.
            if base == ".wh..wh..opq" {
                if let Ok(rd) = self.root.read_dir(if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    &parent
                }) {
                    for child in rd.flatten() {
                        let p = parent.join(child.file_name());
                        if !added.contains(&p) {
                            self.remove(&p);
                        }
                    }
                }
                return Ok(());
            }
            if let Some(hidden) = base.strip_prefix(".wh.") {
                self.remove(&parent.join(hidden));
                return Ok(());
            }

            if !parent.as_os_str().is_empty() {
                self.ensure_dir(&parent)?;
            }
            let perm = h.mode().unwrap_or(0o644) & 0o7777;
            let (ftype, written) =
                match h.entry_type() {
                    tar::EntryType::Directory => {
                        if self.root.symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
                            self.remove(&path);
                        }
                        self.root.create_dir_all(&path)?;
                        self.root.set_permissions(&path, perms(0o755))?;
                        (libc::S_IFDIR, 0o755)
                    }
                    tar::EntryType::Regular | tar::EntryType::Continuous => {
                        self.remove(&path);
                        let mut f = self.root.create(&path)?;
                        let budget = self.limit.saturating_sub(self.size) + 1;
                        let n = io::copy(&mut e.take(budget), &mut f)?;
                        self.size += n;
                        if self.size > self.limit {
                            bail!(
                                "image is larger than the {} MiB limit (max_image_mib)",
                                self.limit >> 20
                            );
                        }
                        let written = perm & 0o777 | 0o600;
                        f.set_permissions(perms(written))?;
                        // A hostile header may carry any 64-bit time: skip what
                        // does not fit rather than overflow.
                        if let Some(t) = h.mtime().ok().and_then(|m| {
                            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(m))
                        }) {
                            let _ = f.into_std().set_modified(t);
                        }
                        (libc::S_IFREG, written)
                    }
                    tar::EntryType::Symlink => {
                        self.remove(&path);
                        let target = link.ok_or_else(|| anyhow!("symlink without target"))?;
                        self.root.symlink_contents(target, &path)?;
                        (libc::S_IFLNK, 0o777)
                    }
                    tar::EntryType::Link => {
                        let src = clean(&link.ok_or_else(|| anyhow!("hardlink without target"))?);
                        self.remove(&path);
                        self.root
                            .hard_link(&src, &self.root, &path)
                            .with_context(|| format!("hardlink {}", path.display()))?;
                        added.insert(path);
                        return Ok(()); // shares the inode, and its fixup, with src
                    }
                    _ => return Ok(()),
                };
            self.size += 512;
            let perm = if ftype == libc::S_IFLNK { 0o777 } else { perm };
            let uid = owner.0.unwrap_or_else(|| h.uid().unwrap_or(0));
            let gid = owner.1.unwrap_or_else(|| h.gid().unwrap_or(0));
            if uid != 0 || gid != 0 || perm != written {
                let p = format!("/{}", path.display());
                self.fixups.insert(
                    path.clone(),
                    Fixup {
                        path: p,
                        uid,
                        gid,
                        mode: ftype | perm,
                    },
                );
            } else {
                self.fixups.remove(&path);
            }
            added.insert(path);
        }
        Ok(())
    }

    /// Installs the agent and returns the fixups and the content size.
    pub fn finish(self, agent: &[u8]) -> Result<(Vec<Fixup>, u64)> {
        if agent.is_empty() {
            bail!("ember was built without the guest agent (build with `just build`)");
        }
        let _ = self.root.remove_dir_all(".ember");
        let _ = self.root.remove_file(".ember");
        self.root.create_dir(".ember")?;
        let mut f = self.root.create(".ember/agent")?;
        f.write_all(agent)?;
        f.set_permissions(perms(0o755))?;
        let mut fixups: Vec<Fixup> = self.fixups.into_values().collect();
        fixups.sort_by(|a, b| a.path.cmp(&b.path));
        Ok((fixups, self.size + agent.len() as u64))
    }
}

fn perms(mode: u32) -> cap_std::fs::Permissions {
    cap_std::fs::Permissions::from_std(Permissions::from_mode(mode))
}

/// Makes an ext4 image of the given size from dir, then applies fixups. It
/// needs only e2fsprogs (1.47.1 or newer) and unprivileged user namespaces.
pub fn build_ext4(
    dir: &Path,
    out: &Path,
    size: u64,
    fixups: &[Fixup],
    cancel: &AtomicBool,
) -> Result<()> {
    let mut cmd = Command::new("mke2fs");
    cmd.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-m",
        "0",
        "-L",
        "ember",
        "-O",
        "^has_journal",
    ])
    .args(["-E", "root_owner=0:0,lazy_itable_init=1,nodiscard", "-d"])
    .arg(dir)
    .arg(out)
    .arg(format!("{}k", size >> 10));
    // Inside a new user namespace where the current user is uid 0, mke2fs
    // records every unpacked file as owned by root.
    let maps = [
        (
            CString::new("/proc/self/setgroups").unwrap(),
            b"deny".to_vec(),
        ),
        (
            CString::new("/proc/self/uid_map").unwrap(),
            format!("0 {} 1", unsafe { libc::getuid() }).into_bytes(),
        ),
        (
            CString::new("/proc/self/gid_map").unwrap(),
            format!("0 {} 1", unsafe { libc::getgid() }).into_bytes(),
        ),
    ];
    unsafe {
        // Only async-signal-safe calls between fork and exec: the strings
        // above are built before forking.
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(io::Error::last_os_error());
            }
            for (path, data) in &maps {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = libc::write(fd, data.as_ptr().cast(), data.len());
                libc::close(fd);
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let (status, stderr) = run_cancellable(&mut cmd, out, cancel).context("run mke2fs")?;
    if !status.success() {
        bail!("mke2fs: {status}: {}", stderr.trim());
    }
    if fixups.is_empty() {
        return Ok(());
    }
    let mut script = String::new();
    for f in fixups {
        if f.path.contains(['"', '\n', '\\']) {
            continue; // debugfs cannot quote these; they stay root's
        }
        let q = format!("\"{}\"", f.path);
        if f.uid != 0 {
            script += &format!("sif {q} uid {}\n", f.uid);
        }
        if f.gid != 0 {
            script += &format!("sif {q} gid {}\n", f.gid);
        }
        script += &format!("sif {q} mode 0{:o}\n", f.mode);
    }
    // The script goes in a file and debugfs's echo of each command to
    // /dev/null: piping both ways deadlocks once the echo fills the pipe.
    let script_path = out.with_extension("debugfs");
    fs::write(&script_path, script)?;
    let mut cmd = Command::new("debugfs");
    cmd.arg("-w").arg("-f").arg(&script_path).arg(out);
    let res = run_cancellable(&mut cmd, out, cancel).context("run debugfs");
    let _ = fs::remove_file(&script_path);
    let (status, stderr) = res?;
    // debugfs exits 0 even when a command fails; failures go to stderr,
    // after its version banner.
    let errors: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("debugfs "))
        .collect();
    if !status.success() || !errors.is_empty() {
        bail!("debugfs: {status}: {}", errors.join("; "));
    }
    Ok(())
}

/// Runs cmd with stdout discarded and stderr kept in a file next to `near`,
/// killing it if `cancel` is set.
fn run_cancellable(
    cmd: &mut Command,
    near: &Path,
    cancel: &AtomicBool,
) -> Result<(std::process::ExitStatus, String)> {
    let err_path = near.with_extension("stderr");
    let err_file = File::create(&err_path)?;
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(err_file)
        .spawn()?;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&err_path);
            bail!("cancelled");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stderr = fs::read_to_string(&err_path).unwrap_or_default();
    let _ = fs::remove_file(&err_path);
    Ok((status, stderr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(entries: &[(&str, tar::EntryType, u32, u64, u64, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for &(name, kind, mode, uid, gid, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_uid(uid);
            h.set_gid(gid);
            h.set_mtime(1);
            let body: &[u8] = if kind == tar::EntryType::Regular {
                b"hi"
            } else {
                b""
            };
            h.set_size(body.len() as u64);
            if kind == tar::EntryType::Symlink || kind == tar::EntryType::Link {
                b.append_link(&mut h, name, link).unwrap();
            } else {
                b.append_data(&mut h, name, body).unwrap();
            }
        }
        b.into_inner().unwrap()
    }

    use tar::EntryType::{Directory as D, Link as L, Regular as F, Symlink as S};

    #[test]
    fn fixups_and_whiteouts() {
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        u.layer(
            &layer(&[
                ("etc/", D, 0o755, 0, 0, ""),
                ("etc/plain", F, 0o644, 0, 0, ""),
                ("etc/shadow", F, 0o640, 0, 42, ""),
                ("usr/bin/su", F, 0o4755, 0, 0, ""),
                ("home/node/", D, 0o700, 1000, 1000, ""),
                ("bin", S, 0o777, 0, 0, "usr/bin"),
                ("sbin/sh", S, 0o777, 0, 0, "/bin/busybox"),
                ("usr/bin/su2", L, 0o4755, 0, 0, "usr/bin/su"),
                ("old/gone", F, 0o644, 0, 0, ""),
                ("opq/lower", F, 0o644, 0, 0, ""),
                (".ember/agent", F, 0o755, 0, 0, ""),
            ])[..],
        )
        .unwrap();
        u.layer(
            &layer(&[
                ("old/.wh.gone", F, 0o644, 0, 0, ""),
                ("opq/upper", F, 0o644, 0, 0, ""),
                ("opq/.wh..wh..opq", F, 0o644, 0, 0, ""),
            ])[..],
        )
        .unwrap();
        let (fixups, _) = u.finish(b"agent").unwrap();
        let by: HashMap<_, _> = fixups.iter().map(|f| (f.path.as_str(), f)).collect();
        assert!(!by.contains_key("/etc/plain"));
        assert_eq!(
            (by["/etc/shadow"].gid, by["/etc/shadow"].mode),
            (42, libc::S_IFREG | 0o640)
        );
        assert_eq!(by["/usr/bin/su"].mode, libc::S_IFREG | 0o4755);
        assert_eq!(
            (by["/home/node"].uid, by["/home/node"].mode),
            (1000, libc::S_IFDIR | 0o700)
        );
        let p = dir.path();
        assert_eq!(
            fs::read_link(p.join("sbin/sh")).unwrap(),
            Path::new("/bin/busybox"),
            "absolute symlinks are kept"
        );
        assert!(!p.join("old/gone").exists(), "whiteout");
        assert!(
            !p.join("opq/lower").exists() && p.join("opq/upper").exists(),
            "opaque whiteout"
        );
        assert_eq!(
            fs::read(p.join(".ember/agent")).unwrap(),
            b"agent",
            "image cannot supply the agent"
        );
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(p.join("usr/bin/su")).unwrap().ino(),
            fs::metadata(p.join("usr/bin/su2")).unwrap().ino()
        );
    }

    #[test]
    fn cannot_escape_through_symlink() {
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        let res = u.layer(
            &layer(&[
                ("evil", S, 0o777, 0, 0, outside.path().to_str().unwrap()),
                ("evil/pwned", F, 0o644, 0, 0, ""),
            ])[..],
        );
        assert!(res.is_err());
        assert!(
            !outside.path().join("pwned").exists(),
            "wrote outside the root"
        );
    }

    #[test]
    fn size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 3, Default::default()).unwrap();
        assert!(
            u.layer(&layer(&[("a", F, 0o644, 0, 0, ""), ("b", F, 0o644, 0, 0, "")])[..])
                .is_err()
        );
    }

    #[test]
    fn hostile_tar_headers() {
        // A binary-encoded mtime of 2^64-1 must not overflow.
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(F);
        h.set_mode(0o644);
        h.set_size(2);
        h.set_path("f").unwrap();
        let m = &mut h.as_gnu_mut().unwrap().mtime;
        m[0] = 0x80;
        m[4..].copy_from_slice(&u64::MAX.to_be_bytes());
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, &b"hi"[..]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        u.layer(&b.into_inner().unwrap()[..]).unwrap();

        // A long name of normal size works; a 2 MiB one is refused.
        let long = format!("d/{}file", "abcdefghij/".repeat(20));
        let ok = layer(&[(&long, F, 0o644, 0, 0, "")]);
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        u.layer(&ok[..]).unwrap();
        assert!(dir.path().join(&long).exists());

        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNULongName);
        h.set_path("././@LongLink").unwrap();
        h.set_size(2 << 20);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, &vec![b'a'; 2 << 20][..]).unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 30, Default::default()).unwrap();
        assert!(u.layer(&b.into_inner().unwrap()[..]).is_err());
    }

    #[test]
    fn removing_a_directory_drops_only_its_fixups() {
        // Path orders by component, so "usr/..." sorts before "usr0".
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        u.layer(
            &layer(&[
                ("usr/x", F, 0o640, 0, 42, ""),
                ("usr/y/z", F, 0o640, 0, 42, ""),
                ("usr0", F, 0o640, 0, 42, ""),
            ])[..],
        )
        .unwrap();
        u.layer(&layer(&[(".wh.usr", F, 0o644, 0, 0, "")])[..])
            .unwrap();
        let (fixups, _) = u.finish(b"agent").unwrap();
        let paths: Vec<_> = fixups.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/usr0"]);
    }

    #[test]
    fn deep_long_names_are_refused_not_recursed() {
        let deep = format!("{}f", "a/".repeat(20_000));
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNULongName);
        h.set_path("././@LongLink").unwrap();
        h.set_size(deep.len() as u64 + 1);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        let mut name = deep.into_bytes();
        name.push(0);
        b.append(&h, &name[..]).unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_entry_type(F);
        f.set_path("placeholder").unwrap();
        f.set_size(0);
        f.set_cksum();
        b.append(&f, &b""[..]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut u = Unpack::new(dir.path(), 1 << 20, Default::default()).unwrap();
        assert!(u.layer(&b.into_inner().unwrap()[..]).is_err());
    }
}
