//! Tar in and out of the guest filesystem. Extraction goes through a
//! cap-std directory handle, so neither `../` names nor symlinks can place a
//! file outside the destination.

use std::{
    fs::Permissions,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};

use cap_std::{ambient_authority, fs::Dir};
use tokio::sync::mpsc::Sender;
use tonic::Status;

use crate::pb::CopyOutChunk;

/// Reads the byte chunks a CopyIn stream delivers.
pub struct ChanReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChanReader {
    /// Use from a blocking task: reads block on the channel.
    pub fn new(rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            match self.rx.blocking_recv() {
                Some(b) => {
                    self.buf = b;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

const CHUNK: usize = 256 << 10;

/// Sends a tar stream as CopyOut chunks.
pub struct ChunkWriter {
    tx: Sender<Result<CopyOutChunk, Status>>,
    buf: Vec<u8>,
}

impl ChunkWriter {
    pub fn new(tx: Sender<Result<CopyOutChunk, Status>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(CHUNK),
        }
    }

    fn send(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK));
        self.tx
            .blocking_send(Ok(CopyOutChunk { data }))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "copyout stream closed"))
    }
}

impl Write for ChunkWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= CHUNK {
            self.send()?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.send()
    }
}

/// Archives src: a directory's contents, or a single file under its base
/// name. A missing path yields an empty archive, which the runner treats as
/// "not there" (it reads env files and action.yml/action.yaml this way).
pub fn tar_path(src: &Path, w: impl Write) -> io::Result<()> {
    let mut b = tar::Builder::new(w);
    b.follow_symlinks(false);
    match std::fs::symlink_metadata(src) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(md) if md.is_dir() => b.append_dir_all(".", src)?,
        Ok(_) => {
            let name = src
                .file_name()
                .ok_or_else(|| io::Error::other("no file name"))?;
            b.append_path_with_name(src, name)?;
        }
    }
    b.into_inner()?.flush()
}

/// Turns an archive entry name into a relative path with no `..`.
pub fn clean(name: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in name.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// Extracts a tar stream under dest, creating dest if needed.
pub fn untar(r: impl Read, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    let root = Dir::open_ambient_dir(dest, ambient_authority())?;
    let mut ar = tar::Archive::new(r);
    for entry in ar.entries()? {
        let mut e = entry?;
        let h = e.header().clone();
        let target = clean(&e.path()?);
        if target.as_os_str().is_empty() {
            continue;
        }
        let mode = h.mode().unwrap_or(0o644) & 0o7777;
        let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
        match h.entry_type() {
            tar::EntryType::Directory => {
                root.create_dir_all(&target)?;
                root.set_permissions(
                    &target,
                    cap_std::fs::Permissions::from_std(Permissions::from_mode(mode | 0o700)),
                )?;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(p) = parent {
                    root.create_dir_all(p)?;
                }
                let _ = root.remove_file(&target);
                let mut f = root.create(&target)?;
                io::copy(&mut e, &mut f)?;
                f.set_permissions(cap_std::fs::Permissions::from_std(Permissions::from_mode(
                    mode,
                )))?;
                let (uid, gid) = (h.uid().unwrap_or(0) as u32, h.gid().unwrap_or(0) as u32);
                if uid != 0 || gid != 0 {
                    let _ = std::os::unix::fs::fchown(f.into_std(), Some(uid), Some(gid));
                }
            }
            tar::EntryType::Symlink => {
                if let Some(p) = parent {
                    root.create_dir_all(p)?;
                }
                let _ = root.remove_file(&target);
                let link = e
                    .link_name()?
                    .ok_or_else(|| io::Error::other("symlink without target"))?;
                root.symlink_contents(link, &target)?;
            }
            tar::EntryType::Link => {
                let src = clean(
                    &e.link_name()?
                        .ok_or_else(|| io::Error::other("hardlink without target"))?,
                );
                let _ = root.remove_file(&target);
                root.hard_link(&src, &root, &target)?;
            }
            _ => {}
        }
    }
    Ok(())
}
