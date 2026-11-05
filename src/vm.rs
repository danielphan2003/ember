//! Boots one Firecracker microVM and connects to its guest agent.

use std::{
    collections::VecDeque,
    fs::{self, File},
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    sync::watch,
};
use tonic::transport::{Channel, Endpoint};

use crate::{AGENT_PORT, pb::backend_plugin_client::BackendPluginClient};

/// Describes one VM.
pub struct Spec {
    pub dir: PathBuf, // private working directory; removed by destroy
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub base_rootfs: PathBuf, // cached image; cloned, never written
    pub disk_bytes: u64,      // grow the clone to this size if larger
    pub vcpus: u32,
    pub memory_mib: u32,
    pub tap: String,
    pub mac: String,
    pub guest_cidr: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub hostname: String,
}

/// A running VM.
pub struct Machine {
    dir: PathBuf,
    killer: Killer,
    exited: watch::Receiver<bool>,
    console: Arc<Mutex<Ring>>,
    pub agent: Option<BackendPluginClient<Channel>>,
}

impl Spec {
    fn vsock_path(&self) -> PathBuf {
        self.dir.join("vsock.sock")
    }
}

/// Clones the root filesystem and starts Firecracker. Returns once the
/// process runs; use `wait_agent` to wait for the guest.
pub fn boot(spec: &Spec) -> Result<Machine> {
    fs::create_dir_all(&spec.dir)?;
    let rootfs = spec.dir.join("rootfs.ext4");
    clone_file(&spec.base_rootfs, &rootfs).context("clone rootfs")?;
    grow(&rootfs, spec.disk_bytes)?;

    let mut args = vec![
        "console=ttyS0".to_string(),
        "reboot=k".into(),
        "panic=1".into(),
        "pci=off".into(),
        "quiet".into(),
        "i8042.noaux".into(),
        "i8042.nomux".into(),
        "i8042.dumbkbd".into(),
        "rootfstype=ext4".into(),
        "rw".into(),
        "init=/.ember/agent".into(),
        format!("ember.ip={}", spec.guest_cidr),
        format!("ember.gw={}", spec.gateway),
        format!("ember.hostname={}", spec.hostname),
    ];
    if !spec.dns.is_empty() {
        args.push(format!("ember.dns={}", spec.dns.join(",")));
    }
    let cfg = serde_json::json!({
        "boot-source": {"kernel_image_path": spec.kernel, "boot_args": args.join(" ")},
        "drives": [{"drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": true, "is_read_only": false}],
        "machine-config": {"vcpu_count": spec.vcpus, "mem_size_mib": spec.memory_mib, "smt": false},
        "network-interfaces": [{"iface_id": "eth0", "host_dev_name": spec.tap, "guest_mac": spec.mac}],
        "vsock": {"guest_cid": 3, "uds_path": spec.vsock_path()},
    });
    let cfg_path = spec.dir.join("firecracker.json");
    fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg)?)?;

    let mut child = Command::new(&spec.firecracker)
        .args(["--no-api", "--config-file"])
        .arg(&cfg_path)
        .args(["--level", "Warning"])
        .current_dir(&spec.dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Its own process group keeps a terminal's Ctrl-C away from the VMs.
        // Cleanup is ember's job, and systemd's, which kills the cgroup.
        .process_group(0)
        .spawn()
        .context("start firecracker")?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("firecracker exited at once"))?;
    // A pidfd names this process, never a later one that reuses its PID.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        let _ = child.start_kill(); // never leave a VM nobody can stop
        return Err(err).context("pidfd_open");
    }
    let pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw as i32) });

    // The serial console goes to a bounded ring: a guest flooding ttyS0
    // must not fill the host disk or ember's memory.
    let console = Arc::new(Mutex::new(Ring::new(64 << 10)));
    for out in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let console = console.clone();
        tokio::spawn(async move {
            let mut out = out;
            let mut buf = vec![0u8; 8192];
            while let Ok(n) = out.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                console.lock().unwrap().write(&buf[..n]);
            }
        });
    }
    let (tx, exited) = watch::channel(false);
    tokio::spawn(async move {
        let _ = child.wait().await;
        let _ = tx.send(true);
    });
    let killer = Killer {
        pidfd,
        exited: exited.clone(),
    };
    Ok(Machine {
        dir: spec.dir.clone(),
        killer,
        exited,
        console,
        agent: None,
    })
}

/// A Machine that goes away without destroy (a Start dropped mid-boot, say)
/// must not leave its VM running on a slot ember thinks is free.
impl Drop for Machine {
    fn drop(&mut self) {
        self.killer.kill();
    }
}

impl Machine {
    fn vsock_path(&self) -> PathBuf {
        self.dir.join("vsock.sock")
    }

    /// Waits until the guest agent answers, the VM dies, or the timeout.
    pub async fn wait_agent(&mut self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let uds = self.vsock_path();
        // Poll the raw handshake: it succeeds as soon as the agent listens.
        let mut last = anyhow!("not tried");
        loop {
            if self.has_exited() {
                bail!("the VM exited during boot");
            }
            if tokio::time::Instant::now() > deadline {
                bail!("timed out after {timeout:?} (last error: {last})");
            }
            match tokio::time::timeout(Duration::from_millis(200), dial_vsock(&uds, AGENT_PORT))
                .await
            {
                Ok(Ok(_)) => break,
                Ok(Err(e)) => last = e.into(),
                Err(_) => last = anyhow!("handshake timed out"),
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let channel = Endpoint::from_static("http://agent")
            .connect_with_connector(tower::service_fn(move |_| {
                let uds = uds.clone();
                async move { dial_vsock(&uds, AGENT_PORT).await.map(TokioIo::new) }
            }))
            .await?;
        let mut client = BackendPluginClient::new(channel).max_decoding_message_size(16 << 20);
        client
            .capabilities(crate::pb::CapabilitiesRequest {})
            .await?;
        self.agent = Some(client);
        Ok(())
    }

    pub fn has_exited(&self) -> bool {
        *self.exited.borrow()
    }

    /// Resolves when the Firecracker process has ended.
    pub fn exited(&self) -> watch::Receiver<bool> {
        self.exited.clone()
    }

    /// Stops the VM at once; destroy still has to clean up.
    pub fn kill(&self) {
        self.killer.kill();
    }

    /// A handle that can kill the VM without access to the Machine.
    pub fn killer(&self) -> Killer {
        self.killer.clone()
    }

    /// The last n lines of the serial console.
    pub fn console_tail(&self, n: usize) -> String {
        let text = self.console.lock().unwrap().text();
        let lines: Vec<&str> = text.trim_end().lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    /// Kills the VM, waits briefly for it, and removes its directory.
    pub async fn destroy(mut self) {
        self.agent = None;
        self.kill();
        let mut exited = self.exited.clone();
        let _ = tokio::time::timeout(Duration::from_secs(5), exited.wait_for(|e| *e)).await;
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
    }
}

/// Kills a VM from anywhere, at any time: the signal goes through a pidfd,
/// so it never reaches a later process that reuses the PID.
#[derive(Clone)]
pub struct Killer {
    pidfd: Arc<OwnedFd>,
    exited: watch::Receiver<bool>,
}

impl Killer {
    pub fn kill(&self) {
        if !*self.exited.borrow() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<()>(),
                    0,
                )
            };
        }
    }
}

/// Connects to a guest port through Firecracker's vsock unix socket: send
/// "CONNECT <port>", expect "OK <host port>".
async fn dial_vsock(uds: &Path, port: u32) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(uds).await?;
    s.write_all(format!("CONNECT {port}\n").as_bytes()).await?;
    // Read the reply byte by byte so no gRPC bytes are swallowed.
    let mut line = Vec::new();
    let mut r = BufReader::with_capacity(1, &mut s);
    r.read_until(b'\n', &mut line).await?;
    if !line.starts_with(b"OK ") {
        return Err(io::Error::other(format!(
            "vsock handshake: {:?}",
            String::from_utf8_lossy(&line)
        )));
    }
    Ok(s)
}

/// Makes dst a copy-on-write clone of src (btrfs, XFS), falling back to a
/// sparse copy on filesystems without reflinks.
pub fn clone_file(src: &Path, dst: &Path) -> io::Result<()> {
    if reflink(src, dst).is_ok() {
        return Ok(());
    }
    let mut input = File::open(src)?;
    let mut out = File::create(dst)?;
    let len = input.metadata()?.len();
    let mut buf = vec![0u8; 1 << 20];
    use std::io::{Read, Seek, SeekFrom, Write};
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().all(|&b| b == 0) {
            out.seek(SeekFrom::Current(n as i64))?;
        } else {
            out.write_all(&buf[..n])?;
        }
    }
    out.set_len(len)
}

/// Clones src to dst, failing if the filesystem cannot share extents.
pub fn reflink(src: &Path, dst: &Path) -> io::Result<()> {
    let input = File::open(src)?;
    let out = File::create(dst)?;
    if unsafe { libc::ioctl(out.as_raw_fd(), libc::FICLONE as _, input.as_raw_fd()) } != 0 {
        let e = io::Error::last_os_error();
        let _ = fs::remove_file(dst);
        return Err(e);
    }
    Ok(())
}

fn grow(path: &Path, size: u64) -> Result<()> {
    if size <= fs::metadata(path)?.len() {
        return Ok(());
    }
    File::options().write(true).open(path)?.set_len(size)?;
    let o = std::process::Command::new("resize2fs")
        .arg("-f")
        .arg(path)
        .output()
        .context("run resize2fs")?;
    if !o.status.success() {
        bail!("resize2fs: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

/// Keeps the last max bytes written to it.
pub struct Ring {
    max: usize,
    buf: VecDeque<u8>,
}

impl Ring {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            buf: VecDeque::with_capacity(max),
        }
    }
    pub fn write(&mut self, b: &[u8]) {
        self.buf.extend(b);
        let over = self.buf.len().saturating_sub(self.max);
        self.buf.drain(..over);
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf.iter().copied().collect::<Vec<_>>()).into_owned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ring_keeps_the_tail() {
        let mut r = super::Ring::new(8);
        r.write(b"hello ");
        r.write(b"world!");
        assert_eq!(r.text(), "o world!");
    }
}
