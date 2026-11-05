//! The guest side of ember: runs inside each microVM and executes commands
//! and file copies for the host.
//!
//! It serves the same BackendPlugin service the runner speaks (Exec, CopyIn
//! and CopyOut only), so the host relays those calls without translating
//! them. `environment_id` is ignored: one agent serves one VM.

pub mod init;
pub mod tarfs;

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Mutex, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::pb::{
    self, CapabilitiesRequest, CapabilitiesResponse, CopyInChunk, CopyInResponse, CopyOutChunk,
    CopyOutRequest, CreateRequest, CreateResponse, DataChunk, ExecOutput, ExecRequest,
    RemoveRequest, RemoveResponse, StartOutput, StartRequest, data_chunk, exec_output,
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How long Exec keeps forwarding output after the step's process exits. A
/// background process the step started (`server &`) may keep the pipes
/// open for ever; its later output is read and dropped.
const DRAIN: Duration = Duration::from_millis(200);

#[derive(Default)]
pub struct Agent;

type Stream<T> = ReceiverStream<Result<T, Status>>;
type ExecTx = mpsc::Sender<Result<ExecOutput, Status>>;

#[tonic::async_trait]
impl pb::backend_plugin_server::BackendPlugin for Agent {
    async fn capabilities(
        &self,
        _: Request<CapabilitiesRequest>,
    ) -> Result<Response<CapabilitiesResponse>, Status> {
        Ok(Response::new(CapabilitiesResponse {
            name: "ember-agent".into(),
        }))
    }

    async fn create(&self, _: Request<CreateRequest>) -> Result<Response<CreateResponse>, Status> {
        Err(Status::unimplemented("the agent only runs commands"))
    }

    type StartStream = Stream<StartOutput>;
    async fn start(&self, _: Request<StartRequest>) -> Result<Response<Self::StartStream>, Status> {
        Err(Status::unimplemented("the agent only runs commands"))
    }

    type ExecStream = Stream<ExecOutput>;
    async fn exec(&self, req: Request<ExecRequest>) -> Result<Response<Self::ExecStream>, Status> {
        let req = req.into_inner();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            // A clone only to notice the client going away; dropped when
            // run returns, so it never keeps the stream open.
            let watcher = tx.clone();
            let out = Arc::new(ExecSink {
                tx: Mutex::new(Some(tx)),
            });
            if let Err(msg) = run(req, out.clone(), watcher).await {
                out.finish(exec_output::Output::ExecFailed(pb::ExecFailed {
                    error_message: msg,
                }))
                .await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn copy_in(
        &self,
        req: Request<Streaming<CopyInChunk>>,
    ) -> Result<Response<CopyInResponse>, Status> {
        let mut stream = req.into_inner();
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("copyin: no header chunk"))?;
        let dest = first
            .dest_path
            .clone()
            .ok_or_else(|| Status::invalid_argument("copyin: first chunk has no dest_path"))?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);
        let untar = tokio::task::spawn_blocking(move || {
            tarfs::untar(tarfs::ChanReader::new(rx), Path::new(&dest))
        });
        let mut pending = Some(first.data);
        loop {
            let data = match pending.take() {
                Some(d) => d,
                None => match stream.message().await? {
                    Some(c) if c.environment_id.is_some() || c.dest_path.is_some() => {
                        return Err(Status::invalid_argument(
                            "copyin: header fields on a later chunk",
                        ));
                    }
                    Some(c) => c.data,
                    None => break,
                },
            };
            if !data.is_empty() && tx.send(data).is_err() {
                break; // untar stopped early; its error is reported below
            }
        }
        drop(tx);
        untar
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(|e| Status::internal(format!("copyin: {e}")))?;
        Ok(Response::new(CopyInResponse {}))
    }

    type CopyOutStream = Stream<CopyOutChunk>;
    async fn copy_out(
        &self,
        req: Request<CopyOutRequest>,
    ) -> Result<Response<Self::CopyOutStream>, Status> {
        let src = PathBuf::from(req.into_inner().src_path);
        let (tx, rx) = mpsc::channel(8);
        tokio::task::spawn_blocking(move || {
            let w = tarfs::ChunkWriter::new(tx.clone());
            if let Err(e) = tarfs::tar_path(&src, w) {
                let _ = tx.blocking_send(Err(Status::internal(format!("copyout: {e}"))));
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn remove(&self, _: Request<RemoveRequest>) -> Result<Response<RemoveResponse>, Status> {
        Err(Status::unimplemented("the agent only runs commands"))
    }
}

/// Serialises sends on an Exec stream. The final message drops the sender,
/// so the stream ends even while a background process keeps a pump alive.
struct ExecSink {
    tx: Mutex<Option<ExecTx>>,
}

impl ExecSink {
    async fn data(&self, stream: data_chunk::Stream, data: Vec<u8>) {
        if let Some(tx) = self.tx.lock().await.as_ref() {
            let chunk = DataChunk {
                stream: stream as i32,
                data,
            };
            let _ = tx
                .send(Ok(ExecOutput {
                    output: Some(exec_output::Output::Data(chunk)),
                }))
                .await;
        }
    }

    async fn finish(&self, out: exec_output::Output) {
        if let Some(tx) = self.tx.lock().await.take() {
            let _ = tx.send(Ok(ExecOutput { output: Some(out) })).await;
        }
    }
}

async fn run(req: ExecRequest, out: Arc<ExecSink>, watcher: ExecTx) -> Result<(), String> {
    let argv = req.command;
    let Some(name) = argv.first() else {
        return Err("empty command".into());
    };
    let mut env = req.env;
    env.entry("PATH".into())
        .or_insert_with(|| DEFAULT_PATH.into());
    let user = lookup_user(req.user.as_deref().unwrap_or(""))?;
    if let Some(home) = &user.home {
        env.entry("HOME".into()).or_insert_with(|| home.clone());
    }
    let bin = look_path(name, &env["PATH"])?;

    let dir = if req.workdir.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(&req.workdir)
    };
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create workdir: {e}"))?;
        if let Some((uid, gid)) = user.ids {
            // A workdir ember created must be usable by the step's user.
            let _ = std::os::unix::fs::chown(&dir, Some(uid), Some(gid));
        }
    }

    let mut cmd = Command::new(&bin);
    cmd.arg0(name)
        .args(&argv[1..])
        .env_clear()
        .envs(&env)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some((uid, gid)) = user.ids {
        cmd.uid(uid).gid(gid);
    }
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", bin.display()))?;
    let pgid = child.id().map(|p| p as i32);

    let pumps = [
        tokio::spawn(pump(
            child.stdout.take().expect("piped"),
            data_chunk::Stream::Stdout,
            out.clone(),
        )),
        tokio::spawn(pump(
            child.stderr.take().expect("piped"),
            data_chunk::Stream::Stderr,
            out.clone(),
        )),
    ];

    // The stream closing means the job was cancelled or timed out: kill the
    // whole process group, not only the direct child.
    let status = tokio::select! {
        status = child.wait() => status.map_err(|e| e.to_string())?,
        _ = watcher.closed() => {
            if let Some(pgid) = pgid {
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            child.wait().await.map_err(|e| e.to_string())?
        }
    };

    let _ = tokio::time::timeout(DRAIN, futures_util::future::join_all(pumps)).await;

    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    out.finish(exec_output::Output::ExecComplete(pb::ExecComplete {
        exit_code: code,
    }))
    .await;
    Ok(())
}

async fn pump(mut r: impl AsyncReadExt + Unpin, kind: data_chunk::Stream, out: Arc<ExecSink>) {
    let mut buf = vec![0u8; 32 << 10];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => out.data(kind, buf[..n].to_vec()).await,
        }
    }
}

/// Resolves name against the PATH the step asked for, not the agent's own.
pub fn look_path(name: &str, path: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }
    for dir in path.split(':') {
        let p = Path::new(if dir.is_empty() { "." } else { dir }).join(name);
        if let Ok(md) = std::fs::metadata(&p)
            && md.is_file()
            && md.permissions().mode() & 0o111 != 0
        {
            return Ok(p);
        }
    }
    Err(format!("{name}: executable not found in PATH"))
}

#[derive(Debug, PartialEq)]
pub struct User {
    pub ids: Option<(u32, u32)>, // None: stay root
    pub home: Option<String>,
}

/// Maps the runner's user field (name, uid, name:group or uid:gid) to ids,
/// reading the image's /etc/passwd and /etc/group.
pub fn lookup_user(spec: &str) -> Result<User, String> {
    lookup_user_in(spec, Path::new("/etc"))
}

pub fn lookup_user_in(spec: &str, etc: &Path) -> Result<User, String> {
    if spec.is_empty() || spec == "root" || spec == "0" {
        return Ok(User {
            ids: None,
            home: Some("/root".into()),
        });
    }
    let (name, group) = spec
        .split_once(':')
        .map_or((spec, None), |(n, g)| (n, Some(g)));
    let fields = |file: &str| -> Vec<Vec<String>> {
        std::fs::read_to_string(etc.join(file))
            .unwrap_or_default()
            .lines()
            .map(|l| l.split(':').map(String::from).collect())
            .collect()
    };
    let passwd = fields("passwd");
    let entry = passwd
        .iter()
        .find(|f| f.len() >= 7 && (f[0] == name || f[2] == name));
    let (uid, mut gid, home) = match entry {
        Some(f) => (
            f[2].parse().map_err(|_| format!("bad uid for {name}"))?,
            f[3].parse().map_err(|_| format!("bad gid for {name}"))?,
            Some(f[5].clone()),
        ),
        None => {
            let n: u32 = name.parse().map_err(|_| format!("unknown user {name:?}"))?;
            (n, n, None)
        }
    };
    if let Some(group) = group {
        gid = match fields("group")
            .iter()
            .find(|f| f.len() >= 3 && f[0] == group)
        {
            Some(f) => f[2].parse().map_err(|_| format!("bad gid for {group}"))?,
            None => group
                .parse()
                .map_err(|_| format!("unknown group {group:?}"))?,
        };
    }
    Ok(User {
        ids: Some((uid, gid)),
        home,
    })
}
