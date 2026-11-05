//! The forgejo-runner's plugin.v1alpha BackendPlugin service: one
//! Firecracker microVM per job.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Code, Request, Response, Status, Streaming};
use tracing::{info, warn};

use crate::{
    config::{Config, Slot},
    image::{Image, Progress, Store},
    pb::{
        self, CapabilitiesRequest, CapabilitiesResponse, CopyInChunk, CopyInResponse, CopyOutChunk,
        CopyOutRequest, CreateRequest, CreateResponse, ExecOutput, ExecRequest, RemoveRequest,
        RemoveResponse, StartOutput, StartRequest, data_chunk, exec_output, start_output,
    },
    vm::{self, Killer, Machine},
};

// Paths the runner lays files out under inside every VM.
const ROOT_PATH: &str = "/ember";
const ACT_PATH: &str = "/ember/act";
const TOOL_CACHE_PATH: &str = "/ember/toolcache";
const TEMP_PATH: &str = "/ember/tmp";

/// Bounds an environment when the runner sends no timeout.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(6 * 3600);

/// The plugin. Cheap to clone; all state is shared.
#[derive(Clone)]
pub struct Server(Arc<Inner>);

struct Inner {
    cfg: Config,
    images: Arc<Store>,
    slot_permits: Arc<Semaphore>,
    free_slots: Mutex<Vec<Slot>>,
    mem_budget: u32,
    committed: Mutex<u32>,
    envs: Mutex<HashMap<String, Arc<Environment>>>,
    host: Box<dyn HostProbe>,
}

/// Host resources, replaceable in tests.
pub trait HostProbe: Send + Sync {
    fn mem_available_mib(&self) -> Option<u32>;
    fn disk_free_gib(&self, path: &std::path::Path) -> Option<u64>;
}

struct RealHost;

impl HostProbe for RealHost {
    fn mem_available_mib(&self) -> Option<u32> {
        meminfo_mib("MemAvailable:")
    }
    fn disk_free_gib(&self, path: &std::path::Path) -> Option<u64> {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0)
            .then(|| (st.f_bavail * st.f_frsize) >> 30)
    }
}

fn meminfo_mib(key: &str) -> Option<u32> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = s.lines().find(|l| l.starts_with(key))?;
    let kb: u64 = line[key.len()..]
        .trim()
        .trim_end_matches(" kB")
        .trim()
        .parse()
        .ok()?;
    Some((kb / 1024) as u32)
}

struct Environment {
    id: String,
    image_ref: String,
    vcpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    /// One RPC at a time per environment, as the protocol advises.
    state: Arc<tokio::sync::Mutex<State>>,
    /// Readable without `state`, so Remove can stop a VM whose agent call
    /// is stuck while holding it.
    killer: Mutex<Option<Killer>>,
    lifetime: Mutex<Option<tokio::task::AbortHandle>>,
}

#[derive(Default)]
struct State {
    /// Set by destroy: a Start that looked the environment up just before
    /// must not boot a VM nothing can reach.
    removed: bool,
    slot: Option<(Slot, OwnedSemaphorePermit)>,
    reserved_mib: u32,
    machine: Option<Machine>,
    image: Option<Image>,
}

impl Environment {
    fn kill(&self) {
        if let Some(k) = self.killer.lock().unwrap().as_ref() {
            k.kill();
        }
    }
}

type Stream<T> = ReceiverStream<Result<T, Status>>;

impl Server {
    pub fn new(cfg: Config, agent: &'static [u8]) -> Result<Self> {
        Self::with_host(cfg, agent, Box::new(RealHost))
    }

    pub fn with_host(cfg: Config, agent: &'static [u8], host: Box<dyn HostProbe>) -> Result<Self> {
        let images = Store::new(
            cfg.state_dir.join("images"),
            agent,
            cfg.image_refresh,
            cfg.disk_gib,
            cfg.max_image_mib,
        )?;
        let mem_budget = match cfg.memory_budget_mib {
            0 => meminfo_mib("MemTotal:")
                .map(|t| t.saturating_sub(cfg.host_reserve_mib))
                .unwrap_or(cfg.memory_mib * cfg.slots as u32)
                .max(cfg.memory_mib),
            b => b,
        };
        let mut slots = cfg.slot_list();
        slots.reverse(); // hand out ember0 first
        Ok(Self(Arc::new(Inner {
            slot_permits: Arc::new(Semaphore::new(cfg.slots)),
            free_slots: Mutex::new(slots),
            mem_budget,
            committed: Mutex::new(0),
            envs: Mutex::new(HashMap::new()),
            images,
            host,
            cfg,
        })))
    }

    pub fn images(&self) -> &Arc<Store> {
        &self.0.images
    }

    fn vm_dir(&self, id: &str) -> PathBuf {
        self.0.cfg.state_dir.join("vms").join(id)
    }

    /// Removes VM directories left by a previous run.
    pub fn clean_stale(&self) {
        let _ = std::fs::remove_dir_all(self.0.cfg.state_dir.join("vms"));
    }

    fn snapshot(&self) -> Vec<Arc<Environment>> {
        self.0.envs.lock().unwrap().values().cloned().collect()
    }

    /// Kills every VM at once, without waiting for in-flight calls.
    pub fn kill_all(&self) {
        for e in self.snapshot() {
            e.kill();
        }
    }

    /// Destroys every environment. Call after the gRPC server has stopped.
    pub async fn shutdown(&self) {
        self.kill_all();
        for e in self.snapshot() {
            self.destroy(&e).await;
        }
    }

    fn lookup(&self, id: &str) -> Result<Arc<Environment>, Status> {
        self.0
            .envs
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("environment {id:?} not found")))
    }

    /// Stops the VM and returns its slot, memory and disk, but keeps the
    /// environment known so the runner's Remove still succeeds.
    async fn teardown(&self, st: &mut State, id: &str) {
        if let Some(m) = st.machine.take() {
            m.destroy().await;
        }
        let _ = tokio::fs::remove_dir_all(self.vm_dir(id)).await;
        if let Some((slot, permit)) = st.slot.take() {
            self.0.free_slots.lock().unwrap().push(slot);
            drop(permit);
        }
        if st.reserved_mib > 0 {
            *self.0.committed.lock().unwrap() -= st.reserved_mib;
            st.reserved_mib = 0;
        }
    }

    /// Tears the environment down and forgets it.
    async fn destroy(&self, e: &Arc<Environment>) {
        e.kill();
        let mut st = e.state.lock().await;
        st.removed = true;
        self.teardown(&mut st, &e.id).await;
        *e.killer.lock().unwrap() = None;
        if let Some(h) = e.lifetime.lock().unwrap().take() {
            h.abort();
        }
        if self.0.envs.lock().unwrap().remove(&e.id).is_some() {
            info!(env = %e.id, "removed");
        }
    }

    /// Takes a slot and reserves the VM's memory. Waits while the budget is
    /// spent or the host is short of memory, holding no slot meanwhile so a
    /// smaller job can still start.
    async fn acquire(&self, e: &Environment, st: &mut State, log: &StartLog) -> Result<(), Status> {
        let inner = &self.0;
        if e.memory_mib > inner.mem_budget {
            return Err(Status::invalid_argument(format!(
                "job asks for {} MiB, more than the {} MiB budget for all VMs",
                e.memory_mib, inner.mem_budget
            )));
        }
        let (mut warned_slots, mut warned_mem) = (false, false);
        loop {
            if inner.slot_permits.available_permits() == 0 && !warned_slots {
                log.line(format!("all {} slots busy; waiting", inner.cfg.slots))
                    .await;
                warned_slots = true;
            }
            let permit = inner
                .slot_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Status::unavailable("shutting down"))?;
            let free = inner.host.mem_available_mib();
            let ok = {
                let mut committed = inner.committed.lock().unwrap();
                let fits = *committed + e.memory_mib <= inner.mem_budget
                    && free.is_none_or(|f| f >= e.memory_mib + inner.cfg.host_reserve_mib);
                if fits {
                    *committed += e.memory_mib;
                }
                fits
            };
            if ok {
                st.reserved_mib = e.memory_mib;
                let slot = inner
                    .free_slots
                    .lock()
                    .unwrap()
                    .pop()
                    .expect("a permit means a free slot");
                st.slot = Some((slot, permit));
                return Ok(());
            }
            drop(permit);
            if !warned_mem {
                let committed = *inner.committed.lock().unwrap();
                log.line(format!(
                    "waiting for memory: {committed} of {} MiB promised to VMs, {} MiB available on the host; job needs {} MiB",
                    inner.mem_budget,
                    free.map_or("?".into(), |f| f.to_string()),
                    e.memory_mib
                ))
                .await;
                warned_mem = true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn start_inner(
        &self,
        e: Arc<Environment>,
        st: &mut State,
        log: &StartLog,
    ) -> Result<(), Status> {
        let cfg = &self.0.cfg;
        let began = Instant::now();
        if let Some(free) = self.0.host.disk_free_gib(&cfg.state_dir)
            && free < cfg.min_free_gib
        {
            return Err(Status::resource_exhausted(format!(
                "only {free} GiB free in {} (min_free_gib is {}); refusing to start a VM",
                cfg.state_dir.display(),
                cfg.min_free_gib
            )));
        }
        let tx = log.tx.clone();
        let progress: Progress = Arc::new(move |line: String| {
            let _ = tx.try_send(Ok(data_line(&line)));
        });
        let img = self
            .0
            .images
            .ensure(&e.image_ref, progress)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!("image {}: {err:#}", e.image_ref))
            })?;
        st.image = Some(img.clone());

        self.acquire(&e, st, log).await?;
        let slot = st.slot.as_ref().map(|(s, _)| s.clone()).expect("acquired");
        let boot_start = Instant::now();
        let spec = vm::Spec {
            dir: self.vm_dir(&e.id),
            firecracker: cfg.firecracker.clone(),
            kernel: cfg.kernel.clone(),
            base_rootfs: img.rootfs.clone(),
            disk_bytes: u64::from(e.disk_gib) << 30,
            vcpus: e.vcpus,
            memory_mib: e.memory_mib,
            tap: slot.tap.clone(),
            mac: slot.mac.clone(),
            guest_cidr: slot.guest_cidr(),
            gateway: slot.host.to_string(),
            dns: cfg.dns.clone(),
            hostname: e.id.clone(),
        };
        // Cloning (or copying, without reflinks) and resize2fs are disk work:
        // keep them off the async workers.
        let rt = tokio::runtime::Handle::current();
        let machine = tokio::task::spawn_blocking(move || {
            let _guard = rt.enter(); // boot spawns tasks for the console and exit
            vm::boot(&spec)
        })
        .await
        .map_err(|err| Status::internal(format!("boot: {err}")))?
        .map_err(|err| Status::internal(format!("boot: {err:#}")))?;
        *e.killer.lock().unwrap() = Some(machine.killer());
        let machine = st.machine.insert(machine);
        if let Err(err) = machine.wait_agent(Duration::from_secs(60)).await {
            let tail = machine.console_tail(40);
            return Err(Status::internal(format!(
                "microVM did not come up: {err:#}\n--- console (last 40 lines) ---\n{tail}"
            )));
        }
        log.line(format!(
            "microVM {} ready: {}, {} vCPU, {} MiB; booted in {} ms ({} ms total)",
            e.id,
            short_digest(&img.digest),
            e.vcpus,
            e.memory_mib,
            boot_start.elapsed().as_millis(),
            began.elapsed().as_millis()
        ))
        .await;
        info!(env = %e.id, slot = %slot.tap, boot_ms = boot_start.elapsed().as_millis() as u64, "started");
        Ok(())
    }

    /// Whether the VM behind an environment has died, and why, for errors.
    fn vm_gone(st: &State, err: impl std::fmt::Display) -> String {
        match &st.machine {
            Some(m) if m.has_exited() => format!(
                "the microVM stopped (out of memory, timeout or guest crash)\n--- console (last 20 lines) ---\n{}",
                m.console_tail(20)
            ),
            _ => err.to_string(),
        }
    }
}

struct StartLog {
    tx: mpsc::Sender<Result<StartOutput, Status>>,
}

fn data_line(line: &str) -> StartOutput {
    StartOutput {
        output: Some(start_output::Output::Data(pb::DataChunk {
            stream: data_chunk::Stream::Stdout as i32,
            data: format!("ember: {line}\n").into_bytes(),
        })),
    }
}

impl StartLog {
    async fn line(&self, line: String) {
        let _ = self.tx.send(Ok(data_line(&line))).await;
    }
}

#[tonic::async_trait]
impl pb::backend_plugin_server::BackendPlugin for Server {
    async fn capabilities(
        &self,
        _: Request<CapabilitiesRequest>,
    ) -> Result<Response<CapabilitiesResponse>, Status> {
        Ok(Response::new(CapabilitiesResponse {
            name: "ember".into(),
        }))
    }

    async fn create(
        &self,
        req: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let req = req.into_inner();
        if !req.services.is_empty() {
            return Err(Status::invalid_argument(
                "ember does not support service containers: run the service inside the job (it is a full VM)",
            ));
        }
        let cfg = &self.0.cfg;
        let opts = &req.backend_options;
        let id = format!("ember-{}", hex::encode(rand::random::<[u8; 6]>()));
        let image_ref = [&req.image, &req.label_arg, &cfg.default_image]
            .into_iter()
            .find(|s| !s.is_empty())
            .cloned()
            .unwrap_or_default();
        let e = Arc::new(Environment {
            id: id.clone(),
            image_ref,
            vcpus: int_option(opts, "vcpus", cfg.vcpus, 1, 32)?,
            memory_mib: int_option(opts, "memory_mib", cfg.memory_mib, 128, 1 << 20)?,
            disk_gib: int_option(opts, "disk_gib", cfg.disk_gib, 1, 1024)?,
            state: Arc::new(tokio::sync::Mutex::new(State::default())),
            killer: Mutex::new(None),
            lifetime: Mutex::new(None),
        });
        let lifetime = req
            .environment_timeout
            .and_then(|d| Duration::try_from(d).ok())
            .filter(|d| !d.is_zero())
            .unwrap_or(DEFAULT_LIFETIME);
        self.0.envs.lock().unwrap().insert(id.clone(), e.clone());
        // The lifetime runs from Create, so an environment whose Remove never
        // comes (the runner restarted mid-job) still gives its slot back.
        let (server, env) = (self.clone(), e.clone());
        let timer = tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            warn!(env = %env.id, after = ?lifetime, "environment lifetime exceeded; removing");
            env.lifetime.lock().unwrap().take();
            server.destroy(&env).await;
        });
        *e.lifetime.lock().unwrap() = Some(timer.abort_handle());
        info!(env = %id, image = %e.image_ref, vcpus = e.vcpus, memory_mib = e.memory_mib, "create");
        Ok(Response::new(CreateResponse {
            environment_id: id,
            root_path: ROOT_PATH.into(),
            act_path: ACT_PATH.into(),
            tool_cache_path: TOOL_CACHE_PATH.into(),
            temp_path: TEMP_PATH.into(),
            os: "Linux".into(),
            arch: runner_arch().into(),
            ..Default::default()
        }))
    }

    type StartStream = Stream<StartOutput>;
    async fn start(
        &self,
        req: Request<StartRequest>,
    ) -> Result<Response<Self::StartStream>, Status> {
        let e = self.lookup(&req.into_inner().environment_id)?;
        let (tx, rx) = mpsc::channel(64);
        let server = self.clone();
        tokio::spawn(async move {
            let log = StartLog { tx: tx.clone() };
            let mut st = e.state.clone().lock_owned().await;
            if st.removed {
                let _ = tx
                    .send(Err(Status::not_found(format!(
                        "environment {:?} was removed",
                        e.id
                    ))))
                    .await;
                return;
            }
            if st.machine.is_some() {
                let _ = tx
                    .send(Err(Status::failed_precondition(
                        "environment already started",
                    )))
                    .await;
                return;
            }
            // A closed stream means the job was cancelled: stop starting.
            // Whatever was acquired is in `st`, so Remove cleans it up.
            let res = tokio::select! {
                r = server.start_inner(e.clone(), &mut st, &log) => r,
                _ = tx.closed() => Err(Status::cancelled("start cancelled")),
            };
            match res {
                Ok(()) => {
                    let env = st
                        .image
                        .as_ref()
                        .map(|i| image_env(&i.env))
                        .unwrap_or_default();
                    let done = StartOutput {
                        output: Some(start_output::Output::StartComplete(pb::StartComplete {
                            image_env: env,
                        })),
                    };
                    let _ = tx.send(Ok(done)).await;
                }
                Err(status) => {
                    server.teardown(&mut st, &e.id).await; // the runner still sends Remove
                    *e.killer.lock().unwrap() = None;
                    let _ = tx.send(Err(status)).await;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type ExecStream = Stream<ExecOutput>;
    async fn exec(&self, req: Request<ExecRequest>) -> Result<Response<Self::ExecStream>, Status> {
        let mut req = req.into_inner();
        let e = self.lookup(&req.environment_id)?;
        let st = e.state.clone().lock_owned().await;
        let (Some(machine), Some(img)) = (st.machine.as_ref(), st.image.as_ref()) else {
            return Err(Status::failed_precondition(format!(
                "environment {:?} is not started",
                e.id
            )));
        };
        // The runner does not merge the image's ENV into steps, so a golang
        // image would lose /usr/local/go/bin. Layer it under the step's own.
        req.env = merge_image_env(&img.env, std::mem::take(&mut req.env));
        if req.user.is_none() && !img.user.is_empty() {
            req.user = Some(img.user.clone());
        }
        let mut agent = machine
            .agent
            .clone()
            .ok_or_else(|| Status::failed_precondition("agent not connected"))?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let st = st; // held until the step ends
            let failed = |msg: String| ExecOutput {
                output: Some(exec_output::Output::ExecFailed(pb::ExecFailed {
                    error_message: msg,
                })),
            };
            let relay = async {
                let mut stream = match agent.exec(req).await {
                    Ok(r) => r.into_inner(),
                    Err(err) => return Some(failed(Server::vm_gone(&st, err))),
                };
                loop {
                    match stream.next().await {
                        Some(Ok(msg)) => {
                            if tx.send(Ok(msg)).await.is_err() {
                                return None;
                            }
                        }
                        Some(Err(err)) => return Some(failed(Server::vm_gone(&st, err))),
                        None => return None,
                    }
                }
            };
            // Dropping the relay cancels the agent call, which kills the step.
            let last = tokio::select! {
                last = relay => last,
                _ = tx.closed() => None,
            };
            if let Some(msg) = last {
                let _ = tx.send(Ok(msg)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn copy_in(
        &self,
        req: Request<Streaming<CopyInChunk>>,
    ) -> Result<Response<CopyInResponse>, Status> {
        let mut incoming = req.into_inner();
        let first = incoming
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("copyin: no chunks"))?;
        let (Some(id), Some(_)) = (first.environment_id.clone(), first.dest_path.as_ref()) else {
            return Err(Status::invalid_argument(
                "copyin: first chunk must set environment_id and dest_path",
            ));
        };
        let e = self.lookup(&id)?;
        let st = e.state.lock().await;
        let Some(machine) = st.machine.as_ref() else {
            return Err(Status::failed_precondition(format!(
                "environment {id:?} is not started"
            )));
        };
        let mut agent = machine
            .agent
            .clone()
            .ok_or_else(|| Status::failed_precondition("agent not connected"))?;
        let (tx, rx) = mpsc::channel::<CopyInChunk>(16);
        let (err_tx, mut err_rx) = mpsc::channel::<Status>(1);
        tokio::spawn(async move {
            if tx.send(first).await.is_err() {
                return;
            }
            loop {
                match incoming.message().await {
                    Ok(Some(c)) if c.environment_id.is_some() || c.dest_path.is_some() => {
                        let _ = err_tx
                            .send(Status::invalid_argument(
                                "copyin: environment_id or dest_path on a later chunk",
                            ))
                            .await;
                        return;
                    }
                    Ok(Some(c)) => {
                        if tx.send(c).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(s) => {
                        let _ = err_tx.send(s).await;
                        return;
                    }
                }
            }
        });
        let res = agent.copy_in(ReceiverStream::new(rx)).await;
        if let Ok(s) = err_rx.try_recv() {
            return Err(s);
        }
        match res {
            Ok(_) => Ok(Response::new(CopyInResponse {})),
            Err(s) if s.code() == Code::InvalidArgument => Err(s),
            Err(s) => Err(Status::internal(format!(
                "copyin: {}",
                Server::vm_gone(&st, s)
            ))),
        }
    }

    type CopyOutStream = Stream<CopyOutChunk>;
    async fn copy_out(
        &self,
        req: Request<CopyOutRequest>,
    ) -> Result<Response<Self::CopyOutStream>, Status> {
        let req = req.into_inner();
        let e = self.lookup(&req.environment_id)?;
        let st = e.state.clone().lock_owned().await;
        let Some(machine) = st.machine.as_ref() else {
            return Err(Status::failed_precondition(format!(
                "environment {:?} is not started",
                e.id
            )));
        };
        let mut agent = machine
            .agent
            .clone()
            .ok_or_else(|| Status::failed_precondition("agent not connected"))?;
        let mut stream = agent
            .copy_out(req)
            .await
            .map_err(|s| copy_out_error(&st, s))?
            .into_inner();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let st = st;
            while let Some(item) = stream.next().await {
                let item = item.map_err(|s| copy_out_error(&st, s));
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn remove(
        &self,
        req: Request<RemoveRequest>,
    ) -> Result<Response<RemoveResponse>, Status> {
        let e = self.lookup(&req.into_inner().environment_id)?;
        // destroy kills first, without the lock: an agent call stuck in a
        // hung guest holds the lock, and killing the VM is what frees it.
        self.destroy(&e).await;
        Ok(Response::new(RemoveResponse {}))
    }
}

/// Keeps NotFound (the runner reads it as "no such file"); anything else
/// becomes Internal with the VM's state.
fn copy_out_error(st: &State, s: Status) -> Status {
    if s.code() == Code::NotFound {
        return s;
    }
    Status::internal(format!("copyout: {}", Server::vm_gone(st, s)))
}

fn int_option(
    opts: &HashMap<String, String>,
    key: &str,
    default: u32,
    lo: u32,
    hi: u32,
) -> Result<u32, Status> {
    match opts.get(key).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .ok()
            .filter(|n| (lo..=hi).contains(n))
            .ok_or_else(|| {
                Status::invalid_argument(format!(
                    "option {key}={v:?} must be an integer from {lo} to {hi}"
                ))
            }),
    }
}

fn image_env(env: &[String]) -> HashMap<String, String> {
    env.iter()
        .map(|kv| {
            kv.split_once('=')
                .map_or((kv.clone(), String::new()), |(k, v)| (k.into(), v.into()))
        })
        .collect()
}

/// Layers a step's variables over the image's ENV. PATH is joined: the
/// step's entries first, then any image entries it lacks.
pub fn merge_image_env(image: &[String], step: HashMap<String, String>) -> HashMap<String, String> {
    let mut out = image_env(image);
    let image_path = out.get("PATH").cloned().unwrap_or_default();
    let step_path = step.get("PATH").cloned().unwrap_or_default();
    out.extend(step);
    if !image_path.is_empty() && !step_path.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let joined: Vec<&str> = step_path
            .split(':')
            .chain(image_path.split(':'))
            .filter(|p| !p.is_empty() && seen.insert(*p))
            .collect();
        out.insert("PATH".into(), joined.join(":"));
    }
    out
}

/// GOARCH-style names, as GitHub-style actions expect in RUNNER_ARCH.
fn runner_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        a => a,
    }
}

fn short_digest(d: &str) -> String {
    match d.split_once(':') {
        Some((alg, h)) if h.len() > 12 => format!("{alg}:{}", &h[..12]),
        _ => d.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::backend_plugin_server::BackendPlugin;

    struct FakeHost;
    impl HostProbe for FakeHost {
        fn mem_available_mib(&self) -> Option<u32> {
            Some(1 << 20)
        }
        fn disk_free_gib(&self, _: &std::path::Path) -> Option<u64> {
            Some(1 << 20)
        }
    }

    fn server() -> (Server, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            state_dir: dir.path().into(),
            memory_budget_mib: 8192,
            ..Config::default()
        };
        (
            Server::with_host(cfg, b"agent", Box::new(FakeHost)).unwrap(),
            dir,
        )
    }

    #[tokio::test]
    async fn create_defaults_and_options() {
        let (s, _d) = server();
        let resp = s
            .create(Request::new(CreateRequest {
                label_arg: "docker.io/library/alpine:3.22".into(),
                backend_options: [
                    ("vcpus".into(), "4".into()),
                    ("memory_mib".into(), "4096".into()),
                ]
                .into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let e = s.lookup(&resp.environment_id).unwrap();
        assert_eq!(
            (e.image_ref.as_str(), e.vcpus, e.memory_mib),
            ("docker.io/library/alpine:3.22", 4, 4096)
        );
        assert_eq!(
            (resp.act_path.as_str(), resp.os.as_str()),
            (ACT_PATH, "Linux")
        );

        let resp = s
            .create(Request::new(CreateRequest {
                image: "debian:trixie".into(),
                label_arg: "alpine".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            s.lookup(&resp.environment_id).unwrap().image_ref,
            "debian:trixie",
            "workflow container wins"
        );
    }

    #[tokio::test]
    async fn create_rejects() {
        let (s, _d) = server();
        for req in [
            CreateRequest {
                services: vec![pb::ServiceContainer {
                    name: "db".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            CreateRequest {
                backend_options: [("vcpus".into(), "lots".into())].into(),
                ..Default::default()
            },
            CreateRequest {
                backend_options: [("memory_mib".into(), "1".into())].into(),
                ..Default::default()
            },
        ] {
            assert_eq!(
                s.create(Request::new(req)).await.unwrap_err().code(),
                Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn remove_unknown_and_before_start() {
        let (s, _d) = server();
        let err = s
            .remove(Request::new(RemoveRequest {
                environment_id: "nope".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        let id = s
            .create(Request::new(CreateRequest::default()))
            .await
            .unwrap()
            .into_inner()
            .environment_id;
        s.remove(Request::new(RemoveRequest { environment_id: id }))
            .await
            .unwrap();
        assert_eq!(s.0.slot_permits.available_permits(), s.0.cfg.slots);
        assert!(s.0.envs.lock().unwrap().is_empty());
    }

    #[test]
    fn image_env_merge() {
        let got = merge_image_env(
            &[
                "PATH=/usr/local/go/bin:/usr/bin:/bin".into(),
                "GOLANG_VERSION=1.26".into(),
                "LANG=C.UTF-8".into(),
            ],
            [
                ("PATH".into(), "/root/.local/bin:/usr/bin".into()),
                ("LANG".into(), "en_US.UTF-8".into()),
            ]
            .into(),
        );
        assert_eq!(
            got["PATH"],
            "/root/.local/bin:/usr/bin:/usr/local/go/bin:/bin"
        );
        assert_eq!(got["GOLANG_VERSION"], "1.26");
        assert_eq!(got["LANG"], "en_US.UTF-8");
        assert_eq!(
            merge_image_env(&["PATH=/opt/bin".into()], HashMap::new())["PATH"],
            "/opt/bin"
        );
    }
}
