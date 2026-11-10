//! ember runs Forgejo Actions jobs in Firecracker microVMs.

use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ember::{
    AGENT,
    config::Config,
    hostnet,
    pb::{
        self, CreateRequest, ExecRequest, RemoveRequest, StartRequest,
        backend_plugin_client::BackendPluginClient, backend_plugin_server::BackendPluginServer,
        exec_output, start_output,
    },
    server::Server,
};
use hyper_util::rt::TokioIo;
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
use tonic::transport::Endpoint;

#[derive(Parser)]
#[command(version, about = "Run Forgejo Actions jobs in Firecracker microVMs")]
struct Cli {
    /// Configuration file; every key is optional.
    #[arg(
        long,
        global = true,
        env = "EMBER_CONFIG",
        default_value = "/etc/ember/config.yaml"
    )]
    config: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the runner's plugin protocol on the configured socket.
    Serve,
    /// Boot a VM through a running `ember serve`, run one command, tear it down.
    Run {
        /// Image (default: default_image from the config).
        #[arg(short, long, default_value = "")]
        image: String,
        #[arg(long)]
        vcpus: Option<u32>,
        /// Memory in MiB.
        #[arg(long)]
        memory: Option<u32>,
        /// Do not print boot and timing lines.
        #[arg(short, long)]
        quiet: bool,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Build cached root filesystems ahead of time.
    Pull { images: Vec<String> },
    /// Delete cached images unused for image_keep.
    Prune,
    /// Check that this host can run ember; changes nothing.
    Doctor,
    /// (root) Create or remove the tap devices and firewall rules.
    Host {
        #[arg(value_parser = ["up", "down"])]
        action: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(dispatch(cli)) {
        // gRPC errors read best as their message alone.
        match e.downcast_ref::<tonic::Status>() {
            Some(s) => eprintln!("ember: {}", s.message()),
            None => eprintln!("ember: {e:#}"),
        }
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    match cli.cmd {
        Cmd::Serve => serve(cfg).await,
        Cmd::Run {
            image,
            vcpus,
            memory,
            quiet,
            command,
        } => run(cfg, image, vcpus, memory, quiet, command).await,
        Cmd::Pull { images } => pull(cfg, images).await,
        Cmd::Prune => {
            let server = Server::new(cfg.clone(), AGENT)?;
            for r in server.images().prune(cfg.image_keep) {
                println!("removed {r}");
            }
            Ok(())
        }
        Cmd::Doctor => doctor(&cfg),
        Cmd::Host { action } if action == "up" => hostnet::up(&cfg),
        Cmd::Host { .. } => hostnet::down(&cfg),
    }
}

/// Fails fast on problems that would otherwise surface as a confusing job
/// failure.
fn preflight(cfg: &Config) -> Result<()> {
    if AGENT.is_empty() {
        bail!("built without the guest agent; build with `just build`");
    }
    for p in [&cfg.firecracker, &cfg.kernel, &PathBuf::from("/dev/kvm")] {
        std::fs::metadata(p).with_context(|| format!("{} (run `ember doctor`)", p.display()))?;
    }
    std::fs::create_dir_all(&cfg.state_dir)?;
    Ok(())
}

async fn serve(cfg: Config) -> Result<()> {
    use std::io::IsTerminal;
    // No colour codes in the journal.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
    preflight(&cfg)?;
    let server = Server::new(cfg.clone(), AGENT)?;
    server.clean_stale();
    let keep = cfg.image_keep;
    let janitor = server.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let removed = janitor.images().prune(keep);
            if !removed.is_empty() {
                tracing::info!(count = removed.len(), "pruned images");
            }
            let dirs = janitor.prune_vm_dirs();
            if dirs > 0 {
                tracing::info!(count = dirs, "removed orphaned VM directories");
            }
        }
    });

    let path = cfg.socket_path();
    let _ = std::fs::remove_file(&path);
    let lis = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("listen on {}", path.display()))?;
    // The runner reaches the socket through the ember group; see deploy/.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;

    let (health, health_service) = tonic_health::server::health_reporter();
    health
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    let svc = BackendPluginServer::new(server.clone()).max_decoding_message_size(16 << 20);

    let shutdown = {
        let server = server.clone();
        async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
            tracing::info!("shutting down");
            server.kill_all(); // unblocks calls waiting on guests
        }
    };
    tracing::info!(version = env!("CARGO_PKG_VERSION"), listen = %cfg.listen, slots = cfg.slots, "ember ready");
    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(svc)
        .serve_with_incoming_shutdown(
            UnixListenerStream::new(lis).map(|c| c.map(ember::authority::wrap)),
            shutdown,
        )
        .await?;
    server.shutdown().await;
    Ok(())
}

async fn connect(path: &Path) -> Result<BackendPluginClient<tonic::transport::Channel>> {
    let path = path.to_path_buf();
    let channel = Endpoint::from_static("http://ember")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await?;
    Ok(BackendPluginClient::new(channel).max_decoding_message_size(16 << 20))
}

/// Talks to a running `ember serve` exactly like the Forgejo runner does:
/// Create, Start, Exec, Remove.
async fn run(
    cfg: Config,
    image: String,
    vcpus: Option<u32>,
    memory: Option<u32>,
    quiet: bool,
    mut command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        command = vec![
            "sh".into(),
            "-c".into(),
            "uname -a; head -2 /etc/os-release".into(),
        ];
    }
    let mut c = connect(&cfg.socket_path())
        .await
        .with_context(|| format!("is `ember serve` running at {}?", cfg.listen))?;
    let mut opts = std::collections::HashMap::new();
    if let Some(v) = vcpus {
        opts.insert("vcpus".to_string(), v.to_string());
    }
    if let Some(m) = memory {
        opts.insert("memory_mib".to_string(), m.to_string());
    }
    let t0 = Instant::now();
    let id = c
        .create(CreateRequest {
            image,
            name: "ember-run".into(),
            backend_options: opts,
            ..Default::default()
        })
        .await?
        .into_inner()
        .environment_id;
    let code = run_in(&mut c, &id, command, quiet, t0).await;
    let _ = c.remove(RemoveRequest { environment_id: id }).await;
    let code = code?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

async fn run_in(
    c: &mut BackendPluginClient<tonic::transport::Channel>,
    id: &str,
    command: Vec<String>,
    quiet: bool,
    t0: Instant,
) -> Result<i32> {
    let mut start = c
        .start(StartRequest {
            environment_id: id.into(),
        })
        .await?
        .into_inner();
    let mut env = std::collections::HashMap::from([("HOME".to_string(), "/root".to_string())]);
    while let Some(msg) = start.next().await {
        match msg?.output {
            Some(start_output::Output::Data(d)) if !quiet => {
                std::io::stderr().write_all(&d.data)?
            }
            Some(start_output::Output::StartComplete(done)) => {
                env.extend(done.image_env);
                break;
            }
            _ => {}
        }
    }
    let ready = t0.elapsed();
    let mut exec = c
        .exec(ExecRequest {
            environment_id: id.into(),
            command,
            env,
            workdir: "/root".into(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let mut code = 0;
    while let Some(msg) = exec.next().await {
        match msg?.output {
            Some(exec_output::Output::Data(d))
                if d.stream == pb::data_chunk::Stream::Stderr as i32 =>
            {
                std::io::stderr().write_all(&d.data)?
            }
            Some(exec_output::Output::Data(d)) => std::io::stdout().write_all(&d.data)?,
            Some(exec_output::Output::ExecComplete(done)) => code = done.exit_code,
            Some(exec_output::Output::ExecFailed(f)) => bail!(f.error_message),
            None => {}
        }
    }
    if !quiet {
        eprintln!(
            "ember: ready in {} ms, command finished at {} ms",
            ready.as_millis(),
            t0.elapsed().as_millis()
        );
    }
    Ok(code)
}

async fn pull(cfg: Config, mut images: Vec<String>) -> Result<()> {
    if images.is_empty() {
        images.push(cfg.default_image.clone());
    }
    let server = Server::new(cfg, AGENT)?;
    for i in images {
        let img = server
            .images()
            .ensure(&i, Arc::new(|l: String| println!("{l}")))
            .await?;
        println!("{i} -> {}", img.digest);
    }
    Ok(())
}

/// Checks every host requirement and says how to fix each failure.
fn doctor(cfg: &Config) -> Result<()> {
    let mut failed = 0;
    let mut check = |name: &str, res: Result<()>, fix: &str| match res {
        Ok(()) => println!("  ok    {name}"),
        Err(e) => {
            failed += 1;
            println!("  FAIL  {name}: {e:#}\n        fix: {fix}");
        }
    };
    println!("ember doctor");
    check(
        "guest agent embedded",
        if AGENT.is_empty() {
            Err(anyhow::anyhow!("missing"))
        } else {
            Ok(())
        },
        "build with `just build`",
    );
    check(
        "/dev/kvm is usable",
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map(drop)
            .map_err(Into::into),
        "enable virtualization in firmware; add the user to the kvm group",
    );
    check(
        &format!("firecracker at {}", cfg.firecracker.display()),
        executable(&cfg.firecracker),
        "run `just fetch` or set firecracker: in the config",
    );
    check(
        &format!("guest kernel at {}", cfg.kernel.display()),
        std::fs::metadata(&cfg.kernel).map(drop).map_err(Into::into),
        "run `just fetch` or set kernel: in the config",
    );
    check(
        "mke2fs is e2fsprogs 1.47.1 or newer",
        mke2fs_ok(),
        "install e2fsprogs 1.47.1 or newer",
    );
    for tool in ["debugfs", "resize2fs"] {
        check(
            &format!("{tool} available"),
            on_path(tool),
            "install e2fsprogs",
        );
    }
    check(
        &format!("state dir {} supports reflinks", cfg.state_dir.display()),
        reflink_ok(&cfg.state_dir),
        "use btrfs or XFS for state_dir (works without, but each job copies its image)",
    );
    let owner = if cfg.user.is_empty() {
        std::env::var("USER").unwrap_or_default()
    } else {
        cfg.user.clone()
    };
    match hostnet::uid_of(&owner) {
        None => check(
            &format!("user {owner} exists"),
            Err(anyhow::anyhow!("not found")),
            "create it, e.g. with deploy/sysusers.conf",
        ),
        Some(uid) => {
            check(&format!("user {owner} exists"), Ok(()), "");
            for s in cfg.slot_list() {
                let res = match hostnet::tap_owner(&s.tap) {
                    Some(o) if o == uid => Ok(()),
                    Some(o) => Err(anyhow::anyhow!("owned by uid {o}")),
                    None => Err(anyhow::anyhow!("missing")),
                };
                check(
                    &format!("tap {} owned by {owner}", s.tap),
                    res,
                    "run `sudo ember host up`",
                );
            }
        }
    }
    // Outside ember's zone, firewalld's default zone rejects the guests'
    // forwarded traffic, so jobs lose the network.
    if hostnet::firewalld_wanted() {
        for s in cfg.slot_list() {
            let res = match hostnet::firewalld_zone_of(&s.tap) {
                Ok(z) if z == cfg.tap_prefix => Ok(()),
                Ok(z) => Err(anyhow::anyhow!("in zone {z}")),
                Err(e) => Err(e),
            };
            check(
                &format!("tap {} in firewalld zone {}", s.tap, cfg.tap_prefix),
                res,
                "run `sudo ember host up`",
            );
        }
    }
    let fwd = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    check(
        "IPv4 forwarding on",
        if fwd.trim() == "1" {
            Ok(())
        } else {
            Err(anyhow::anyhow!("off"))
        },
        "run `sudo ember host up`",
    );
    if failed > 0 {
        bail!("{failed} check(s) failed");
    }
    println!("all good");
    Ok(())
}

fn executable(p: &Path) -> Result<()> {
    let md = std::fs::metadata(p)?;
    if md.permissions().mode() & 0o111 == 0 {
        bail!("not executable");
    }
    Ok(())
}

fn on_path(tool: &str) -> Result<()> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    if path.split(':').any(|d| Path::new(d).join(tool).exists()) {
        Ok(())
    } else {
        bail!("not found in PATH")
    }
}

fn mke2fs_ok() -> Result<()> {
    let o = std::process::Command::new("mke2fs").arg("-V").output()?;
    let text =
        String::from_utf8_lossy(&o.stderr).into_owned() + &String::from_utf8_lossy(&o.stdout);
    let v = text
        .split_whitespace()
        .nth(1)
        .context("cannot parse mke2fs -V")?;
    let parts: Vec<u32> = v.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let (maj, min, patch) = (
        parts[0],
        *parts.get(1).unwrap_or(&0),
        *parts.get(2).unwrap_or(&0),
    );
    if (maj, min, patch) >= (1, 47, 1) {
        Ok(())
    } else {
        bail!("version {v}")
    }
}

fn reflink_ok(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = tempfile::tempdir_in(dir)?;
    let a = tmp.path().join("a");
    std::fs::write(&a, b"ember")?;
    ember::vm::reflink(&a, &tmp.path().join("b"))?;
    Ok(())
}
