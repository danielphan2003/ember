//! Boots real microVMs. Runs only when EMBER_E2E_CONFIG names an ember
//! config whose host network is up (`ember host up`) and no `ember serve`
//! uses the same slots. `just e2e` builds and runs it natively (KVM).

use std::{io::Read, net::Ipv4Addr, path::Path, time::Instant};

use ember::{
    AGENT,
    config::Config,
    pb::{
        CopyInChunk, CopyOutRequest, CreateRequest, ExecRequest, RemoveRequest, StartRequest,
        backend_plugin_client::BackendPluginClient, backend_plugin_server::BackendPluginServer,
        exec_output, start_output,
    },
    server::Server,
};
use hyper_util::rt::TokioIo;
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint};

const IMAGE: &str = "docker.io/library/alpine:3.22";

async fn setup(dir: &Path) -> Option<BackendPluginClient<Channel>> {
    let path = std::env::var("EMBER_E2E_CONFIG")
        .ok()
        .filter(|p| !p.is_empty())?;
    let cfg = Config::load(&path).unwrap();
    assert!(cfg.slots >= 2, "e2e needs at least 2 slots");
    assert!(
        !AGENT.is_empty(),
        "build with `just e2e` so the agent is embedded"
    );
    let server = Server::new(cfg, AGENT).unwrap();
    let sock = dir.join("ember.sock");
    let lis = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(BackendPluginServer::new(server))
            .serve_with_incoming(UnixListenerStream::new(lis)),
    );
    let ch = Endpoint::from_static("http://ember")
        .connect_with_connector(tower::service_fn(move |_| {
            let sock = sock.clone();
            async move {
                tokio::net::UnixStream::connect(sock)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await
        .unwrap();
    Some(BackendPluginClient::new(ch))
}

struct Vm {
    c: BackendPluginClient<Channel>,
    id: String,
}

impl Vm {
    async fn boot(c: &BackendPluginClient<Channel>) -> Vm {
        let mut c = c.clone();
        let t0 = Instant::now();
        let id = c
            .create(CreateRequest {
                image: IMAGE.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .environment_id;
        let mut s = c
            .start(StartRequest {
                environment_id: id.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        while let Some(msg) = s.next().await {
            match msg.unwrap().output.unwrap() {
                start_output::Output::Data(d) => eprint!("{}", String::from_utf8_lossy(&d.data)),
                start_output::Output::StartComplete(_) => break,
            }
        }
        eprintln!("{id} ready after {} ms", t0.elapsed().as_millis());
        Vm { c, id }
    }

    async fn sh(&mut self, script: &str) -> (String, i32) {
        let req = ExecRequest {
            environment_id: self.id.clone(),
            command: vec!["sh".into(), "-c".into(), script.into()],
            workdir: "/root".into(),
            env: [(
                "PATH".to_string(),
                "/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            )]
            .into(),
            ..Default::default()
        };
        let mut s = self.c.exec(req).await.unwrap().into_inner();
        let mut out = String::new();
        while let Some(msg) = s.next().await {
            match msg.unwrap().output.unwrap() {
                exec_output::Output::Data(d) => out += &String::from_utf8_lossy(&d.data),
                exec_output::Output::ExecComplete(c) => return (out, c.exit_code),
                exec_output::Output::ExecFailed(f) => panic!("exec failed: {}", f.error_message),
            }
        }
        panic!("exec ended without completion")
    }

    async fn remove(mut self) {
        self.c
            .remove(RemoveRequest {
                environment_id: self.id.clone(),
            })
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(c) = setup(tmp.path()).await else {
        return;
    };
    let mut vm = Vm::boot(&c).await;
    assert_eq!(vm.sh("echo hi; exit 4").await, ("hi\n".into(), 4));

    // CopyIn a script, run it, CopyOut what it wrote.
    let body = "#!/bin/sh\necho copied > /ember/act/out.txt\n";
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(body.len() as u64);
    h.set_mode(0o755);
    b.append_data(&mut h, "run.sh", body.as_bytes()).unwrap();
    let chunks = vec![
        CopyInChunk {
            environment_id: Some(vm.id.clone()),
            dest_path: Some("/ember/act".into()),
            data: vec![],
        },
        CopyInChunk {
            data: b.into_inner().unwrap(),
            ..Default::default()
        },
    ];
    vm.c.copy_in(tokio_stream::iter(chunks)).await.unwrap();
    assert_eq!(vm.sh("/ember/act/run.sh").await.1, 0);
    let mut s =
        vm.c.copy_out(CopyOutRequest {
            environment_id: vm.id.clone(),
            src_path: "/ember/act/out.txt".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut data = vec![];
    while let Some(ch) = s.next().await {
        data.extend(ch.unwrap().data);
    }
    let mut ar = tar::Archive::new(&data[..]);
    let mut text = String::new();
    ar.entries()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "copied\n");

    // A background process does not hold the step.
    let t0 = Instant::now();
    assert_eq!(vm.sh("sleep 30 & echo bg").await, ("bg\n".into(), 0));
    assert!(t0.elapsed().as_secs() < 5);
    vm.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_network_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(c) = setup(tmp.path()).await else {
        return;
    };
    let (mut a, mut b) = (Vm::boot(&c).await, Vm::boot(&c).await);
    let ip = |out: (String, i32)| out.0.trim().to_string();
    let a_ip = ip(a
        .sh("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1")
        .await);
    let b_ip = ip(b
        .sh("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1")
        .await);
    let gw = ip(a.sh("ip route | awk '/default/ {print $3}'").await);

    // Positive controls: the probes below must be able to succeed at all.
    assert_eq!(
        a.sh("wget -q -T 10 -O /dev/null https://example.com && echo ok")
            .await
            .1,
        0,
        "internet unreachable"
    );
    assert_eq!(
        a.sh("nc -z -w 3 1.1.1.1 443").await.1,
        0,
        "nc cannot reach the internet, so the probes prove nothing"
    );
    assert_eq!(
        a.sh(&format!("nc -z -w 3 -s {a_ip} 1.1.1.1 443")).await.1,
        0,
        "nc -s with the guest's own address"
    );

    let mut blocked = vec![
        ("gateway (host)", gw),
        ("other VM", b_ip.clone()),
        ("cloud metadata", "169.254.169.254".into()),
        ("tailnet", "100.100.100.100".into()),
        ("private LAN", "192.168.1.1".into()),
    ];
    if let Some(lan) = host_lan_addr() {
        blocked.push(("host LAN address", lan.to_string()));
    }
    for (name, ip) in &blocked {
        let probe = format!("nc -z -w 2 {ip} 22 || nc -z -w 2 {ip} 80 || nc -z -w 2 {ip} 443");
        assert_ne!(
            a.sh(&probe).await.1,
            0,
            "{name} ({ip}) is reachable from a guest"
        );
    }
    // Spoofing another slot's address must not get packets out.
    let spoof = format!("ip addr add {b_ip}/32 dev eth0 && nc -z -w 3 -s {b_ip} 1.1.1.1 443");
    assert_ne!(
        a.sh(&spoof).await.1,
        0,
        "spoofed source address reached the internet"
    );
    // SMTP is dropped.
    assert_ne!(
        a.sh("nc -z -w 3 smtp.gmail.com 25").await.1,
        0,
        "outbound SMTP is open"
    );
    a.remove().await;
    b.remove().await;
}

/// The host's first private IPv4 address outside ember's ranges, if any.
fn host_lan_addr() -> Option<Ipv4Addr> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|w| w.split('/').next()?.parse::<Ipv4Addr>().ok())
        .find(|ip| ip.is_private() && ip.octets()[0] != 172)
}
