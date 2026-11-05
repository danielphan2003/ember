//! The guest agent, served on a unix socket outside a VM.

use std::{collections::HashMap, io::Read, path::Path, time::Duration};

use ember::{
    agent::{Agent, lookup_user_in},
    pb::{
        CopyInChunk, CopyOutRequest, ExecRequest, backend_plugin_client::BackendPluginClient,
        backend_plugin_server::BackendPluginServer, data_chunk, exec_output,
    },
};
use hyper_util::rt::TokioIo;
use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
use tonic::transport::{Channel, Endpoint, Server};

async fn client(dir: &Path) -> BackendPluginClient<Channel> {
    let sock = dir.join("agent.sock");
    let lis = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(BackendPluginServer::new(Agent))
            .serve_with_incoming(UnixListenerStream::new(lis)),
    );
    let ch = Endpoint::from_static("http://agent")
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
    BackendPluginClient::new(ch)
}

struct Ran {
    stdout: String,
    stderr: String,
    code: i32,
    failed: String,
}

async fn run(
    c: &mut BackendPluginClient<Channel>,
    cmd: &[&str],
    env: &[(&str, &str)],
    dir: &Path,
) -> Ran {
    let req = ExecRequest {
        command: cmd.iter().map(|s| s.to_string()).collect(),
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
        workdir: dir.to_string_lossy().into(),
        ..Default::default()
    };
    let mut s = c.exec(req).await.unwrap().into_inner();
    let mut r = Ran {
        stdout: String::new(),
        stderr: String::new(),
        code: -1,
        failed: String::new(),
    };
    while let Some(msg) = s.next().await {
        match msg.unwrap().output.unwrap() {
            exec_output::Output::Data(d) if d.stream == data_chunk::Stream::Stderr as i32 => {
                r.stderr += &String::from_utf8_lossy(&d.data)
            }
            exec_output::Output::Data(d) => r.stdout += &String::from_utf8_lossy(&d.data),
            exec_output::Output::ExecComplete(c) => r.code = c.exit_code,
            exec_output::Output::ExecFailed(f) => r.failed = f.error_message,
        }
    }
    r
}

#[tokio::test]
async fn exec_streams_and_exit_code() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let dir = tmp.path().join("new/workdir");
    let r = run(
        &mut c,
        &[
            "sh",
            "-c",
            r#"echo "$GREETING from $(pwd)"; echo oops >&2; exit 3"#,
        ],
        &[("GREETING", "hello"), ("PATH", "/usr/bin:/bin")],
        &dir,
    )
    .await;
    assert_eq!(r.failed, "");
    assert_eq!(r.stdout, format!("hello from {}\n", dir.display()));
    assert_eq!((r.stderr.as_str(), r.code), ("oops\n", 3));
}

#[tokio::test]
async fn exec_missing_binary_and_request_path() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let r = run(&mut c, &["no-such-binary-ember"], &[], tmp.path()).await;
    assert!(r.failed.contains("not found in PATH"), "{}", r.failed);

    let bin = tmp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let script = bin.join("ember-hello");
    std::fs::write(&script, "#!/bin/sh\necho from-request-path\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let r = run(&mut c, &["ember-hello"], &[("PATH", &path)], tmp.path()).await;
    assert_eq!((r.stdout.as_str(), r.code), ("from-request-path\n", 0));
}

#[tokio::test]
async fn exec_does_not_wait_for_background_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let t0 = std::time::Instant::now();
    let r = run(
        &mut c,
        &["sh", "-c", "sleep 5 & echo started"],
        &[],
        tmp.path(),
    )
    .await;
    assert_eq!((r.stdout.as_str(), r.code), ("started\n", 0));
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "waited {:?} for a background process",
        t0.elapsed()
    );
}

#[tokio::test]
async fn exec_cancel_kills_process_group() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let marker = tmp.path().join("survived");
    let script = format!("(sleep 2; touch {}) & echo started; wait", marker.display());
    let req = ExecRequest {
        command: vec!["sh".into(), "-c".into(), script],
        workdir: tmp.path().to_string_lossy().into(),
        ..Default::default()
    };
    let mut s = c.exec(req).await.unwrap().into_inner();
    s.next().await.unwrap().unwrap(); // "started"
    drop(s); // cancels the call
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        !marker.exists(),
        "the background child survived cancellation"
    );
}

fn tar_of(entries: &[(&str, tar::EntryType, &str)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for &(name, kind, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(0o755);
        if kind == tar::EntryType::Symlink {
            h.set_size(0);
            b.append_link(&mut h, name, body).unwrap();
        } else {
            h.set_size(body.len() as u64);
            b.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
    }
    b.into_inner().unwrap()
}

async fn copy_in(
    c: &mut BackendPluginClient<Channel>,
    dest: &Path,
    data: Vec<u8>,
) -> Result<(), tonic::Status> {
    let mut chunks = vec![CopyInChunk {
        environment_id: Some("env".into()),
        dest_path: Some(dest.to_string_lossy().into()),
        data: vec![],
    }];
    // Small chunks exercise reassembly.
    chunks.extend(data.chunks(7).map(|d| CopyInChunk {
        data: d.to_vec(),
        ..Default::default()
    }));
    c.copy_in(tokio_stream::iter(chunks)).await.map(drop)
}

async fn copy_out(c: &mut BackendPluginClient<Channel>, src: &Path) -> Vec<u8> {
    let mut s = c
        .copy_out(CopyOutRequest {
            src_path: src.to_string_lossy().into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut out = vec![];
    while let Some(ch) = s.next().await {
        out.extend(ch.unwrap().data);
    }
    out
}

#[tokio::test]
async fn copy_in_and_out() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let dest = tmp.path().join("act");
    use tar::EntryType::{Directory, Regular, Symlink};
    copy_in(
        &mut c,
        &dest,
        tar_of(&[
            ("dir/", Directory, ""),
            ("dir/script.sh", Regular, "echo hi"),
            ("link", Symlink, "dir/script.sh"),
        ]),
    )
    .await
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(dest.join("dir/script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read_link(dest.join("link")).unwrap(),
        Path::new("dir/script.sh")
    );

    // A file comes back as one entry named after it.
    let data = copy_out(&mut c, &dest.join("dir/script.sh")).await;
    let mut ar = tar::Archive::new(&data[..]);
    let mut e = ar.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(e.path().unwrap(), Path::new("script.sh"));
    let mut body = String::new();
    e.read_to_string(&mut body).unwrap();
    assert_eq!(body, "echo hi");
}

#[tokio::test]
async fn copy_out_missing_is_an_empty_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let data = copy_out(&mut c, Path::new("/nonexistent/ember")).await;
    assert_eq!(tar::Archive::new(&data[..]).entries().unwrap().count(), 0);
}

#[tokio::test]
async fn copy_in_stays_inside_dest() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = client(tmp.path()).await;
    let dest = tmp.path().join("dest");
    let outside = tempfile::tempdir().unwrap();
    use tar::EntryType::{Regular, Symlink};
    // "../escaped" is cleaned to "escaped" under dest.
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(1);
    h.set_mode(0o644);
    h.set_entry_type(Regular);
    h.as_gnu_mut().unwrap().name[..10].copy_from_slice(b"../escaped");
    h.set_cksum();
    b.append(&h, &b"x"[..]).unwrap();
    copy_in(&mut c, &dest, b.into_inner().unwrap())
        .await
        .unwrap();
    assert!(dest.join("escaped").exists() && !tmp.path().join("escaped").exists());

    // A symlink pointing outside cannot be written through.
    let res = copy_in(
        &mut c,
        &dest,
        tar_of(&[
            ("evil", Symlink, outside.path().to_str().unwrap()),
            ("evil/pwned", Regular, "x"),
        ]),
    )
    .await;
    assert!(res.is_err());
    assert!(!outside.path().join("pwned").exists());
}

#[test]
fn users() {
    let etc = tempfile::tempdir().unwrap();
    std::fs::write(
        etc.path().join("passwd"),
        "root:x:0:0::/root:/bin/sh\nnode:x:1000:1000::/home/node:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(etc.path().join("group"), "root:x:0:\nstaff:x:50:\n").unwrap();
    let u = lookup_user_in("node", etc.path()).unwrap();
    assert_eq!(
        (u.ids, u.home.as_deref()),
        (Some((1000, 1000)), Some("/home/node"))
    );
    assert_eq!(
        lookup_user_in("node:staff", etc.path()).unwrap().ids,
        Some((1000, 50))
    );
    assert_eq!(
        lookup_user_in("0:50", etc.path()).unwrap().ids,
        Some((0, 50))
    );
    assert_eq!(
        lookup_user_in("1234", etc.path()).unwrap().ids,
        Some((1234, 1234))
    );
    assert_eq!(lookup_user_in("", etc.path()).unwrap().ids, None);
    assert!(lookup_user_in("ghost", etc.path()).is_err());
}
