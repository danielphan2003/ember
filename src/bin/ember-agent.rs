//! ember-agent runs inside each ember microVM as PID 1.
//!
//! As PID 1 it mounts the pseudo-filesystems, configures the network from
//! the kernel command line, then supervises `ember-agent serve`, which
//! answers the host over vsock. For tests it can serve on a unix socket:
//! `ember-agent serve --listen unix:/tmp/agent.sock`.

use ember::{
    AGENT_PORT,
    agent::{Agent, init},
    pb::backend_plugin_server::BackendPluginServer,
};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tonic::transport::Server;

fn main() {
    if std::process::id() == 1 {
        init::init();
        init::supervise();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("serve") {
        eprintln!("usage: ember-agent serve [--listen unix:PATH]");
        std::process::exit(2);
    }
    let listen = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(serve(listen)) {
        eprintln!("ember-agent: {e}");
        std::process::exit(1);
    }
}

async fn serve(listen: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let svc = BackendPluginServer::new(Agent).max_decoding_message_size(16 << 20);
    let server = Server::builder().add_service(svc);
    match listen.as_deref().and_then(|l| l.strip_prefix("unix:")) {
        Some(path) => {
            let _ = std::fs::remove_file(path);
            let lis = tokio::net::UnixListener::bind(path)?;
            server
                .serve_with_incoming(UnixListenerStream::new(lis))
                .await?;
        }
        None => {
            let lis = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, AGENT_PORT))?;
            eprintln!("ember-agent: ready on vsock port {AGENT_PORT}");
            server.serve_with_incoming(lis.incoming()).await?;
        }
    }
    Ok(())
}
