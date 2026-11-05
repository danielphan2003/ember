// Generates the plugin.v1alpha gRPC code (protox parses the proto in pure
// Rust, so no protoc is needed) and embeds the guest agent.
//
// The agent is a separate static binary: `just build` compiles it first and
// passes its path in EMBER_AGENT. Without it, ember still builds (for tests
// and `cargo check`) but refuses to serve.
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/plugin.proto");
    let fds = protox::compile(["proto/plugin.proto"], ["proto"])?;
    tonic_prost_build::configure().compile_fds(fds)?;

    println!("cargo:rerun-if-env-changed=EMBER_AGENT");
    let out = PathBuf::from(env::var("OUT_DIR")?).join("ember-agent");
    match env::var("EMBER_AGENT").ok().filter(|p| !p.is_empty()) {
        Some(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out)?;
        }
        None => fs::write(&out, b"")?,
    }
    Ok(())
}
