//! ember runs Forgejo Actions jobs in Firecracker microVMs.
//!
//! The host side (`ember serve`) implements the forgejo-runner's
//! `plugin.v1alpha` BackendPlugin service. Each job gets a microVM booted
//! from a cached ext4 image of its OCI image, with `ember-agent` as PID 1;
//! the agent serves Exec, CopyIn and CopyOut of the same service over vsock.

pub mod agent;
pub mod authority;
pub mod config;
pub mod hostnet;
pub mod image;
pub mod registry;
pub mod server;
pub mod vm;

/// Generated from Forgejo's MIT-licensed `plugin.proto`.
pub mod pb {
    tonic::include_proto!("plugin.v1alpha");
}

/// The static ember-agent binary installed into every guest root filesystem.
/// Empty when ember was built without it (see build.rs).
pub static AGENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ember-agent"));

/// The vsock port ember-agent listens on.
pub const AGENT_PORT: u32 = 1024;
