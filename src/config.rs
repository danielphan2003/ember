//! ember's configuration file. Every field has a default, so an empty file
//! (or none) is a working configuration.

use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where the runner reaches ember: unix:///path (keep it a unix socket:
    /// the protocol has no authentication).
    pub listen: String,
    /// Image cache and per-VM working directories.
    pub state_dir: PathBuf,
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    /// Owns the tap devices and runs the VMs (used by `ember host up`).
    /// Empty: the user who ran sudo.
    pub user: String,
    /// VMs that may run at once; each has its own tap and /30 network.
    pub slots: usize,
    /// Names the taps (<prefix>0, ...), the nftables table and the firewalld zone.
    pub tap_prefix: String,
    /// Carved into one /30 per slot.
    pub subnet: String,
    /// Guests cannot reach the host, so these must be public resolvers.
    pub dns: Vec<String>,
    pub default_image: String,
    /// How long a tag's digest is trusted before asking the registry again.
    #[serde(deserialize_with = "duration")]
    pub image_refresh: Duration,
    /// Cached images unused this long are deleted.
    #[serde(deserialize_with = "duration")]
    pub image_keep: Duration,
    /// Largest unpacked image accepted, so a hostile image cannot fill the disk.
    pub max_image_mib: u64,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
    /// A VM starts only while MemAvailable covers it plus this reserve.
    pub host_reserve_mib: u32,
    /// Memory promised to all VMs together; 0 means MemTotal minus the reserve.
    pub memory_budget_mib: u32,
    /// No VM starts while state_dir has less free space.
    pub min_free_gib: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "unix:///run/ember/ember.sock".into(),
            state_dir: "/var/lib/ember".into(),
            firecracker: "/usr/local/lib/ember/firecracker".into(),
            kernel: "/usr/local/lib/ember/vmlinux".into(),
            user: "ember".into(),
            slots: 8,
            tap_prefix: "ember".into(),
            subnet: "172.30.0.0/16".into(),
            dns: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            default_image: "docker.io/library/node:24-trixie".into(),
            image_refresh: Duration::from_secs(3600),
            image_keep: Duration::from_secs(7 * 24 * 3600),
            max_image_mib: 16 << 10,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 16,
            host_reserve_mib: 1024,
            memory_budget_mib: 0,
            min_free_gib: 20,
        }
    }
}

/// Accepts Go-style durations: "90s", "30m", "1h", "168h", "1h30m".
fn duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

pub fn parse_duration(s: &str) -> Result<Duration> {
    let mut total = 0u64;
    let mut num = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u64 = num.parse().with_context(|| format!("bad duration {s:?}"))?;
        num.clear();
        total += n * match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => bail!("bad duration {s:?}: unit must be s, m, h or d"),
        };
    }
    if !num.is_empty() {
        bail!("bad duration {s:?}: missing unit");
    }
    Ok(Duration::from_secs(total))
}

/// One VM's network position.
#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub index: usize,
    pub tap: String,
    pub host: Ipv4Addr,
    pub guest: Ipv4Addr,
    pub mac: String,
}

impl Slot {
    pub fn guest_cidr(&self) -> String {
        format!("{}/30", self.guest)
    }
    pub fn host_cidr(&self) -> String {
        format!("{}/30", self.host)
    }
}

impl Config {
    /// Reads path over the defaults. A missing file is not an error.
    pub fn load(path: &str) -> Result<Self> {
        let mut c: Config = match std::fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => Config::default(),
            Ok(s) => serde_yaml::from_str(&s).with_context(|| path.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| path.to_string()),
        };
        // Firecracker runs in each VM's own directory: make paths absolute.
        let cwd = std::env::current_dir()?;
        for p in [&mut c.state_dir, &mut c.firecracker, &mut c.kernel] {
            if p.is_relative() {
                *p = cwd.join(&*p);
            }
        }
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        if self.slots < 1 {
            bail!("slots must be at least 1");
        }
        let (base, bits) = self.subnet_parts()?;
        let _ = base;
        if bits > 30 || (1u64 << (32 - bits)) / 4 < self.slots as u64 {
            bail!(
                "subnet {} holds fewer than slots={} /30 networks",
                self.subnet,
                self.slots
            );
        }
        let p = &self.tap_prefix;
        if p.is_empty()
            || p.len() > 8
            || !p.starts_with(|c: char| c.is_ascii_lowercase())
            || !p
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            bail!(
                "tap_prefix {p:?} must be 1-8 lowercase letters or digits, starting with a letter"
            );
        }
        if self.vcpus < 1 || self.memory_mib < 128 || self.disk_gib < 1 {
            bail!("vcpus, memory_mib and disk_gib must be positive (memory_mib >= 128)");
        }
        if self.max_image_mib < 64 {
            bail!("max_image_mib must be at least 64");
        }
        if let Some(l) = self.listen.strip_prefix("unix://") {
            if l.is_empty() {
                bail!("listen: empty unix socket path");
            }
        } else {
            bail!("listen must be unix:///path: the plugin protocol has no authentication");
        }
        Ok(())
    }

    fn subnet_parts(&self) -> Result<(u32, u32)> {
        let (a, l) = self
            .subnet
            .split_once('/')
            .context("subnet must be a.b.c.d/len")?;
        let ip: Ipv4Addr = a
            .parse()
            .with_context(|| format!("subnet {:?}", self.subnet))?;
        let bits: u32 = l
            .parse()
            .with_context(|| format!("subnet {:?}", self.subnet))?;
        if bits > 32 {
            bail!("subnet {:?}: bad prefix length", self.subnet);
        }
        let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
        Ok((u32::from(ip) & mask, bits))
    }

    pub fn socket_path(&self) -> PathBuf {
        PathBuf::from(self.listen.trim_start_matches("unix://"))
    }

    /// Every slot's tap and addresses.
    pub fn slot_list(&self) -> Vec<Slot> {
        let (base, _) = self.subnet_parts().expect("validated");
        (0..self.slots)
            .map(|i| {
                let net = base + i as u32 * 4;
                let guest = Ipv4Addr::from(net + 2);
                let g = guest.octets();
                Slot {
                    index: i,
                    tap: format!("{}{i}", self.tap_prefix),
                    host: Ipv4Addr::from(net + 1),
                    guest,
                    mac: format!("06:00:{:02x}:{:02x}:{:02x}:{:02x}", g[0], g[1], g[2], g[3]),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots() {
        let c = Config {
            slots: 3,
            ..Config::default()
        };
        let s = &c.slot_list()[2];
        assert_eq!(s.tap, "ember2");
        assert_eq!(s.host.to_string(), "172.30.0.9");
        assert_eq!(s.guest_cidr(), "172.30.0.10/30");
        assert_eq!(s.mac, "06:00:ac:1e:00:0a");
    }

    #[test]
    fn validation() {
        let bad: [fn(&mut Config); 5] = [
            |c| {
                c.subnet = "10.0.0.0/30".into();
                c.slots = 2
            },
            |c| c.tap_prefix = "Ember-0".into(),
            |c| c.subnet = "fd00::/64".into(),
            |c| c.slots = 0,
            |c| c.listen = "0.0.0.0:9000".into(),
        ];
        for (i, f) in bad.iter().enumerate() {
            let mut c = Config::default();
            f(&mut c);
            assert!(c.validate().is_err(), "case {i} should fail");
        }
        Config::default().validate().unwrap();
    }

    #[test]
    fn load_merges_over_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.yaml");
        std::fs::write(&p, "slots: 4\nstate_dir: rel\nimage_keep: 1h30m\n").unwrap();
        let c = Config::load(p.to_str().unwrap()).unwrap();
        assert_eq!(c.slots, 4);
        assert_eq!(c.vcpus, Config::default().vcpus);
        assert!(c.state_dir.is_absolute());
        assert_eq!(c.image_keep, Duration::from_secs(5400));
        assert!(Config::load(dir.path().join("missing").to_str().unwrap()).is_ok());
        std::fs::write(&p, "slotz: 4\n").unwrap();
        assert!(
            Config::load(p.to_str().unwrap()).is_err(),
            "unknown keys are rejected"
        );
    }
}
