//! Prepares the host network for the VMs. Runs as root, once per boot
//! (`ember host up`), so the daemon itself needs no privileges.
//!
//! Each slot gets a tap device owned by the ember user and a /30 network.
//! An nftables table, named after the tap prefix, enforces the isolation:
//!
//! - guests cannot reach the host (input from the taps is dropped),
//! - nor each other, private networks, the tailnet's CGNAT range,
//!   link-local or multicast addresses,
//! - guests have no IPv6 and only TCP, UDP and ICMP (no 6in4 or GRE
//!   tunnels), at most 4096 tracked connections each, and no mail
//!   submission (ports 25, 465, 587, 2525) from your address,
//! - a guest can only send from its own address,
//! - everything else is masqueraded to the internet.
//!
//! iproute2, nft and (if running) firewall-cmd do the work.

use std::{
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::Config;

/// IPv4 destinations guests may never reach.
pub const BLOCKED: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
];

/// The nftables table for cfg. Taps are matched by name from a set, not a
/// wildcard, so another instance's taps never match.
pub fn ruleset(cfg: &Config) -> String {
    let slots = cfg.slot_list();
    let taps: Vec<String> = slots.iter().map(|s| format!("\"{}\"", s.tap)).collect();
    let pairs: Vec<String> = slots
        .iter()
        .map(|s| format!("\"{}\" . {}", s.tap, s.guest))
        .collect();
    format!(
        r#"table inet {table} {{
	set taps {{
		type ifname
		elements = {{ {taps} }}
	}}
	set blocked4 {{
		type ipv4_addr
		flags interval
		elements = {{ {blocked} }}
	}}
	set slots {{
		type ifname . ipv4_addr
		elements = {{ {pairs} }}
	}}
	set flows {{
		type ipv4_addr
		size 65535
		flags dynamic
	}}
	chain input {{
		type filter hook input priority filter - 10; policy accept;
		iifname @taps drop
	}}
	chain forward {{
		type filter hook forward priority filter - 10; policy accept;
		iifname @taps meta nfproto ipv6 drop
		iifname @taps iifname . ip saddr != @slots drop
		iifname @taps oifname @taps drop
		iifname @taps ip daddr @blocked4 drop
		iifname @taps ip protocol != {{ tcp, udp, icmp }} drop
		iifname @taps tcp dport {{ 25, 465, 587, 2525 }} drop
		iifname @taps ct state new add @flows {{ ip saddr ct count over 4096 }} drop
		oifname @taps ct state != {{ established, related }} drop
	}}
	chain postrouting {{
		type nat hook postrouting priority srcnat; policy accept;
		iifname @taps oifname != @taps masquerade
	}}
}}
"#,
        table = cfg.tap_prefix,
        taps = taps.join(", "),
        blocked = BLOCKED.join(", "),
        pairs = pairs.join(", "),
    )
}

fn run(name: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = Command::new(name);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().with_context(|| format!("run {name}"))?;
    if let Some(s) = stdin {
        use std::io::Write;
        child.stdin.take().expect("piped").write_all(s.as_bytes())?;
    }
    let o = child.wait_with_output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .trim()
    .to_string();
    if !o.status.success() {
        bail!("{name} {}: {text}", args.join(" "));
    }
    Ok(text)
}

fn owner(cfg: &Config) -> Result<String> {
    if !cfg.user.is_empty() {
        return Ok(cfg.user.clone());
    }
    std::env::var("SUDO_USER")
        .map_err(|_| anyhow!("user is empty in the config and SUDO_USER is not set"))
}

/// The uid that owns a tun/tap device, from sysfs.
pub fn tap_owner(tap: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/owner"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn uid_of(user: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.len() > 2 && f[0] == user)?[2]
        .parse()
        .ok()
}

/// Creates the taps and installs the ruleset. Idempotent.
pub fn up(cfg: &Config) -> Result<()> {
    let user = owner(cfg)?;
    let uid = uid_of(&user)
        .ok_or_else(|| anyhow!("user {user:?} does not exist (see deploy/sysusers.conf)"))?;
    for s in cfg.slot_list() {
        if tap_owner(&s.tap) != Some(uid) {
            let _ = run("ip", &["link", "del", &s.tap], None);
            run(
                "ip",
                &["tuntap", "add", "dev", &s.tap, "mode", "tap", "user", &user],
                None,
            )?;
        }
        run(
            "ip",
            &["addr", "replace", &s.host_cidr(), "dev", &s.tap],
            None,
        )?;
        // Guests never need the host's IPv6.
        let _ = std::fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", s.tap),
            "1",
        );
        run("ip", &["link", "set", &s.tap, "up"], None)?;
    }
    println!(
        "{} tap devices ready ({p}0..{p}{}, owner {user})",
        cfg.slots,
        cfg.slots - 1,
        p = cfg.tap_prefix
    );

    // Replace the table atomically: create-or-keep, delete, add, in one batch.
    let t = &cfg.tap_prefix;
    run(
        "nft",
        &["-f", "-"],
        Some(&format!(
            "table inet {t}\ndelete table inet {t}\n{}",
            ruleset(cfg)
        )),
    )?;
    println!("nftables table inet {t} installed");
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enable ip_forward")?;

    if firewalld_wanted() {
        if wait_for_firewalld()? {
            firewalld_up(cfg)?;
            println!("firewalld zone {t} holds the tap devices");
        } else {
            // Nothing is enforcing firewalld's zones, so the guests are not
            // rejected; the table above isolates them. Bindings from an
            // earlier `up`, if any, apply once firewalld runs again.
            eprintln!(
                "warning: firewalld stopped while starting; zone {t} is not applied. \
                 Run `ember host up` again once firewalld runs."
            );
        }
    }
    Ok(())
}

/// Removes the taps and the ruleset. The firewalld zone keeps its permanent
/// bindings: this runs at every shutdown, and the bindings make firewalld
/// put the taps back in the DROP zone the moment `up` recreates them.
pub fn down(cfg: &Config) -> Result<()> {
    let mut errs = vec![];
    for s in cfg.slot_list() {
        if std::path::Path::new(&format!("/sys/class/net/{}", s.tap)).exists()
            && let Err(e) = run("ip", &["link", "del", &s.tap], None)
        {
            errs.push(e.to_string());
        }
    }
    let t = &cfg.tap_prefix;
    if let Err(e) = run("nft", &["delete", "table", "inet", t], None)
        && !e.to_string().contains("No such file")
    {
        errs.push(e.to_string());
    }
    println!(
        "removed taps and table inet {t} (ip_forward, the firewalld zone {t} and policy {t}-egress are left as they are)"
    );
    if !errs.is_empty() {
        bail!(errs.join("; "));
    }
    Ok(())
}

/// firewalld's state from `firewall-cmd --state`, decided by exit code:
/// only "running" goes to stdout; "failed" (251, running a fallback config
/// because its own did not load) and "not running" (252) go to stderr.
fn firewalld_state() -> &'static str {
    let code = Command::new("firewall-cmd")
        .arg("--state")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code());
    match code {
        Some(0) => "running",
        Some(251) => "failed",
        _ => "not running",
    }
}

pub fn firewalld_running() -> bool {
    firewalld_state() == "running"
}

/// Whether firewalld is running or about to: at boot, `up` can start while
/// firewalld is still loading, and skipping the zone then leaves the taps
/// in the default zone, which rejects their forwarded traffic.
pub fn firewalld_wanted() -> bool {
    // is-active exits non-zero for "activating", so read its output directly.
    // systemd first: an unprivileged `firewall-cmd --state` needs polkit,
    // which can pop up an authorization dialog on a desktop.
    Command::new("systemctl")
        .args(["is-active", "firewalld.service"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| {
            matches!(
                String::from_utf8_lossy(&o.stdout).trim(),
                "active" | "activating" | "reloading"
            )
        })
        || firewalld_running()
}

/// Waits until firewalld runs (true) or gives up starting (false).
fn wait_for_firewalld() -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match firewalld_state() {
            "running" => return Ok(true),
            // Its configuration did not load; it runs a fallback one.
            "failed" => bail!(
                "firewalld is in its failed state (see `firewall-offline-cmd --check-config`)"
            ),
            _ => {}
        }
        if !firewalld_wanted() {
            return Ok(false);
        }
        if Instant::now() > deadline {
            bail!("firewalld is starting but did not report running within 90s");
        }
        sleep(Duration::from_millis(500));
    }
}

/// The firewalld zone a tap is in. Works without root.
pub fn firewalld_zone_of(tap: &str) -> Result<String> {
    run(
        "firewall-cmd",
        &[&format!("--get-zone-of-interface={tap}")],
        None,
    )
}

/// Puts the taps in a zone named after the tap prefix with target DROP: if
/// ember's table were ever flushed, the host would still refuse the guests.
/// (Their forwarded traffic would then be unfiltered but also un-NATed, as
/// the masquerade rule lives in the same table, so it could not get out.)
/// A policy from that zone to every other zone lets forwarded traffic
/// through firewalld; ember's table filters it first. The bindings are
/// permanent, so `firewall-cmd --reload` keeps them.
fn firewalld_up(cfg: &Config) -> Result<()> {
    let zone = cfg.tap_prefix.as_str();
    let policy = format!("{zone}-egress");
    let has = |list: &str, name: &str| {
        run("firewall-cmd", &["--permanent", list], None)
            .is_ok_and(|o| o.split_whitespace().any(|z| z == name))
    };
    let fw = |args: &[&str]| run("firewall-cmd", args, None).map(|_| ());
    if !has("--get-zones", zone) {
        fw(&["--permanent", &format!("--new-zone={zone}")])?;
    }
    fw(&[
        "--permanent",
        &format!("--zone={zone}"),
        "--set-target=DROP",
    ])?;
    let desc =
        format!("--set-description=ember microVM taps; filtering is in nftables table inet {zone}");
    let _ = fw(&["--permanent", &format!("--zone={zone}"), &desc]);
    if !has("--get-policies", &policy) {
        fw(&["--permanent", &format!("--new-policy={policy}")])?;
        fw(&[
            "--permanent",
            &format!("--policy={policy}"),
            "--set-target=ACCEPT",
        ])?;
        fw(&[
            "--permanent",
            &format!("--policy={policy}"),
            &format!("--add-ingress-zone={zone}"),
        ])?;
        fw(&[
            "--permanent",
            &format!("--policy={policy}"),
            "--add-egress-zone=ANY",
        ])?;
    }
    let taps: Vec<String> = cfg.slot_list().into_iter().map(|s| s.tap).collect();
    // Bindings outlive `down`, so drop those of slots that no longer exist.
    let bound = run(
        "firewall-cmd",
        &[
            "--permanent",
            &format!("--zone={zone}"),
            "--list-interfaces",
        ],
        None,
    )?;
    for old in bound
        .split_whitespace()
        .filter(|i| !taps.iter().any(|t| t == i))
    {
        fw(&[
            "--permanent",
            &format!("--zone={zone}"),
            &format!("--remove-interface={old}"),
        ])?;
    }
    for tap in &taps {
        fw(&[
            "--permanent",
            &format!("--zone={zone}"),
            &format!("--change-interface={tap}"),
        ])?;
    }
    fw(&["--reload"])
}

#[cfg(test)]
mod tests {
    #[test]
    fn ruleset_names_each_tap() {
        let cfg = crate::config::Config {
            slots: 2,
            tap_prefix: "embt".into(),
            ..Default::default()
        };
        let r = super::ruleset(&cfg);
        assert!(r.starts_with("table inet embt {"));
        assert!(r.contains(r#"elements = { "embt0", "embt1" }"#));
        assert!(r.contains(r#""embt1" . 172.30.0.6"#));
        assert!(
            !r.contains("embt*"),
            "no wildcard that could match another instance"
        );
    }
}
