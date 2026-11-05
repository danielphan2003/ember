//! PID 1 duties: pseudo-filesystems, hostname, network, and reaping.

use std::{ffi::CString, io, mem, net::Ipv4Addr, os::unix::process::CommandExt, process::Command};

/// The `ember.*` parameters the host puts on the kernel command line.
#[derive(Debug, Default, PartialEq)]
pub struct BootParams {
    pub addr: Option<(Ipv4Addr, u8)>, // guest address and prefix length
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<String>,
    pub hostname: Option<String>,
}

pub fn parse_cmdline(cmdline: &str) -> BootParams {
    let mut p = BootParams::default();
    for field in cmdline.split_whitespace() {
        let Some((k, v)) = field.split_once('=') else {
            continue;
        };
        match k {
            "ember.ip" => {
                p.addr = v
                    .split_once('/')
                    .and_then(|(a, l)| Some((a.parse().ok()?, l.parse().ok()?)));
            }
            "ember.gw" => p.gateway = v.parse().ok(),
            "ember.dns" => p.dns = v.split(',').map(String::from).collect(),
            "ember.hostname" => p.hostname = Some(v.into()),
            _ => {}
        }
    }
    p
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) {
    let _ = std::fs::create_dir_all(target);
    let c = |s: &str| CString::new(s).expect("no NUL");
    let (src, tgt, fs, dat) = (c(src), c(target), c(fstype), c(data));
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fs.as_ptr(),
            flags,
            dat.as_ptr().cast(),
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("ember-agent: mount {target}: {err}");
        }
    }
}

/// Prepares the guest. Failures in optional steps are logged, not fatal,
/// so a job still gets a shell to report from.
pub fn init() {
    use libc::{MS_NODEV, MS_NOEXEC, MS_NOSUID};
    mount(
        "proc",
        "/proc",
        "proc",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        "",
    );
    mount(
        "sysfs",
        "/sys",
        "sysfs",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        "",
    );
    mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    mount(
        "devpts",
        "/dev/pts",
        "devpts",
        MS_NOSUID | MS_NOEXEC,
        "gid=5,mode=0620,ptmxmode=0666",
    );
    mount(
        "tmpfs",
        "/dev/shm",
        "tmpfs",
        MS_NOSUID | MS_NODEV,
        "mode=1777",
    );
    mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
    mount(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        "",
    );
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
        ("/dev/ptmx", "pts/ptmx"),
    ] {
        let _ = std::fs::remove_file(link);
        let _ = std::os::unix::fs::symlink(target, link);
    }
    // /tmp and the runner's RUNNER_TEMP and RUNNER_TOOL_CACHE must be
    // writable by whatever user the image runs steps as.
    for dir in ["/tmp", "/ember/tmp", "/ember/toolcache"] {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::create_dir_all(dir).is_ok() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o1777));
        }
    }

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let p = parse_cmdline(&cmdline);
    if let Some(h) = &p.hostname {
        unsafe { libc::sethostname(h.as_ptr().cast(), h.len()) };
    }
    write_etc(&p);
    if let Err(e) = network(&p) {
        eprintln!("ember-agent: network: {e}");
    }
}

fn write_etc(p: &BootParams) {
    if !p.dns.is_empty() {
        let conf: String = p
            .dns
            .iter()
            .map(|ns| format!("nameserver {ns}\n"))
            .collect();
        // Images often ship resolv.conf as a symlink into /run; replace it.
        let _ = std::fs::remove_file("/etc/resolv.conf");
        let _ = std::fs::write("/etc/resolv.conf", conf);
    }
    let mut hosts = String::from("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n");
    if let Some(h) = &p.hostname {
        hosts.push_str(&format!("127.0.1.1 {h}\n"));
        let _ = std::fs::write("/etc/hostname", format!("{h}\n"));
    }
    let _ = std::fs::write("/etc/hosts", hosts);
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    unsafe { mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

fn ifreq(name: &str) -> libc::ifreq {
    let mut r: libc::ifreq = unsafe { mem::zeroed() };
    for (d, s) in r.ifr_name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    r
}

fn ioctl(
    fd: libc::c_int,
    req: libc::c_ulong,
    arg: *mut libc::c_void,
    what: &str,
) -> io::Result<()> {
    if unsafe { libc::ioctl(fd, req as libc::Ioctl, arg) } < 0 {
        return Err(io::Error::other(format!(
            "{what}: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn link_up(fd: libc::c_int, name: &str) -> io::Result<()> {
    let mut r = ifreq(name);
    ioctl(fd, libc::SIOCGIFFLAGS, (&raw mut r).cast(), "get flags")?;
    unsafe { r.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    ioctl(fd, libc::SIOCSIFFLAGS, (&raw mut r).cast(), "set flags")
}

/// Configures lo and eth0 with plain ioctls: images need not ship `ip`.
fn network(p: &BootParams) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| {
        link_up(fd, "lo")?;
        let Some((addr, len)) = p.addr else {
            return Ok(());
        };
        let mut r = ifreq("eth0");
        r.ifr_ifru.ifru_addr = sockaddr(addr);
        ioctl(fd, libc::SIOCSIFADDR, (&raw mut r).cast(), "set address")?;
        let mask = Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0));
        r.ifr_ifru.ifru_netmask = sockaddr(mask);
        ioctl(fd, libc::SIOCSIFNETMASK, (&raw mut r).cast(), "set netmask")?;
        link_up(fd, "eth0")?;
        if let Some(gw) = p.gateway {
            let mut rt: libc::rtentry = unsafe { mem::zeroed() };
            rt.rt_dst = sockaddr(Ipv4Addr::UNSPECIFIED);
            rt.rt_genmask = sockaddr(Ipv4Addr::UNSPECIFIED);
            rt.rt_gateway = sockaddr(gw);
            rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
            ioctl(
                fd,
                libc::SIOCADDRT,
                (&raw mut rt).cast(),
                "add default route",
            )?;
        }
        Ok(())
    })();
    unsafe { libc::close(fd) };
    res
}

/// Runs as PID 1: starts the agent server as a child process and reaps
/// every orphan. When the server exits, the VM powers off.
///
/// The server runs in a separate process because its own child waits and a
/// PID 1 reaper calling waitpid(-1) would race for the same children.
pub fn supervise() -> ! {
    let child = match Command::new("/proc/self/exe")
        .arg0("ember-agent")
        .arg("serve")
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ember-agent: start server: {e}");
            power_off();
        }
    };
    let server = child.id() as libc::pid_t;
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == server {
            eprintln!("ember-agent: server exited ({status})");
            power_off();
        }
        if pid < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            power_off();
        }
    }
}

/// Stops the VM: Firecracker exits when the guest reboots.
pub fn power_off() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    std::process::exit(1)
}
