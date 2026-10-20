//! 2026-10-03 — private agents page v2: where the agent runs, sent with each
//! heartbeat (display only; the backend never trusts it for anything else).

use std::net::UdpSocket;

/// "Debian GNU/Linux 12 (bookworm) · linux/x86_64" — the distribution's
/// PRETTY_NAME when /etc/os-release has one, then OS/arch.
pub fn platform() -> String {
    let arch = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);
    let pretty = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| pretty_name(&s));
    match pretty {
        Some(p) => format!("{p} · {arch}"),
        None => arch,
    }
}

fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|l| {
        l.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// The local address the OS would use to reach the aggregator: a connected
/// UDP socket sends nothing, it only resolves the route. None when the
/// aggregator URL has no host or the route can't be resolved.
pub fn private_ip(aggregator_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(aggregator_url).ok()?;
    let host = url.host_str()?;
    let port = url.port_or_known_default().unwrap_or(443);
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((host, port)).ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pretty_name() {
        let os = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(pretty_name(os).as_deref(), Some("Debian GNU/Linux 12 (bookworm)"));
        assert_eq!(pretty_name("ID=alpine\n"), None);
    }

    #[test]
    fn platform_always_names_os_and_arch() {
        assert!(platform().contains(std::env::consts::ARCH));
    }

    #[test]
    fn no_ip_for_a_url_without_host() {
        assert_eq!(private_ip("not a url"), None);
    }
}
