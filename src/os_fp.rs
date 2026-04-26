use crate::scanner::{HostResult, PortState};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsGuess {
    pub family: String,
    pub confidence: u8, // 0-100
    pub ttl: Option<u8>,
    pub hints: Vec<String>,
}

static TTL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)ttl[=:]\s*(\d+)").unwrap());

/// Ping the host and parse TTL from system ping output.
fn ping_ttl(ip: IpAddr, timeout: Duration) -> Option<u8> {
    let ip_s = ip.to_string();
    let timeout_ms = timeout.as_millis().max(200) as u64;
    let out = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip_s])
            .output()
            .ok()?
    } else {
        let secs = timeout_ms.div_ceil(1000).max(1);
        Command::new("ping")
            .args(["-c", "1", "-W", &secs.to_string(), &ip_s])
            .output()
            .ok()?
    };
    let text = String::from_utf8_lossy(&out.stdout);
    TTL_RE.captures(&text).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<u8>().ok())
}

fn family_from_ttl(ttl: u8) -> (&'static str, u8) {
    // Hop count ambiguity: most hosts are within ~30 hops.
    match ttl {
        1..=64 => ("Linux/BSD/macOS", 55),
        65..=128 => ("Windows", 55),
        129..=255 => ("Network device (Cisco/router)", 50),
        0 => ("unknown", 0),
    }
}

fn refine_from_ports(host: &HostResult, guess: &mut OsGuess) {
    let open: Vec<u16> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect();

    let has = |p: u16| open.contains(&p);

    // ── Windows family ──
    if has(135) || has(139) || has(445) || has(3389) || has(5357) {
        guess.hints.push("RPC/SMB/RDP open".into());
        if guess.family != "Windows" {
            guess.family = "Windows".into();
            guess.confidence = guess.confidence.max(70);
        } else {
            guess.confidence = (guess.confidence + 20).min(95);
        }
    }
    // Windows server roles
    if has(88) && has(389) && has(445) && has(636) {
        guess.hints.push("Kerberos+LDAP+SMB+LDAPS — Active Directory DC".into());
        guess.family = "Windows Server (Domain Controller)".into();
        guess.confidence = 90;
    }
    if has(1433) || has(1434) {
        guess.hints.push("MSSQL ports — Windows server".into());
    }
    if has(2179) {
        guess.hints.push("VMM Console — Hyper-V host".into());
        guess.family = "Windows Server (Hyper-V)".into();
        guess.confidence = guess.confidence.max(80);
    }

    // ── *nix family ──
    if has(22) {
        guess.hints.push("SSH open".into());
        if guess.family.starts_with("Linux") {
            guess.confidence = (guess.confidence + 10).min(95);
        }
    }
    if has(548) {
        guess.hints.push("AFP open (likely macOS)".into());
        guess.family = "macOS".into();
        guess.confidence = guess.confidence.max(70);
    }
    if has(515) || has(631) || has(9100) {
        guess.hints.push("LPD/IPP/JetDirect printer ports".into());
    }
    if has(2049) && has(111) {
        guess.hints.push("NFS+rpcbind — UNIX file server".into());
    }
    if has(902) || has(443) && has(5480) {
        guess.hints.push("vCenter / ESXi mgmt port".into());
        guess.family = "VMware ESXi".into();
        guess.confidence = guess.confidence.max(80);
    }

    // ── Embedded / network gear ──
    if has(23) && has(80) && !has(445) {
        guess.hints.push("telnet+http, likely embedded/network device".into());
    }
    if has(8291) {
        guess.hints.push("MikroTik Winbox port".into());
        guess.family = "MikroTik RouterOS".into();
        guess.confidence = guess.confidence.max(85);
    }
    if has(161) && has(443) && has(80) && !has(22) {
        guess.hints.push("SNMP+web admin only — likely embedded appliance".into());
    }
    // VPN concentrator hints
    if has(500) && has(4500) {
        guess.hints.push("IKE+NAT-T — IPsec VPN endpoint".into());
    }
    if has(1701) {
        guess.hints.push("L2TP".into());
    }
    if has(1723) {
        guess.hints.push("PPTP (legacy VPN)".into());
    }

    // ── Mobile / IoT ──
    if has(5555) {
        guess.hints.push("ADB exposed — Android device".into());
        guess.family = "Android".into();
        guess.confidence = guess.confidence.max(85);
    }
    if has(62078) {
        guess.hints.push("iPhone/iPad lockdown port".into());
        guess.family = "iOS".into();
        guess.confidence = guess.confidence.max(90);
    }
    if has(8009) && has(8008) && has(8443) {
        guess.hints.push("Google Cast / Chromecast".into());
    }

    // ── ICS/SCADA ──
    if has(102) {
        guess.hints.push("S7 / Siemens — ICS device".into());
    }
    if has(502) {
        guess.hints.push("Modbus TCP — ICS device".into());
    }
    if has(20000) {
        guess.hints.push("DNP3 — ICS/utility".into());
    }
    if has(44818) {
        guess.hints.push("EtherNet/IP — Rockwell/Allen-Bradley".into());
    }
    if has(47808) {
        guess.hints.push("BACnet — building automation".into());
    }

    // ── Container / orchestration ──
    if has(2375) || has(2376) {
        guess.hints.push("Docker daemon exposed".into());
    }
    if has(6443) {
        guess.hints.push("Kubernetes API server".into());
    }
    if has(10250) {
        guess.hints.push("kubelet API".into());
    }
    if has(2379) || has(2380) {
        guess.hints.push("etcd (cluster store)".into());
    }
}

fn refine_from_banners(host: &HostResult, guess: &mut OsGuess) {
    // Pattern → (family, confidence, hint). First match wins.
    // Rules are checked in priority order; the first hit upgrades the guess.
    let rules: &[(&str, &str, u8)] = &[
        // ── Linux distros ──
        ("ubuntu", "Linux (Ubuntu)", 90),
        ("debian", "Linux (Debian)", 90),
        ("centos", "Linux (RHEL/CentOS)", 90),
        ("rhel", "Linux (RHEL)", 90),
        ("red hat", "Linux (RHEL)", 90),
        ("amazon linux", "Linux (Amazon Linux)", 92),
        ("alpine", "Linux (Alpine)", 90),
        ("arch linux", "Linux (Arch)", 90),
        ("fedora", "Linux (Fedora)", 90),
        ("suse", "Linux (SUSE)", 88),
        ("oracle linux", "Linux (Oracle)", 92),
        ("rocky linux", "Linux (Rocky)", 92),
        ("almalinux", "Linux (AlmaLinux)", 92),
        ("openwrt", "OpenWrt (embedded Linux)", 92),
        ("dd-wrt", "DD-WRT (embedded Linux)", 92),
        ("synology dsm", "Synology DSM (Linux)", 92),
        ("qnap qts", "QNAP QTS (Linux)", 92),
        ("raspbian", "Raspberry Pi OS (Linux)", 92),
        // ── BSD family ──
        ("freebsd", "FreeBSD", 92),
        ("openbsd", "OpenBSD", 92),
        ("netbsd", "NetBSD", 92),
        ("dragonfly", "DragonFly BSD", 90),
        ("pfsense", "pfSense (FreeBSD)", 92),
        ("opnsense", "OPNsense (FreeBSD)", 92),
        // ── Windows ──
        ("microsoft-iis", "Windows", 85),
        ("microsoft ftp", "Windows", 85),
        ("microsoft-httpapi", "Windows", 85),
        ("microsoft exchange", "Windows Server (Exchange)", 92),
        ("windows server 2022", "Windows Server 2022", 95),
        ("windows server 2019", "Windows Server 2019", 95),
        ("windows server 2016", "Windows Server 2016", 95),
        ("windows nt", "Windows NT (legacy)", 85),
        // ── Apple ──
        ("mac os x", "macOS", 90),
        ("macos", "macOS", 90),
        ("darwin", "macOS / Darwin", 88),
        ("iphone", "iOS", 90),
        // ── Network gear ──
        ("cisco ios", "Cisco IOS", 95),
        ("ios xe", "Cisco IOS XE", 95),
        ("ios xr", "Cisco IOS XR", 95),
        ("nx-os", "Cisco NX-OS", 95),
        ("cisco asa", "Cisco ASA", 95),
        ("cisco wlc", "Cisco WLC", 92),
        ("juniper", "Juniper Junos", 92),
        ("junos", "Juniper Junos", 95),
        ("routeros", "MikroTik RouterOS", 95),
        ("edgeos", "Ubiquiti EdgeOS", 92),
        ("unifi", "Ubiquiti UniFi", 90),
        ("fortios", "Fortinet FortiOS", 95),
        ("fortigate", "Fortinet FortiGate", 95),
        ("pan-os", "Palo Alto PAN-OS", 95),
        ("globalprotect", "Palo Alto GlobalProtect", 92),
        ("sonicwall", "SonicWall", 92),
        ("netscaler", "Citrix NetScaler", 92),
        ("big-ip", "F5 BIG-IP", 95),
        ("checkpoint", "Check Point", 92),
        // ── Hypervisors / cloud ──
        ("vmware esxi", "VMware ESXi", 95),
        ("vmware vsphere", "VMware vSphere", 92),
        ("vcenter", "VMware vCenter", 92),
        ("xenserver", "Citrix XenServer", 90),
        ("proxmox", "Proxmox VE", 92),
        // ── Commercial UNIX ──
        ("solaris", "Solaris", 92),
        ("smartos", "SmartOS", 90),
        ("hp-ux", "HP-UX", 92),
        ("aix", "IBM AIX", 92),
        ("os/400", "IBM i (OS/400)", 92),
        ("z/os", "IBM z/OS (mainframe)", 95),
        // ── Embedded RTOS / firmware ──
        ("vxworks", "Wind River VxWorks", 90),
        ("freertos", "FreeRTOS", 88),
        ("contiki", "Contiki OS", 88),
        ("riot-os", "RIOT OS", 88),
        // ── Storage appliances ──
        ("netapp", "NetApp ONTAP", 92),
        ("isilon", "Dell EMC Isilon", 92),
        ("powerstore", "Dell PowerStore", 92),
    ];

    for p in &host.ports {
        if let Some(svc) = &p.service {
            let s = svc.display().to_lowercase();
            let b = svc.banner.as_deref().unwrap_or("").to_lowercase();
            let extra = svc.extra.as_deref().unwrap_or("").to_lowercase();
            let all = format!("{} {} {}", s, b, extra);
            for (needle, family, conf) in rules {
                if all.contains(needle) {
                    if guess.confidence < *conf || guess.family == "unknown" {
                        guess.family = (*family).into();
                        guess.confidence = *conf;
                        guess.hints.push(format!("banner: {}", needle));
                    }
                    break; // first matching rule per port is enough
                }
            }
        }
    }
}

pub fn fingerprint(host: &HostResult, timeout: Duration) -> OsGuess {
    let ttl = ping_ttl(host.target.ip, timeout);
    let (family, base_conf) = ttl.map(family_from_ttl).unwrap_or(("unknown", 0));
    let mut guess = OsGuess {
        family: family.to_string(),
        confidence: base_conf,
        ttl,
        hints: if let Some(t) = ttl { vec![format!("TTL={}", t)] } else { vec![] },
    };
    refine_from_ports(host, &mut guess);
    refine_from_banners(host, &mut guess);
    guess
}
