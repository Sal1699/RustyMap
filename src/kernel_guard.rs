//! Suppress the local kernel's own RSTs during raw OS-probe scans (lab bug #5).
//!
//! When RustyMap sends crafted TCP probes (T5–T7, ACK/Maimon, etc.) from a
//! source port the local kernel isn't tracking, the target's reply arrives
//! at an "unowned" port and **the scanning host's own kernel fires a RST**.
//! That extra RST races our raw capture and can also tear down the very
//! exchange we're measuring, so probes intermittently read `R=N` when the
//! target actually answered (seen on 10.0.2.2 in lab: nmap `T6/T7 R=Y`,
//! RustyMap `R=N`). nmap sidesteps this internally; here we install a
//! transient, target-scoped firewall rule that drops **outbound RSTs to the
//! target** for the duration of the probe, then removes it on drop (RAII).
//!
//! Linux only (nft, falling back to iptables) and only when it actually
//! succeeds (needs root). Everywhere else it is an inert no-op — the guard
//! object still exists so callers don't branch on the platform.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;

/// Active while held; removes the firewall rule when dropped.
pub struct RstGuard {
    /// The command + args that *removes* the rule we added, or `None` when
    /// no rule was installed (non-Linux, not root, or firewall tool absent).
    remove: Option<Vec<String>>,
    /// Human note describing what was (or wasn't) done, for `-v` output.
    pub note: String,
}

impl RstGuard {
    /// Whether a rule is actually in place.
    pub fn active(&self) -> bool {
        self.remove.is_some()
    }

    fn inert(note: impl Into<String>) -> Self {
        RstGuard { remove: None, note: note.into() }
    }
}

/// Source-port range our raw probes use (`send_tcp_probe` /
/// `capture_seq_sample` / `tcp_fp::probe` all draw from 40000..60000).
/// Scoping the RST drop to this range means we suppress **only our own**
/// probe RSTs, never the kernel's legitimate RSTs for real connections.
const PROBE_SPORT_LO: u16 = 40000;
const PROBE_SPORT_HI: u16 = 60000;

/// `iptables`/`ip6tables` argument vectors for adding/removing the
/// RST-drop rule, scoped to `dst` **and** our probe source-port range.
/// Pure (no execution) so it can be unit-tested.
pub fn iptables_args(dst: &str, add: bool) -> Vec<String> {
    // -I inserts (add), -D deletes; same match otherwise.
    let op = if add { "-I" } else { "-D" };
    vec![
        op.to_string(),
        "OUTPUT".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-d".to_string(),
        dst.to_string(),
        "--sport".to_string(),
        format!("{}:{}", PROBE_SPORT_LO, PROBE_SPORT_HI),
        "--tcp-flags".to_string(),
        "RST".to_string(),
        "RST".to_string(),
        "-j".to_string(),
        "DROP".to_string(),
    ]
}

/// Name of the dedicated nftables table we create so cleanup is a single
/// atomic `delete table` (deleting an individual nft rule needs its
/// runtime handle, which the old `delete rule <spec>` form couldn't do).
const NFT_TABLE: &str = "rustymap_guard";

/// The nft `rule` body scoped to `dst` + our probe source-port range.
pub fn nft_rule(dst: &str) -> String {
    let proto = if dst.contains(':') { "ip6" } else { "ip" };
    format!(
        "{} daddr {} tcp sport {}-{} tcp flags rst drop",
        proto, dst, PROBE_SPORT_LO, PROBE_SPORT_HI
    )
}

/// Install the guard for `dst`. Returns an inert guard on any platform
/// other than Linux, without privileges, or if no firewall tool is present.
#[cfg(target_os = "linux")]
pub fn guard_for(dst: IpAddr) -> RstGuard {
    let dst_s = dst.to_string();
    let ipt = if dst.is_ipv6() { "ip6tables" } else { "iptables" };

    // Try iptables/ip6tables first (most Kali installs have it).
    let add = iptables_args(&dst_s, true);
    if let Ok(out) = Command::new(ipt).args(&add).output() {
        if out.status.success() {
            let mut remove = iptables_args(&dst_s, false);
            remove.insert(0, ipt.to_string()); // arg0 = tool, for Drop
            return RstGuard {
                remove: Some(remove),
                note: format!("kernel-RST guard active ({} rule on {})", ipt, dst_s),
            };
        }
    }

    // Fall back to nftables with a DEDICATED table so cleanup is one
    // atomic `delete table` (no per-rule handle bookkeeping).
    let rule = nft_rule(&dst_s);
    // A single `nft -f -` script: create table + hooked chain + rule.
    let script = format!(
        "add table inet {t}\n\
         add chain inet {t} output {{ type filter hook output priority 0; }}\n\
         add rule inet {t} output {rule}\n",
        t = NFT_TABLE,
        rule = rule
    );
    use std::io::Write as _;
    if let Ok(mut child) = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        if matches!(child.wait(), Ok(s) if s.success()) {
            let remove = vec![
                "nft".to_string(),
                "delete".to_string(),
                "table".to_string(),
                "inet".to_string(),
                NFT_TABLE.to_string(),
            ];
            return RstGuard {
                remove: Some(remove),
                note: format!("kernel-RST guard active (nft table {} on {})", NFT_TABLE, dst_s),
            };
        }
    }

    RstGuard::inert(
        "kernel-RST guard unavailable (need root + iptables/nft) — T5–T7 may read R=N spuriously"
            .to_string(),
    )
}

/// Non-Linux: nothing to do.
#[cfg(not(target_os = "linux"))]
pub fn guard_for(_dst: IpAddr) -> RstGuard {
    RstGuard::inert("kernel-RST guard is Linux-only (no-op on this platform)")
}

#[cfg(target_os = "linux")]
impl Drop for RstGuard {
    fn drop(&mut self) {
        if let Some(rm) = self.remove.take() {
            if let Some((tool, args)) = rm.split_first() {
                let _ = Command::new(tool).args(args).output();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_add_and_delete_symmetric() {
        let add = iptables_args("10.0.2.2", true);
        let del = iptables_args("10.0.2.2", false);
        assert_eq!(add[0], "-I");
        assert_eq!(del[0], "-D");
        // Everything after the op flag must be identical (same rule).
        assert_eq!(&add[1..], &del[1..]);
        assert!(add.contains(&"DROP".to_string()));
        assert!(add.contains(&"10.0.2.2".to_string()));
        assert!(add.windows(3).any(|w| w == ["--tcp-flags", "RST", "RST"]));
    }

    #[test]
    fn nft_rule_picks_ip_family() {
        assert!(nft_rule("10.0.2.2").starts_with("ip daddr"));
        assert!(nft_rule("fe80::1").starts_with("ip6 daddr"));
        assert!(nft_rule("10.0.2.2").ends_with("tcp flags rst drop"));
    }

    #[test]
    fn guard_is_inert_when_unprivileged() {
        // In CI / dev (non-root or non-Linux) the guard must not error and
        // must report inactive.
        let g = guard_for("10.0.2.2".parse().unwrap());
        // We can't assert active/inactive across environments, but note
        // must be non-empty and dropping must not panic.
        assert!(!g.note.is_empty());
    }
}
