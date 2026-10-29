//! Module maturity tier registry — Fase 24 hardening.
//!
//! After v0.65 the codebase has 100+ modules and a long tail of features
//! that pass synthetic tests but were never run against real targets.
//! This registry makes that asymmetry honest:
//!
//! - `Tier::Production` — battle-validated in real lab against a reference
//!   tool (nmap / hydra / sslscan) or simple enough to trust by inspection.
//! - `Tier::Beta` — passes synthetic tests and is likely correct, but not
//!   yet validated against real targets.
//! - `Tier::Alpha` — known limitations, new code (<2 weeks), or both. The
//!   user must pass `--experimental-confirm` to invoke an Alpha feature;
//!   otherwise the run errors out with a pointer to the limitation note.
//!
//! Lab-validation progress lives in `LAB_VALIDATION.md`. As features get
//! validated their tier is promoted (and the note updated to "validated
//! YYYY-MM-DD against …").

use anyhow::{anyhow, Result};
use colored::Colorize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Production,
    Beta,
    Alpha,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Production => "production",
            Tier::Beta => "beta",
            Tier::Alpha => "alpha",
        }
    }
}

pub struct Feature {
    pub key: &'static str,
    pub tier: Tier,
    pub note: &'static str,
}

/// Curated registry. Not every CLI flag is here — only ones whose tier is
/// non-obvious or where the user benefits from knowing the limitation.
/// Implicit default for an unlisted flag is Production. New unproven
/// features should land here at Beta or Alpha before going to Production.
const REGISTRY: &[Feature] = &[
    // ── Production scan primitives (listed so the maturity matrix shows
    // them as deliberately validated, not just "we didn't classify them") ──
    Feature { key: "--sT", tier: Tier::Production, note: "TCP connect scan" },
    Feature { key: "--sS", tier: Tier::Production, note: "SYN scan (raw sockets)" },
    Feature { key: "--sU", tier: Tier::Production, note: "UDP scan" },
    Feature { key: "--sn", tier: Tier::Production, note: "Host discovery (ping sweep)" },
    Feature { key: "--Pn", tier: Tier::Production, note: "No host discovery (treat all as up)" },

    // ── Promoted to Production after real-target lab validation (nmap /
    // hydra / crackmapexec / sslscan). Full history in LAB_VALIDATION.md. ──
    Feature { key: "-O", tier: Tier::Production,
        note: "OS fingerprint. The emitted 16-field block is byte-identical to `nmap -O` (validated v0.75→0.79), and the match now agrees with `nmap -O` on heterogeneous real hardware: lab v0.100.1 hit 3/3 — OpenWrt router (.1), OpenWrt/Linux embedded (.31, 93%), and Windows 11 24H2 (.64, exact family+version). Pass `--nmap-os-db` for best accuracy; without it the built-in 100-sig heuristic can read confidence lower. The earlier v0.99 misfire (an AP read as 'VirtualBox Slirp NAT') was fixed in v0.99.2 by demoting the Slirp heuristic to a hint." },
    Feature { key: "--sV", tier: Tier::Production,
        note: "Service detection (nmap-service-probes DB). Lab-validated: SSH/DNS/SMB/RPC identical to nmap (v0.82) and lighttpd/nginx identified behind TLS (v0.95)." },
    Feature { key: "--ssh-audit", tier: Tier::Production,
        note: "RFC 4253 KEXINIT enum. Lab-validated vs ssh-audit/reference (v0.82.1); exotic stacks (Cisco IOS SSH) still less exercised." },
    Feature { key: "--smb-audit", tier: Tier::Production,
        note: "SMBv1/v2 dialect + signing. Sends a native SMB2 NEGOTIATE first (dialects 2.0.2→3.1.1 + preauth-integrity context) and falls back to the legacy SMB1 negotiate only for SMB1-only servers. Lab v0.100.2 three-way match on Win11 24H2 (:445): dialect SMB 3.1.1 and the signing verdict (enabled, not required → relay-vulnerable) agree with both `nmap --script smb2-security-mode` and crackmapexec. Port 139 (SMB-over-NetBIOS) is correctly refused by modern Windows." },
    Feature { key: "--tls-grade", tier: Tier::Production,
        note: "A+/F grading + DROWN/POODLE/Heartbleed PoC. Lab-validated vs sslscan on :443/:8443 (Fase L v0.83); cross-check testssl.sh for stakeholder-facing reports." },
    Feature { key: "--cve-for", tier: Tier::Production,
        note: "CPE→CVE matching. Lab-validated vs NVD (v0.99: `OpenSSH 9.6p1` → 25 CVEs incl. CVE-2024-6387/regreSSHion). Complex distro version strings can still misclassify — verify high-impact hits manually." },
    Feature { key: "--brute-protocol ftp", tier: Tier::Production,
        note: "FTP cred brute (v0.63). Lab v0.100.3 agrees with hydra on Metasploitable 2 vsftpd 2.3.4: same hit (msfadmin:msfadmin) on single-cred and needle-in-haystack, wrong creds correctly rejected." },
    Feature { key: "--brute-protocol ssh", tier: Tier::Production,
        note: "SSH cred brute via russh (v0.64). Lab-validated vs hydra across every mode: --brute-pair/--brute-userpass HIT=hydra (v0.100.5), and the full --brute-userlist×--brute-passlist recovered the known-valid cred in v0.100.8 on a modern OpenSSH server — in 8 effective attempts, where hydra's 16 parallel tasks were throttled to an intermittent miss by the server's MaxStartups. The success path needed the v0.100.6/.8 retry-backoff work (transport errors retried 4× with seconds-scale exponential backoff + jitter) to outlast a burst throttle; a single connection always worked. Password auth only — no pubkey / keyboard-interactive." },
    Feature { key: "--brute-protocol smb", tier: Tier::Production,
        note: "SMB NTLMv2 cred brute over SMBv1 (v0.64). Lab-validated vs hydra + crackmapexec on Metasploitable 2 Samba 3.0.20 (v0.100.13): finds msfadmin:msfadmin in 6 attempts — identical hit and attempt count to crackmapexec, matching hydra — with no guest-mapping false positive (root:wrong rejected). Getting there took a four-bug chain fixed over v0.100.10→.13: UID correlation, session-setup ByteCount, missing CAP_EXTENDED_SECURITY, and the Type-3 Version-field length that had silent-guest-mapped every credential. SMBv1 NTLMSSP only — modern SMB2/3-only servers need a separate negotiate path." },
    Feature { key: "--brute-protocol mysql", tier: Tier::Production,
        note: "MySQL native_password cred brute (v0.64). The v0.100.4 empty-password fix (auth-data-length 0) was confirmed on Kali v0.100.5: agrees with hydra on Metasploitable 2 MySQL 5.0.51a (root with a blank password). caching_sha2_password (8.0+ default) is still best-effort — native_password only." },
    Feature { key: "--brute-protocol postgres", tier: Tier::Production,
        note: "PostgreSQL MD5 cred brute (v0.64). Lab v0.100.3 agrees with hydra on Metasploitable 2 PostgreSQL 8.3 (MD5 auth): same hit (postgres:postgres) single-cred + needle-in-haystack. SCRAM (PG10+) still not implemented — MD5 auth only." },
    Feature { key: "--brute-protocol ldap", tier: Tier::Production,
        note: "LDAP simple-bind brute (v0.64). Lab v0.100.3 agrees with hydra ldap3:// on osixia/openldap: correct bind on cn=admin,dc=example,dc=org and correct rejection of a wrong password. SASL/GSSAPI still not supported — simple bind only." },
    Feature { key: "--brute-protocol vnc", tier: Tier::Production,
        note: "RFB 3.x DES challenge-response (v0.64). The v0.100.4 RFB 3.3 handshake fix was confirmed on Kali v0.100.5: agrees with hydra on Metasploitable 2 VNC (RFB 3.3, password 'password'). RFB 4+ and Apple Remote Desktop variants still not covered." },

    // ── Alpha — known limits or freshly landed; --experimental-confirm gate ──
    Feature { key: "--brute-protocol rdp", tier: Tier::Alpha,
        note: "RDP CredSSP best-effort (v0.65): pubKeyAuth NOT implemented (would need RC4 of TLS SPKI under NTLM session key). Negative results (specific NTSTATUS error codes) are reliable; positive results are SUGGESTIVE, not authoritative. Validate against a real Windows RDP server before reporting findings." },
    Feature { key: "--brute-protocol mssql", tier: Tier::Alpha,
        note: "MSSQL TDS 7.4 SQL Server Auth (v0.65). Implemented from MS-TDS spec but not yet validated against a real SQL Server instance." },
    Feature { key: "--apk-scan", tier: Tier::Alpha,
        note: "Android APK static analysis with inline AXML parser. Mobile-secret patterns may produce false positives; structure parsing not exercised against obfuscated/protected APKs." },
    Feature { key: "--ipa-scan", tier: Tier::Alpha,
        note: "iOS IPA static analysis via plist. Only Info.plist inspected; mach-O entitlements / embedded provisioning profiles not parsed." },
    Feature { key: "--threat-intel-sync", tier: Tier::Alpha,
        note: "MISP IoC sync. Pull-only, no de-duplication across syncs; rate-limit handling minimal." },
    Feature { key: "--osdb-submit", tier: Tier::Alpha,
        note: "Submits OS-fingerprint observations to an external endpoint. Don't enable on networks where this leak is a concern." },
    Feature { key: "--sI", tier: Tier::Alpha,
        note: "Idle/zombie scan. Requires a zombie with predictable IPID; modern OSes have randomized IPID and won't work. Complex, low real-world coverage." },
    Feature { key: "--os-fp-v6", tier: Tier::Alpha,
        note: "IPv6 OS fingerprint (`os_fp_v6.rs` / `os_fp_multi.rs`). Less mature than IPv4 path; database coverage thinner." },
    Feature { key: "--owasp-scan", tier: Tier::Alpha,
        note: "Basic XSS/SQLi/open-redirect/SSRF probes (CLI flag: --owasp-scan URL). Heavy false-positive rate; dedicated tools (ZAP, sqlmap) outperform on real engagements." },
    Feature { key: "--ics-scan", tier: Tier::Alpha,
        note: "Modbus/S7/DNP3/EnIP/BACnet probes. Validated against Conpot honeypots only — real PLCs may behave differently. Use read-only against production." },
    Feature { key: "--web-crawl", tier: Tier::Alpha,
        note: "BFS crawler with robots.txt + cookie store. Slow vs ZAP and doesn't handle JS-rendered apps. Prefer dedicated tools for serious web work." },
];

pub fn lookup(key: &str) -> Option<&'static Feature> {
    REGISTRY.iter().find(|f| f.key == key)
}

/// Call this at the dispatch point for an Alpha/Beta feature. Returns Err
/// if the feature is Alpha and `experimental_confirmed` is false, so the
/// caller can propagate the error and abort the run.
pub fn announce_and_gate(key: &str, experimental_confirmed: bool) -> Result<()> {
    let Some(f) = lookup(key) else { return Ok(()); };
    match f.tier {
        Tier::Production => Ok(()),
        Tier::Beta => {
            eprintln!(
                "{} {} ({}): {}",
                "ℹ".cyan(),
                f.key.bold(),
                f.tier.label().yellow(),
                f.note
            );
            Ok(())
        }
        Tier::Alpha => {
            if !experimental_confirmed {
                return Err(anyhow!(
                    "{} is alpha — pass --experimental-confirm to acknowledge:\n  {}",
                    f.key,
                    f.note
                ));
            }
            eprintln!(
                "{} {} ({}): {}",
                "⚠".red(),
                f.key.bold(),
                f.tier.label().red(),
                f.note
            );
            Ok(())
        }
    }
}

pub fn registry() -> &'static [Feature] {
    REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_lookup_works() {
        let f = lookup("--brute-protocol rdp").expect("rdp registered");
        assert_eq!(f.tier, Tier::Alpha);
        assert!(f.note.contains("pubKeyAuth"));
    }

    #[test]
    fn alpha_gate_rejects_without_confirm() {
        let r = announce_and_gate("--brute-protocol rdp", false);
        assert!(r.is_err(), "alpha must reject without --experimental-confirm");
    }

    #[test]
    fn alpha_gate_passes_with_confirm() {
        // Stderr banner prints but the function returns Ok
        let r = announce_and_gate("--brute-protocol rdp", true);
        assert!(r.is_ok());
    }

    #[test]
    fn gate_policy_matches_all_tiers() {
        // Policy over the whole registry, self-maintaining as tiers change:
        // Production/Beta pass the gate without --experimental-confirm; Alpha
        // rejects without it and passes with it. (Beta is currently empty — smb
        // was promoted in v0.100.14 — but the invariant still holds for it.)
        for f in registry() {
            match f.tier {
                Tier::Production | Tier::Beta => assert!(
                    announce_and_gate(f.key, false).is_ok(),
                    "{} ({}) must pass the gate without confirm",
                    f.key,
                    f.tier.label()
                ),
                Tier::Alpha => {
                    assert!(
                        announce_and_gate(f.key, false).is_err(),
                        "{} (alpha) must reject without confirm",
                        f.key
                    );
                    assert!(
                        announce_and_gate(f.key, true).is_ok(),
                        "{} (alpha) must pass with confirm",
                        f.key
                    );
                }
            }
        }
    }

    #[test]
    fn unlisted_key_treated_as_production() {
        assert!(announce_and_gate("--some-unlisted-flag", false).is_ok());
    }

    #[test]
    fn registry_has_no_duplicate_keys() {
        let keys: Vec<&str> = REGISTRY.iter().map(|f| f.key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "duplicate keys in maturity registry");
    }
}
