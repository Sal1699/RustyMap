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
    Feature { key: "-sT", tier: Tier::Production, note: "TCP connect scan" },
    Feature { key: "-sS", tier: Tier::Production, note: "SYN scan (raw sockets)" },
    Feature { key: "-sU", tier: Tier::Production, note: "UDP scan" },
    Feature { key: "-sn", tier: Tier::Production, note: "Host discovery (ping sweep)" },
    Feature { key: "-Pn", tier: Tier::Production, note: "No host discovery (treat all as up)" },

    // ── Beta — passes tests but not lab-validated against real targets ──
    Feature { key: "-O", tier: Tier::Beta,
        note: "OS fingerprint uses nmap-os-db but a simpler match engine than nmap's. Compare with `nmap -O` on your hosts before trusting." },
    Feature { key: "-sV", tier: Tier::Beta,
        note: "Service detection: DB ported from nmap-service-probes; soft-match heuristics simpler. Spot-check on services you know." },
    Feature { key: "--ssh-audit", tier: Tier::Beta,
        note: "RFC 4253 KEXINIT enum. Validated against OpenSSH but not exotic implementations (Dropbear, Cisco IOS SSH)." },
    Feature { key: "--smb-audit", tier: Tier::Beta,
        note: "SMBv1/v2 dialect + signing. Validated against Samba 4.x and Windows 10; older SMB1-only servers not exercised." },
    Feature { key: "--tls-grade", tier: Tier::Beta,
        note: "A+/F grading + DROWN/POODLE/Heartbleed PoC. Compare against testssl.sh on a few endpoints before reporting to a stakeholder." },
    Feature { key: "--cve-for", tier: Tier::Beta,
        note: "CPE→CVE matching: version comparator handles common cases; complex version strings (e.g. `7.4p1`, `2.4.59-1ubuntu1`) may misclassify. Verify hits manually." },
    Feature { key: "--brute-protocol ftp", tier: Tier::Beta,
        note: "FTP cred brute (v0.63). Synthetic only; cross-check with hydra." },
    Feature { key: "--brute-protocol ssh", tier: Tier::Beta,
        note: "SSH cred brute via russh (v0.64). Synthetic only; cross-check with hydra." },
    Feature { key: "--brute-protocol smb", tier: Tier::Beta,
        note: "SMB NTLMv2 cred brute (v0.64). Synthetic only; cross-check with hydra/crackmapexec." },
    Feature { key: "--brute-protocol mysql", tier: Tier::Beta,
        note: "MySQL native_password cred brute (v0.64). Synthetic only." },
    Feature { key: "--brute-protocol postgres", tier: Tier::Beta,
        note: "PostgreSQL MD5 cred brute (v0.64). SCRAM not implemented." },
    Feature { key: "--brute-protocol ldap", tier: Tier::Beta,
        note: "LDAP simple-bind brute (v0.64). SASL/GSSAPI not supported." },
    Feature { key: "--brute-protocol vnc", tier: Tier::Beta,
        note: "RFB 3.x DES challenge-response (v0.64). RFB 4+ and Apple Remote Desktop variants not covered." },

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
    Feature { key: "-sI", tier: Tier::Alpha,
        note: "Idle/zombie scan. Requires a zombie with predictable IPID; modern OSes have randomized IPID and won't work. Complex, low real-world coverage." },
    Feature { key: "--os-fp-v6", tier: Tier::Alpha,
        note: "IPv6 OS fingerprint (`os_fp_v6.rs` / `os_fp_multi.rs`). Less mature than IPv4 path; database coverage thinner." },
    Feature { key: "--owasp-probes", tier: Tier::Alpha,
        note: "Basic XSS/SQLi/open-redirect/SSRF probes. Heavy false-positive rate; dedicated tools (ZAP, sqlmap) outperform on real engagements." },
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
    fn beta_gate_passes_silently() {
        let r = announce_and_gate("--brute-protocol ssh", false);
        assert!(r.is_ok(), "beta does not need --experimental-confirm");
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
