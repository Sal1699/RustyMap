//! Compliance evaluation: maps RustyMap findings to controls in
//! PCI-DSS v4.0, HIPAA Security Rule, NIST SP 800-53 Rev. 5, ISO/IEC
//! 27001:2022 Annex A, and CIS Benchmarks (general).
//!
//! Each framework lists ~10 controls relevant to the technical
//! posture RustyMap can actually observe — encryption-in-transit,
//! authentication strength, network exposure, software vulnerability
//! triage. Controls outside that scope (policy, training, physical
//! security, paper-trail evidence) are simply absent — the report is
//! not "you are PCI-DSS compliant", it's "of the controls a network
//! scan can verify, here is your status".
//!
//! Each `Control` declares one or more **trigger kinds**. A scan
//! pushes `Finding` records as it runs (the calling code in
//! `main.rs` does this whenever it would otherwise call
//! `audit.event(...)`). At the end:
//!   - **PASS**: no finding with one of the control's trigger kinds
//!   - **FAIL**: ≥1 such finding — listed as evidence
//!   - **N/A**: no scan covered the relevant area at all (e.g. SMTP
//!     control on a host where SMTP wasn't probed)
//!
//! Output: print summary + per-control table; optional Markdown
//! report file via `--compliance-report`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Framework {
    PciDss,
    Hipaa,
    Nist80053,
    Iso27001,
    Cis,
}

impl Framework {
    pub fn parse(s: &str) -> Option<Framework> {
        match s.to_lowercase().replace(['_', ' '], "-").as_str() {
            "pci-dss" | "pci" | "pcidss" => Some(Framework::PciDss),
            "hipaa" => Some(Framework::Hipaa),
            "nist-800-53" | "nist" | "nist80053" => Some(Framework::Nist80053),
            "iso-27001" | "iso" | "iso27001" => Some(Framework::Iso27001),
            "cis" | "cis-benchmark" | "cis-benchmarks" => Some(Framework::Cis),
            _ => None,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Framework::PciDss => "PCI-DSS v4.0",
            Framework::Hipaa => "HIPAA Security Rule",
            Framework::Nist80053 => "NIST SP 800-53 Rev. 5",
            Framework::Iso27001 => "ISO/IEC 27001:2022 Annex A",
            Framework::Cis => "CIS Benchmarks",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub host: String,
    pub detail: String,
}

impl Finding {
    pub fn new(kind: impl Into<String>, host: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            host: host.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Control {
    pub id: &'static str,
    pub title: &'static str,
    /// Finding kinds whose presence fails this control.
    pub triggers: &'static [&'static str],
    /// "Coverage areas" — finding kinds whose *absence everywhere*
    /// (including no positive evidence at all) means the control was
    /// never actually exercised. When none of these appear, the
    /// control is N/A rather than PASS.
    pub coverage_kinds: &'static [&'static str],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlStatus {
    Pass,
    Fail(Vec<Finding>),
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub id: String,
    pub title: String,
    pub status: ControlStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEval {
    pub framework_label: String,
    pub controls: Vec<ControlResult>,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
}

// ── Coverage areas — what a "scanned" area looks like ──────────────
//
// Each scan family reports at least one finding kind even on a clean
// pass. The TLS audit emits `tls_evaluated`, the SSH audit emits
// `ssh_evaluated`, etc. The compliance evaluator looks for these
// markers to decide whether a control with no fail-trigger is PASS
// (we did look) or N/A (we didn't).

const COV_TLS: &[&str] = &["tls_evaluated"];
const COV_DNS: &[&str] = &["dns_evaluated"];
const COV_SSH: &[&str] = &["ssh_evaluated"];
const COV_SMB: &[&str] = &["smb_evaluated"];
const COV_RDP: &[&str] = &["rdp_evaluated"];
const COV_SMTP: &[&str] = &["smtp_evaluated"];
const COV_WEB: &[&str] = &["web_evaluated"];
const COV_MOBILE: &[&str] = &["apk_evaluated", "ipa_evaluated"];
const COV_CLOUD: &[&str] = &["cloud_evaluated"];
const COV_PORT: &[&str] = &["port_state_evaluated"];

// ── Framework definitions ──────────────────────────────────────────

const PCI_DSS: &[Control] = &[
    Control {
        id: "PCI 2.2.5",
        title: "Disable insecure services and protocols",
        triggers: &["tls_protocol_legacy", "tls_classic_vuln", "smb_v1"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "PCI 4.2.1",
        title: "Strong cryptography for cardholder data in transit",
        triggers: &["tls_protocol_legacy", "tls_weak_cipher", "tls_no_modern", "tls_classic_vuln"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "PCI 4.2.2",
        title: "PAN never sent over unprotected end-user messaging",
        triggers: &["smtp_starttls_missing", "smtp_clear_creds"],
        coverage_kinds: COV_SMTP,
    },
    Control {
        id: "PCI 6.4.1",
        title: "Public-facing web apps are protected against attacks",
        triggers: &["web_xss", "web_sqli", "web_open_redirect", "web_ssrf"],
        coverage_kinds: COV_WEB,
    },
    Control {
        id: "PCI 6.5.1",
        title: "Software vulnerabilities are identified and remediated",
        triggers: &["cve_critical"],
        coverage_kinds: COV_PORT,
    },
    Control {
        id: "PCI 8.3.1",
        title: "All authentication uses strong cryptography",
        triggers: &["ssh_weak_kex", "ssh_weak_cipher", "ssh_weak_mac", "rdp_no_nla"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "PCI 8.3.6",
        title: "Strong cryptography on all auth interfaces (cloud)",
        triggers: &["cloud_imds_v1", "cloud_iam_role_exposed"],
        coverage_kinds: COV_CLOUD,
    },
    Control {
        id: "PCI 11.3.1",
        title: "External vulnerability scans cover all in-scope hosts",
        triggers: &["port_open_unrestricted"],
        coverage_kinds: COV_PORT,
    },
];

const HIPAA: &[Control] = &[
    Control {
        id: "HIPAA 164.312(a)(1)",
        title: "Unique user identification & strong auth",
        triggers: &["ssh_weak_kex", "rdp_no_nla", "smtp_clear_creds"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "HIPAA 164.312(a)(2)(iv)",
        title: "Encryption and decryption of ePHI",
        triggers: &["tls_protocol_legacy", "tls_weak_cipher", "tls_no_modern"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "HIPAA 164.312(c)(1)",
        title: "Integrity controls",
        triggers: &["smb_no_signing", "tls_classic_vuln"],
        coverage_kinds: COV_SMB,
    },
    Control {
        id: "HIPAA 164.312(e)(1)",
        title: "Transmission security",
        triggers: &["tls_protocol_legacy", "smtp_starttls_missing", "ipa_ats_disabled", "apk_cleartext"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "HIPAA 164.312(e)(2)(i)",
        title: "Integrity of data in transit",
        triggers: &["tls_classic_vuln", "smb_no_signing"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "HIPAA 164.312(e)(2)(ii)",
        title: "Encryption of data in transit",
        triggers: &["tls_protocol_legacy", "tls_weak_cipher", "ipa_low_tls"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "HIPAA 164.308(a)(1)(ii)(A)",
        title: "Risk analysis — known vulnerabilities present?",
        triggers: &["cve_critical"],
        coverage_kinds: COV_PORT,
    },
];

const NIST_800_53: &[Control] = &[
    Control {
        id: "NIST AC-3",
        title: "Access enforcement",
        triggers: &["cloud_bucket_public", "cloud_imds_v1"],
        coverage_kinds: COV_CLOUD,
    },
    Control {
        id: "NIST AC-17",
        title: "Remote access — strong auth",
        triggers: &["ssh_weak_kex", "ssh_weak_cipher", "rdp_no_nla"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "NIST IA-5",
        title: "Authenticator management",
        triggers: &["ssh_weak_mac", "smtp_clear_creds", "mobile_hardcoded_secret"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "NIST SC-7",
        title: "Boundary protection — minimize exposed services",
        triggers: &["port_open_unrestricted", "smb_v1"],
        coverage_kinds: COV_PORT,
    },
    Control {
        id: "NIST SC-8",
        title: "Transmission confidentiality and integrity",
        triggers: &["tls_protocol_legacy", "tls_classic_vuln", "smtp_starttls_missing"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "NIST SC-13",
        title: "Cryptographic protection — approved algorithms only",
        triggers: &["tls_weak_cipher", "ssh_weak_cipher", "ssh_weak_kex"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "NIST SC-23",
        title: "Session authenticity",
        triggers: &["smb_no_signing", "rdp_no_nla"],
        coverage_kinds: COV_SMB,
    },
    Control {
        id: "NIST SI-2",
        title: "Flaw remediation — known CVEs patched",
        triggers: &["cve_critical"],
        coverage_kinds: COV_PORT,
    },
    Control {
        id: "NIST SI-10",
        title: "Information input validation",
        triggers: &["web_xss", "web_sqli"],
        coverage_kinds: COV_WEB,
    },
];

const ISO_27001: &[Control] = &[
    Control {
        id: "ISO A.5.10",
        title: "Acceptable use of information & assets",
        triggers: &["mobile_hardcoded_secret", "cloud_bucket_public"],
        coverage_kinds: COV_MOBILE,
    },
    Control {
        id: "ISO A.8.5",
        title: "Secure authentication",
        triggers: &["ssh_weak_kex", "ssh_weak_cipher", "ssh_weak_mac", "rdp_no_nla", "smtp_clear_creds"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "ISO A.8.20",
        title: "Networks security",
        triggers: &["smb_v1", "port_open_unrestricted", "dnssec_missing"],
        coverage_kinds: COV_PORT,
    },
    Control {
        id: "ISO A.8.21",
        title: "Security of network services",
        triggers: &["smb_no_signing", "smtp_starttls_missing"],
        coverage_kinds: COV_SMB,
    },
    Control {
        id: "ISO A.8.23",
        title: "Web filtering / open exposure",
        triggers: &["web_open_redirect", "web_ssrf"],
        coverage_kinds: COV_WEB,
    },
    Control {
        id: "ISO A.8.24",
        title: "Use of cryptography",
        triggers: &["tls_protocol_legacy", "tls_weak_cipher", "tls_no_modern", "tls_classic_vuln"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "ISO A.8.28",
        title: "Secure coding",
        triggers: &["web_xss", "web_sqli", "mobile_hardcoded_secret", "apk_debuggable"],
        coverage_kinds: COV_WEB,
    },
    Control {
        id: "ISO A.8.8",
        title: "Management of technical vulnerabilities",
        triggers: &["cve_critical"],
        coverage_kinds: COV_PORT,
    },
];

const CIS: &[Control] = &[
    Control {
        id: "CIS 2.2",
        title: "Disable SSLv2/v3 and TLS 1.0/1.1",
        triggers: &["tls_protocol_legacy", "tls_classic_vuln"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "CIS 2.3",
        title: "Use only strong TLS ciphers",
        triggers: &["tls_weak_cipher"],
        coverage_kinds: COV_TLS,
    },
    Control {
        id: "CIS 4.1",
        title: "Disable SMBv1",
        triggers: &["smb_v1"],
        coverage_kinds: COV_SMB,
    },
    Control {
        id: "CIS 4.2",
        title: "Require SMB signing on all connections",
        triggers: &["smb_no_signing"],
        coverage_kinds: COV_SMB,
    },
    Control {
        id: "CIS 5.2",
        title: "SSH — disable weak KEX/cipher/MAC",
        triggers: &["ssh_weak_kex", "ssh_weak_cipher", "ssh_weak_mac"],
        coverage_kinds: COV_SSH,
    },
    Control {
        id: "CIS 5.5",
        title: "Require NLA for RDP",
        triggers: &["rdp_no_nla"],
        coverage_kinds: COV_RDP,
    },
    Control {
        id: "CIS 6.1",
        title: "Mail relay — STARTTLS required",
        triggers: &["smtp_starttls_missing", "smtp_clear_creds"],
        coverage_kinds: COV_SMTP,
    },
    Control {
        id: "CIS 7.1",
        title: "DNSSEC enabled on authoritative zones",
        triggers: &["dnssec_missing"],
        coverage_kinds: COV_DNS,
    },
    Control {
        id: "CIS 7.2",
        title: "DMARC published with quarantine/reject policy",
        triggers: &["dmarc_weak"],
        coverage_kinds: COV_DNS,
    },
    Control {
        id: "CIS 7.3",
        title: "SPF policy is restrictive (~all or -all)",
        triggers: &["spf_permissive"],
        coverage_kinds: COV_DNS,
    },
];

fn controls_for(framework: Framework) -> &'static [Control] {
    match framework {
        Framework::PciDss => PCI_DSS,
        Framework::Hipaa => HIPAA,
        Framework::Nist80053 => NIST_800_53,
        Framework::Iso27001 => ISO_27001,
        Framework::Cis => CIS,
    }
}

pub fn evaluate(framework: Framework, findings: &[Finding]) -> ComplianceEval {
    let controls = controls_for(framework);
    let kinds_seen: HashSet<&str> = findings.iter().map(|f| f.kind.as_str()).collect();

    let mut results = Vec::with_capacity(controls.len());
    let mut passed = 0;
    let mut failed = 0;
    let mut not_applicable = 0;

    for c in controls {
        let evidence: Vec<Finding> = findings
            .iter()
            .filter(|f| c.triggers.iter().any(|t| *t == f.kind))
            .cloned()
            .collect();

        let status = if !evidence.is_empty() {
            failed += 1;
            ControlStatus::Fail(evidence)
        } else {
            let any_coverage = c
                .coverage_kinds
                .iter()
                .any(|k| kinds_seen.contains(*k));
            if any_coverage {
                passed += 1;
                ControlStatus::Pass
            } else {
                not_applicable += 1;
                ControlStatus::NotApplicable
            }
        };
        results.push(ControlResult {
            id: c.id.into(),
            title: c.title.into(),
            status,
        });
    }

    ComplianceEval {
        framework_label: framework.label().into(),
        controls: results,
        passed,
        failed,
        not_applicable,
    }
}

/// Plain-language remediation advice keyed by finding kind. Multiple
/// controls in different frameworks tend to fail on the same finding
/// kind (e.g. `ssh_weak_kex` triggers PCI 8.3.1, NIST IA-5, ISO A.8.5,
/// HIPAA 164.312(a)(1) — same fix every time), so we map remediation
/// to the kind rather than duplicating per-control text. Fase 25
/// (v0.67.0).
pub fn remediation_for_kind(kind: &str) -> Option<&'static str> {
    Some(match kind {
        // ── TLS ──
        "tls_protocol_legacy" => "Disable SSLv2/SSLv3/TLS 1.0/1.1 on the target service. Restrict to TLS 1.2+ with PFS-capable ciphers.",
        "tls_weak_cipher" => "Remove RC4, 3DES, NULL and EXPORT ciphers from the server's ordered list. Prefer ECDHE-AES-GCM and ChaCha20-Poly1305.",
        "tls_classic_vuln" => "Apply vendor patches for Heartbleed/POODLE/DROWN/CCS-Injection. Force-renegotiate after patching to invalidate exfiltrated keys.",
        "tls_no_modern" => "Add TLS 1.3 to the server's protocol list (ALPN h2 if HTTP).",
        // ── SMB ──
        "smb_v1" => "Disable SMBv1 on the host (Windows: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`). Replace any legacy client that still requires it.",
        "smb_no_signing" => "Set `signing = mandatory` (Samba smb.conf) or `RequireSecuritySignature = 1` (Windows GPO) to prevent NTLM relay.",
        // ── SSH ──
        "ssh_weak_kex" => "Restrict KEX algorithms in sshd_config to curve25519-sha256 and diffie-hellman-group-exchange-sha256. Remove diffie-hellman-group1-sha1 and group14-sha1.",
        "ssh_weak_cipher" => "Restrict ciphers in sshd_config to chacha20-poly1305@openssh.com and aes*-gcm@openssh.com. Remove arcfour, 3des-cbc, blowfish-cbc.",
        "ssh_weak_mac" => "Restrict MACs in sshd_config to hmac-sha2-512-etm@openssh.com and hmac-sha2-256-etm@openssh.com. Remove md5 and 96-bit MACs.",
        // ── RDP ──
        "rdp_no_nla" => "Enforce Network Level Authentication (NLA) on RDP via GPO `Require user authentication for remote connections by using Network Level Authentication`. Patch BlueKeep (CVE-2019-0708) if on legacy Windows.",
        // ── SMTP ──
        "smtp_starttls_missing" => "Enable STARTTLS on the MTA (Postfix `smtpd_tls_security_level = may` or `encrypt`). Block AUTH on the cleartext channel.",
        "smtp_clear_creds" => "Disable AUTH PLAIN/LOGIN on the non-TLS port. Require STARTTLS before any AUTH.",
        // ── Web ──
        "web_xss" => "Output-encode user-controlled data per context (HTML, attribute, JS, URL). Enable a strict CSP with no `unsafe-inline`.",
        "web_sqli" => "Use parameterised queries / prepared statements. Audit any string-concat building SQL.",
        "web_open_redirect" => "Validate redirect targets against an allowlist of safe paths. Refuse off-site Location: headers.",
        "web_ssrf" => "Allowlist destination hosts for server-side fetches. Block link-local (169.254.0.0/16) and RFC 1918 unless explicitly required.",
        // ── CVE / port hygiene ──
        "cve_critical" => "Patch the affected service to the vendor-recommended fixed version. Cross-reference KEV catalog for in-the-wild exploitation evidence.",
        "port_open_unrestricted" => "Restrict the service to its intended source range at the perimeter firewall. Public exposure of management ports is rarely justified.",
        // ── Cloud ──
        "cloud_imds_v1" => "Migrate to IMDSv2 (AWS) / disable v1 fallback. Set hop-limit to 1 to prevent container reachability.",
        "cloud_iam_role_exposed" => "Rotate the leaked credentials immediately. Audit role permissions and apply least-privilege boundary policy.",
        "cloud_bucket_public" => "Set bucket ACL to private. Use signed URLs for legitimate public access. Enable bucket-level public-access block.",
        // ── Mobile ──
        "mobile_hardcoded_secret" => "Remove secrets from the app bundle. Use a backend-issued token or a secrets manager. Treat the leaked secret as compromised and rotate.",
        "ipa_ats_disabled" => "Re-enable ATS (App Transport Security) in Info.plist. Use NSExceptionDomains only for legacy endpoints, and only with `NSExceptionMinimumTLSVersion`.",
        "ipa_low_tls" => "Raise `NSExceptionMinimumTLSVersion` to TLSv1.2 or higher in NSExceptionDomains.",
        "apk_cleartext" => "Set `android:usesCleartextTraffic=\"false\"` in AndroidManifest.xml. Add a network-security-config XML to override only documented hosts.",
        _ => return None,
    })
}

pub fn print_report(eval: &ComplianceEval) {
    use colored::*;
    println!();
    println!("{}", format!("Compliance evaluation — {}", eval.framework_label).bold());
    println!(
        "  {} pass · {} fail · {} N/A",
        eval.passed.to_string().green(),
        eval.failed.to_string().red(),
        eval.not_applicable.to_string().dimmed()
    );
    println!();
    println!("  {:<24} {:<8} CONTROL", "ID", "STATUS");
    for c in &eval.controls {
        let (label, color) = match &c.status {
            ControlStatus::Pass => ("PASS", "PASS".green().to_string()),
            ControlStatus::Fail(_) => ("FAIL", "FAIL".red().bold().to_string()),
            ControlStatus::NotApplicable => ("N/A ", "N/A ".dimmed().to_string()),
        };
        let _ = label;
        println!("  {:<24} {:<8} {}", c.id, color, c.title);
        if let ControlStatus::Fail(evidence) = &c.status {
            for ev in evidence.iter().take(3) {
                println!("    · {} @ {} — {}", ev.kind, ev.host, ev.detail);
            }
            if evidence.len() > 3 {
                println!("    … {} more piece(s) of evidence", evidence.len() - 3);
            }
            // Fase 25 v0.67.0: emit a remediation line per unique
            // finding kind in the evidence so the user has a concrete
            // next step instead of just the control title.
            let mut shown: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for ev in evidence {
                if shown.insert(ev.kind.as_str()) {
                    if let Some(fix) = remediation_for_kind(&ev.kind) {
                        println!("    {} {}", "fix:".cyan().bold(), fix.dimmed());
                    }
                }
            }
        }
    }
}

pub fn write_markdown(eval: &ComplianceEval, path: &Path) -> Result<()> {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(&mut s, "# Compliance evaluation — {}", eval.framework_label);
    let _ = writeln!(&mut s);
    let _ = writeln!(
        &mut s,
        "**Summary:** {} pass · {} fail · {} N/A",
        eval.passed, eval.failed, eval.not_applicable
    );
    let _ = writeln!(&mut s);
    let _ = writeln!(&mut s, "| Status | ID | Control |");
    let _ = writeln!(&mut s, "|--------|----|---------|");
    for c in &eval.controls {
        let label = match &c.status {
            ControlStatus::Pass => "PASS",
            ControlStatus::Fail(_) => "FAIL",
            ControlStatus::NotApplicable => "N/A",
        };
        let _ = writeln!(&mut s, "| {} | {} | {} |", label, c.id, c.title);
    }
    let _ = writeln!(&mut s);
    let _ = writeln!(&mut s, "## Failed controls — evidence");
    for c in &eval.controls {
        if let ControlStatus::Fail(evidence) = &c.status {
            let _ = writeln!(&mut s, "### {} — {}", c.id, c.title);
            for ev in evidence {
                let _ = writeln!(&mut s, "- `{}` @ `{}` — {}", ev.kind, ev.host, ev.detail);
            }
            // Fase 25 v0.67.0: one remediation block per unique kind.
            let mut shown: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for ev in evidence {
                if shown.insert(ev.kind.as_str()) {
                    if let Some(fix) = remediation_for_kind(&ev.kind) {
                        let _ = writeln!(&mut s, "  - **Fix ({}):** {}", ev.kind, fix);
                    }
                }
            }
            let _ = writeln!(&mut s);
        }
    }
    std::fs::write(path, s)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aliases_and_canonical() {
        assert_eq!(Framework::parse("pci-dss"), Some(Framework::PciDss));
        assert_eq!(Framework::parse("PCI"), Some(Framework::PciDss));
        assert_eq!(Framework::parse("nist_800_53"), Some(Framework::Nist80053));
        assert_eq!(Framework::parse("ISO 27001"), Some(Framework::Iso27001));
        assert_eq!(Framework::parse("cis-benchmarks"), Some(Framework::Cis));
        assert!(Framework::parse("sox").is_none());
    }

    #[test]
    fn pass_when_coverage_present_and_no_trigger() {
        // SSH was probed (ssh_evaluated) but no weak findings → PASS
        let findings = vec![
            Finding::new("ssh_evaluated", "10.0.0.1:22", "modern KEX set"),
            Finding::new("tls_evaluated", "10.0.0.1:443", "1.3 only"),
        ];
        let eval = evaluate(Framework::Cis, &findings);
        assert!(eval.controls.iter().any(|c| c.id == "CIS 5.2" && matches!(c.status, ControlStatus::Pass)));
    }

    #[test]
    fn fail_when_trigger_present() {
        let findings = vec![
            Finding::new("ssh_evaluated", "h1:22", "ok"),
            Finding::new("ssh_weak_cipher", "h1:22", "3des-cbc enabled"),
        ];
        let eval = evaluate(Framework::Cis, &findings);
        let c = eval.controls.iter().find(|c| c.id == "CIS 5.2").unwrap();
        assert!(matches!(c.status, ControlStatus::Fail(_)));
    }

    #[test]
    fn na_when_no_coverage_at_all() {
        // Only TLS evidence present; SMB controls are N/A
        let findings = vec![Finding::new("tls_evaluated", "h1:443", "fine")];
        let eval = evaluate(Framework::Cis, &findings);
        let c = eval.controls.iter().find(|c| c.id == "CIS 4.1").unwrap();
        assert!(matches!(c.status, ControlStatus::NotApplicable));
    }

    #[test]
    fn summary_counts_match() {
        let findings = vec![
            Finding::new("tls_evaluated", "h1", ""),
            Finding::new("tls_protocol_legacy", "h1", "TLS 1.0"),
            Finding::new("smb_evaluated", "h1", ""),
            Finding::new("dns_evaluated", "ex.test", ""),
        ];
        let eval = evaluate(Framework::Cis, &findings);
        let total: usize = eval.passed + eval.failed + eval.not_applicable;
        assert_eq!(total, eval.controls.len());
        assert!(eval.failed >= 1, "expected ≥1 fail for tls_protocol_legacy");
    }

    #[test]
    fn markdown_render_contains_summary_and_evidence() {
        let findings = vec![
            Finding::new("tls_evaluated", "h1:443", ""),
            Finding::new("tls_protocol_legacy", "h1:443", "TLS 1.0 enabled"),
        ];
        let eval = evaluate(Framework::Cis, &findings);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rustymap-test-{}.md", std::process::id()));
        write_markdown(&eval, &path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(content.contains("CIS"));
        assert!(content.contains("FAIL"));
        assert!(content.contains("tls_protocol_legacy"));
    }
}
