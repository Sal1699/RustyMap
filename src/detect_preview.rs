//! "What would a defender see?" — pure-static preview of how a
//! given set of CLI args looks from the other side of the wire.
//!
//! Educational tool. Useful for two crowds:
//!   - Pentesters running authorised engagements who want to know
//!     which IDS rules / SIEM correlations their scan will trip,
//!     so they can pace it appropriately or coordinate with the
//!     blue team in advance.
//!   - Defenders who want to validate that their IDS / SIEM /
//!     EDR actually fires the rules they expect against a known
//!     scan profile.
//!
//! Pure analysis — no network IO. Reads the parsed `Cli` and
//! produces a list of `DetectionExpectation` entries:
//!
//!   - **detector**: which product/rule we're talking about
//!   - **outcome**:  Visible | Suppressed | Unknown
//!   - **rationale**: short English explanation
//!   - **mitigation**: what flag would change the outcome
//!
//! No exhaustive defender catalogue — we cover the high-traffic
//! ones (Suricata `decoder-events.rules` + `stream-events.rules`,
//! Snort sfPortscan, Splunk `stream:tcp` rate thresholds, generic
//! NetFlow burst patterns, EDR process-creation logs).

use crate::cli::Cli;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    Visible,
    Suppressed,
    Unknown,
}

impl Outcome {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Visible => "VISIBLE",
            Outcome::Suppressed => "SUPPRESSED",
            Outcome::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionExpectation {
    pub detector: String,
    pub outcome: Outcome,
    pub rationale: String,
    pub mitigation: Option<String>,
}

pub fn analyze(cli: &Cli) -> Vec<DetectionExpectation> {
    let mut out = Vec::new();
    let timing = cli.timing;
    let parallel = cli.max_parallel;
    let delay = cli.scan_delay_ms;
    let aggressive = cli.aggressive;
    let raw_scan = cli.scan_syn || cli.scan_fin || cli.scan_null
        || cli.scan_xmas || cli.scan_ack || cli.scan_window || cli.scan_maimon;

    // ── Suricata sfPortscan-style rule ─────
    let sca_visible = (timing >= 4) || (delay == 0 && parallel >= 50);
    out.push(DetectionExpectation {
        detector: "Suricata stream-events / sfPortscan".into(),
        outcome: if sca_visible { Outcome::Visible } else { Outcome::Suppressed },
        rationale: if sca_visible {
            format!(
                "T{} with parallel={} (delay={}ms) easily exceeds the default \
                 detection_filter (5 hosts × 60s)",
                timing, parallel, delay
            )
        } else {
            format!(
                "T{} with delay={}ms keeps probe rate below the default \
                 detection_filter window",
                timing, delay
            )
        },
        mitigation: if sca_visible {
            Some("--scan-delay 1000 (or higher) + --timing 2".into())
        } else {
            None
        },
    });

    // ── Snort sfPortscan / pf-portscan ─────
    if raw_scan {
        out.push(DetectionExpectation {
            detector: "Snort sfPortscan".into(),
            outcome: if timing >= 3 { Outcome::Visible } else { Outcome::Unknown },
            rationale: format!(
                "raw scan ({}) at T{} produces SYN/FIN/NULL/Xmas patterns Snort's \
                 sfPortscan preprocessor flags as 'TCP Portscan'",
                cli_scan_name(cli), timing
            ),
            mitigation: Some("use --sT (connect) or pace with --scan-delay 2000".into()),
        });
    }

    // ── EDR process logging ─────
    out.push(DetectionExpectation {
        detector: "EDR process telemetry (Sysmon Event ID 1, CrowdStrike, Defender)".into(),
        outcome: Outcome::Visible,
        rationale: "the scanner binary 'rustymap' executes on the operator's host \
                    and is logged by every modern EDR; obfuscating the binary name \
                    doesn't change parent-process / command-line capture".into(),
        mitigation: Some("rename binary; coordinate with the blue team to whitelist".into()),
    });

    // ── Wireshark-visible heartbeat probe ─────
    if cli.tls_grade {
        out.push(DetectionExpectation {
            detector: "Wireshark / Zeek tls.heartbeat".into(),
            outcome: Outcome::Visible,
            rationale: "--tls-grade sends a malformed Heartbeat (CVE-2014-0160 PoC); \
                        Zeek's `ssl.log` records the heartbeat record type, Wireshark \
                        filters cleanly with `tls.handshake.extension.type == 15`".into(),
            mitigation: Some("drop --tls-grade if PoC visibility is unwanted".into()),
        });
    }

    // ── HTTP path-enum signature ─────
    if cli.http_enum {
        out.push(DetectionExpectation {
            detector: "WAF (Cloudflare/AWS WAF/F5) path-traversal & admin-path rules".into(),
            outcome: Outcome::Visible,
            rationale: "--http-enum walks ~80 paths including /admin, /config.php, \
                        /.git/config, /.env — every WAF in production has rules for \
                        these and will rate-limit or block after a handful".into(),
            mitigation: Some("pace with --max-rate 5; use --proxies to rotate source".into()),
        });
    }

    // ── OWASP active probes signature ─────
    if cli.owasp_scan.is_some() {
        out.push(DetectionExpectation {
            detector: "WAF (OWASP CRS rules 941xxx XSS, 942xxx SQLi)".into(),
            outcome: Outcome::Visible,
            rationale: "reflected-XSS and SQLi probes match OWASP CRS PL1 rules; \
                        SOC will see ModSecurity / Cloudflare audit alerts within \
                        seconds of the first probe".into(),
            mitigation: Some("notify the SOC in advance; constrain with --owasp-checks".into()),
        });
    }

    // ── Aggressive-mode caveat ─────
    if aggressive {
        out.push(DetectionExpectation {
            detector: "any half-decent SIEM correlation".into(),
            outcome: Outcome::Visible,
            rationale: "-A bundles -sV (banner-fetch on every open port) + -O \
                        (TCP/IP fingerprint) + traceroute. Each generates a distinct \
                        signature; together they're an unmissable 'pentest scan' \
                        pattern".into(),
            mitigation: Some("split into separate phases hours apart, or drop -A".into()),
        });
    }

    // ── ICS / SCADA caveat ─────
    if cli.ics_scan.is_some() {
        out.push(DetectionExpectation {
            detector: "ICS firewall / Claroty / Nozomi".into(),
            outcome: Outcome::Visible,
            rationale: "Modbus FC 43, S7 Setup-Communication, DNP3 link-status, \
                        EnIP List Identity, BACnet Who-Is — all five probes are \
                        idiomatic protocol traffic that ICS-aware monitors fingerprint \
                        as 'unauthorised station scanning'".into(),
            mitigation: Some("coordinate with OT team; never run unannounced".into()),
        });
    }

    out
}

fn cli_scan_name(cli: &Cli) -> &'static str {
    if cli.scan_syn { "SYN" }
    else if cli.scan_fin { "FIN" }
    else if cli.scan_null { "NULL" }
    else if cli.scan_xmas { "Xmas" }
    else if cli.scan_ack { "ACK" }
    else if cli.scan_window { "Window" }
    else if cli.scan_maimon { "Maimon" }
    else if cli.scan_udp { "UDP" }
    else { "connect" }
}

pub fn print(expectations: &[DetectionExpectation]) {
    use colored::*;
    println!();
    println!("{}", format!("Detection preview — {} expectation(s)", expectations.len()).bold().underline());
    println!("  {}", "(static analysis — no traffic generated yet)".dimmed());
    for e in expectations {
        let label = match e.outcome {
            Outcome::Visible => "VISIBLE".red().bold().to_string(),
            Outcome::Suppressed => "SUPPRESSED".green().to_string(),
            Outcome::Unknown => "UNKNOWN".yellow().to_string(),
        };
        println!();
        println!("  {} — {}", label, e.detector.bold());
        println!("    why : {}", e.rationale);
        if let Some(m) = &e.mitigation {
            println!("    fix : {}", m.dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        let mut argv = vec!["rustymap"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(&argv).unwrap()
    }

    #[test]
    fn t5_with_no_delay_is_visible() {
        let c = cli(&["--timing", "5", "10.0.0.1"]);
        let exp = analyze(&c);
        let scratch = exp.iter().find(|e| e.detector.contains("Suricata")).unwrap();
        assert_eq!(scratch.outcome, Outcome::Visible);
    }

    #[test]
    fn slow_pace_suppresses_suricata() {
        let c = cli(&["--timing", "2", "--scan-delay", "2000", "10.0.0.1"]);
        let exp = analyze(&c);
        let scratch = exp.iter().find(|e| e.detector.contains("Suricata")).unwrap();
        assert_eq!(scratch.outcome, Outcome::Suppressed);
    }

    #[test]
    fn aggressive_adds_siem_caveat() {
        let c = cli(&["-A", "10.0.0.1"]);
        let exp = analyze(&c);
        assert!(exp.iter().any(|e| e.detector.contains("SIEM")));
    }

    #[test]
    fn http_enum_adds_waf_caveat() {
        let c = cli(&["--http-enum", "10.0.0.1"]);
        let exp = analyze(&c);
        assert!(exp.iter().any(|e| e.detector.contains("WAF")));
    }

    #[test]
    fn tls_grade_adds_heartbeat_caveat() {
        let c = cli(&["--tls-grade", "10.0.0.1"]);
        let exp = analyze(&c);
        assert!(exp.iter().any(|e| e.detector.contains("Wireshark")));
    }

    #[test]
    fn ics_scan_adds_ot_caveat() {
        let c = cli(&["--ics-scan", "10.0.0.50"]);
        let exp = analyze(&c);
        assert!(exp.iter().any(|e| e.detector.contains("ICS")));
    }
}
