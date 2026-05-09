//! `--explain "<args>"` — plain-language gloss of a rustymap
//! invocation.
//!
//! Useful as an onboarding aid for someone who's been handed a
//! command from a runbook and wants to know what it'll actually
//! do before running it. Not a replacement for `--help` or the
//! in-app guide — those are reference. This is line-by-line
//! commentary keyed on the flags actually used.
//!
//! The glossary is hand-curated so the explanations match the
//! present semantics, not just the clap one-liners. Unknown flags
//! pass through with `(unknown flag — see --guide)` so a runbook
//! drift doesn't silently hide them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gloss {
    pub token: String,
    pub gloss: String,
}

/// Token → human gloss (Italian — matches the rest of the in-app
/// guide). Some entries match a flag exactly; others match a *prefix*
/// to handle `--flag value` pairs.
const GLOSSARY: &[(&str, &str)] = &[
    // Targets / ports
    ("-p", "specifica le porte da scansionare (numeri o range)"),
    ("--ports", "specifica le porte da scansionare"),
    ("-F", "scan veloce — top 100 porte"),
    ("--fast", "scan veloce — top 100 porte"),
    ("--all-ports", "scansiona tutte le 65535 porte"),
    ("--top-ports", "scansiona le N porte più comuni"),

    // Scan types
    ("--sT", "TCP connect scan (no privilegi richiesti)"),
    ("--sS", "TCP SYN half-open (raw socket, root/admin)"),
    ("--sU", "UDP scan"),
    ("--sF", "TCP FIN scan"),
    ("--sN", "TCP NULL scan"),
    ("--sX", "TCP Xmas scan (FIN+PSH+URG)"),
    ("--sA", "TCP ACK scan (mapping firewall)"),
    ("--sL", "list scan: risolve target con PTR e esce"),

    // Detection
    ("-sV", "service-version detection (banner-grab + probe)"),
    ("-O", "OS fingerprint via TCP/IP stack quirks"),
    ("--traceroute", "traceroute via tracert/traceroute di sistema"),
    ("-A", "shortcut aggressive: -sV -O --traceroute + scripts/"),
    ("--aggressive", "shortcut aggressive: -sV -O --traceroute + scripts/"),

    // Timing
    ("-T", "preset timing (0=paranoid, 5=insane)"),
    ("--timing", "preset timing (0=paranoid, 5=insane)"),
    ("--scan-delay", "millisecondi di pausa fra probe consecutive"),
    ("--max-rate", "tetto pacchetti/sec (per host)"),
    ("--jitter", "randomizza ±N% lo scan-delay (anti-pattern)"),

    // Audits
    ("--ssl-enum", "enumera TLS 1.0/1.1/1.2/1.3 + cipher su porte TLS"),
    ("--tls-grade", "grade A+/F + DROWN/POODLE/Heartbleed PoC (read-only)"),
    ("--ssh-audit", "SSH KEX/cipher/host-key/MAC enum"),
    ("--smb-audit", "SMB dialect + signing audit"),
    ("--rdp-audit", "RDP X.224 negotiation: TLS+NLA detection"),
    ("--smtp-audit", "SMTP STARTTLS + AUTH-mechanism audit"),
    ("--auth-audit", "shortcut: ssh + smb + rdp + smtp"),
    ("--http-enum", "path enumeration su porte HTTP open"),
    ("--web-crawl", "crawler BFS che enumera URL + form + parametri"),
    ("--owasp-scan", "crawler + probe XSS/SQLi/open-redirect/SSRF"),

    // DNS
    ("--dns-enum", "brute-force sottodomini (+ NS/MX/TXT)"),
    ("--dns-ct", "subdomain via Certificate Transparency (passivo)"),
    ("--dns-security", "audit DNSSEC/CAA/DANE/SPF/DMARC"),
    ("--takeover-check", "subdomain takeover via 17 fingerprint"),
    ("--origin-discovery", "origin-IP dietro CDN: MX/SPF/sub-comuni"),

    // Cloud
    ("--cloud-buckets", "enum public S3/GCS/Azure (~30 permutazioni)"),
    ("--cloud-metadata", "probe IMDS 169.254.169.254"),
    ("--cloud-fingerprint", "identifica AWS/GCP/Azure/Cloudflare/Akamai da DNS"),

    // Mobile
    ("--apk-scan", "static APK: manifest perms + secrets + pinning"),
    ("--ipa-scan", "static IPA: ATS + URL schemes + secrets"),

    // Compliance / reporting
    ("--compliance", "valuta findings vs framework PCI/HIPAA/NIST/ISO/CIS"),
    ("--compliance-report", "scrive un report Markdown del compliance"),
    ("--executive-summary", "narrativa + top services + esposizioni"),
    ("--oP", "scrive report PDF (printpdf, no system deps)"),
    ("--oSvg", "scrive topology SVG self-contained"),
    ("--oA", "scrive tutti i formati (txt/json/html/md)"),
    ("--oJ", "scrive output JSON"),
    ("--oH", "scrive report HTML"),
    ("--oMd", "scrive report Markdown"),
    ("--oX", "scrive XML compatibile nmap"),

    // Specialized
    ("--ics-scan", "ICS/SCADA: Modbus/S7/DNP3/EnIP/BACnet"),
    ("--iot-discover", "IoT unicast: mDNS + SSDP + CoAP"),
    ("--container-scan", "Docker + K8s + etcd + Consul surface"),

    // Integrations
    ("--siem-format", "output SIEM: cef|leef|ecs|syslog"),
    ("--threat-intel-misp", "sync IoC MISP nel cache locale"),
    ("--threat-intel-match", "match scan-target vs IoC cached"),
    ("--notify", "webhook su completamento (ntfy/slack/discord/teams/jira)"),

    // UX
    ("--wizard", "wizard interattivo per assemblare un comando"),
    ("--recommend", "probe rapido + suggerisce flag follow-up"),
    ("--save-profile", "salva l'invocation come profilo TOML"),
    ("--history", "mostra le ultime scan recorded"),
    ("--detect-preview", "anteprima statica: cosa vedrebbe un defender"),

    // Maintenance
    ("--check-update", "verifica se esiste una release più recente"),
    ("--update", "scarica e installa l'ultima release da GitHub"),
    ("--update-cve-db", "sync NVD JSON 2.0 → cache SQLite locale"),
    ("--update-exploit-refs", "sync CISA KEV + ExploitDB + Nuclei"),
];

pub fn explain(args: &[String]) -> Vec<Gloss> {
    let mut out = Vec::new();
    for (i, raw) in args.iter().enumerate() {
        // Skip plain values consumed by a previous flag — we keep
        // the surface focused on the flags themselves; values are
        // visible in the gloss line.
        if i > 0 && !raw.starts_with('-') {
            // Heuristic: previous token ends with `=value` already
            // (long-form), or current token isn't a flag — likely
            // a value or a target.
            continue;
        }
        // Long-form `--flag=value` → split.
        let key = raw.split('=').next().unwrap_or(raw);
        if let Some(g) = lookup(key) {
            out.push(Gloss {
                token: raw.clone(),
                gloss: g.into(),
            });
        } else if key.starts_with('-') {
            out.push(Gloss {
                token: raw.clone(),
                gloss: format!("(flag sconosciuto — vedi --guide per il catalogo completo)"),
            });
        }
    }
    out
}

fn lookup(token: &str) -> Option<&'static str> {
    GLOSSARY
        .iter()
        .find_map(|(k, v)| if *k == token { Some(*v) } else { None })
}

pub fn print(args: &[String], glosses: &[Gloss]) {
    use colored::*;
    println!();
    println!("{}", "Spiegazione del comando".bold().underline());
    println!("  {}", format!("rustymap {}", args.join(" ")).dimmed());
    if glosses.is_empty() {
        println!();
        println!("  {}", "(nessun flag rilevato — solo target o valori posizionali)".dimmed());
        return;
    }
    println!();
    for g in glosses {
        println!("  {} → {}", g.token.bold().cyan(), g.gloss);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_known_flags() {
        let args: Vec<String> = vec!["-sV".into(), "--ssh-audit".into(), "10.0.0.1".into()];
        let g = explain(&args);
        assert_eq!(g.len(), 2);
        assert!(g.iter().any(|x| x.token == "-sV" && x.gloss.contains("service-version")));
        assert!(g.iter().any(|x| x.token == "--ssh-audit"));
    }

    #[test]
    fn explain_long_form_with_equals() {
        let args = vec!["--timing=4".into(), "--scan-delay=500".into(), "host".into()];
        let g = explain(&args);
        assert!(g.iter().any(|x| x.token == "--timing=4" && x.gloss.contains("preset timing")));
        assert!(g.iter().any(|x| x.token == "--scan-delay=500"));
    }

    #[test]
    fn unknown_flag_marked() {
        let args = vec!["--made-up".into()];
        let g = explain(&args);
        assert_eq!(g.len(), 1);
        assert!(g[0].gloss.contains("sconosciuto"));
    }

    #[test]
    fn positional_targets_are_skipped() {
        let args = vec!["10.0.0.1".into(), "10.0.0.2".into()];
        let g = explain(&args);
        assert!(g.is_empty());
    }
}
