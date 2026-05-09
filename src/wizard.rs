//! Interactive scan-wizard — `--wizard`.
//!
//! Walks the user through a sequence of prompts and assembles a
//! rustymap invocation. Pure stdin/stdout, no TUI dep. Each prompt
//! has a default the user can accept by pressing Enter; numeric
//! choices fall back to the default on bad input.
//!
//! At the end the wizard:
//!   1. Prints the assembled command.
//!   2. Asks whether to run it now (Y/n).
//!   3. Optionally writes it to a profile file (`save profile? path`).
//!
//! When run is chosen, `--wizard` exits and main() restarts with
//! the assembled args; we do this rather than calling into the
//! scanner directly so every CLI side-effect (audit, telemetry,
//! report writers) goes through the normal code path.

use anyhow::Result;
use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Default)]
pub struct WizardOutput {
    /// Assembled CLI args (what would follow `rustymap` on the
    /// command line). Excludes the "rustymap" itself.
    pub args: Vec<String>,
    /// True when the user picked "yes" to run-now.
    pub run_now: bool,
    /// When set, persist the assembled args to this profile path.
    pub save_profile: Option<String>,
}

/// Reads a line from stdin, returns `default` on empty input.
fn ask(prompt: &str, default: &str) -> String {
    print!("  {} [{}]: ", prompt, default);
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn ask_yes(prompt: &str, default_yes: bool) -> bool {
    let def = if default_yes { "Y/n" } else { "y/N" };
    let ans = ask(prompt, def).to_lowercase();
    if ans.starts_with('y') {
        true
    } else if ans.starts_with('n') {
        false
    } else {
        default_yes
    }
}

fn ask_choice(prompt: &str, choices: &[&str], default_idx: usize) -> usize {
    println!("  {}", prompt);
    for (i, c) in choices.iter().enumerate() {
        let marker = if i == default_idx { ">" } else { " " };
        println!("    {} {}. {}", marker, i + 1, c);
    }
    let raw = ask("choice", &(default_idx + 1).to_string());
    raw.trim()
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=choices.len()).contains(n))
        .map(|n| n - 1)
        .unwrap_or(default_idx)
}

pub fn run() -> Result<WizardOutput> {
    use colored::*;
    println!();
    println!("{}", "RustyMap scan wizard".bold().underline());
    println!("  Press Enter at any prompt to accept the default.");
    println!();

    let mut args: Vec<String> = Vec::new();

    // Target.
    let target = ask("Target (IP, hostname, CIDR)", "127.0.0.1");
    args.push(target);

    // Scan type.
    let scan_choices = ["TCP connect (no privilege)", "TCP SYN (raw, root/admin)", "UDP", "List only (resolve targets)"];
    let scan_idx = ask_choice("Scan type", &scan_choices, 0);
    match scan_idx {
        1 => args.push("--sS".into()),
        2 => args.push("--sU".into()),
        3 => args.push("--sL".into()),
        _ => {} // sT is the default — no flag needed
    }

    // Ports.
    let port_choices = [
        "Top 100 (--fast)",
        "Top 1000 (default)",
        "All 65535 (--all-ports)",
        "Custom range",
    ];
    let port_idx = ask_choice("Port set", &port_choices, 1);
    match port_idx {
        0 => args.push("-F".into()),
        2 => args.push("--all-ports".into()),
        3 => {
            let custom = ask("Port spec (e.g. 22,80,443 or 1-1024)", "1-1024");
            args.push("-p".into());
            args.push(custom);
        }
        _ => {} // top 1000 is default
    }

    // Service / OS detection.
    if ask_yes("Service version detection (-sV)?", true) {
        args.push("-sV".into());
    }
    if ask_yes("OS fingerprint (-O)?", false) {
        args.push("-O".into());
    }

    // Aggressive shortcut?
    if ask_yes("Use --aggressive (-A: -sV -O --traceroute + scripts/)?", false) {
        args.push("-A".into());
    }

    // Audit add-ons.
    println!("{}", "Optional audits — pick what fits your scope:".dimmed());
    if ask_yes("--ssl-enum (TLS protocol/cipher enum)?", false) {
        args.push("--ssl-enum".into());
    }
    if ask_yes("--tls-grade (A+/F + DROWN/POODLE/Heartbleed)?", false) {
        args.push("--tls-grade".into());
    }
    if ask_yes("--auth-audit (SSH+SMB+RDP+SMTP)?", false) {
        args.push("--auth-audit".into());
    }
    if ask_yes("--http-enum (admin/leak path enumeration)?", false) {
        args.push("--http-enum".into());
    }

    // Compliance.
    let compliance_choices = ["none", "PCI-DSS", "HIPAA", "NIST 800-53", "ISO 27001", "CIS"];
    let comp_idx = ask_choice("Compliance framework", &compliance_choices, 0);
    if comp_idx > 0 {
        let fw = match comp_idx {
            1 => "pci-dss",
            2 => "hipaa",
            3 => "nist-800-53",
            4 => "iso-27001",
            _ => "cis",
        };
        args.push("--compliance".into());
        args.push(fw.into());
    }

    // Outputs.
    if ask_yes("Write outputs (txt/json/html/md/pdf)?", false) {
        let prefix = ask("Output prefix (--oA)", "scan");
        args.push("--oA".into());
        args.push(prefix);
    }
    if ask_yes("Executive summary at end?", true) {
        args.push("--executive-summary".into());
    }

    // Tail.
    println!();
    println!("{}", "Assembled command:".bold());
    println!("  rustymap {}", args.join(" "));
    println!();

    let run_now = ask_yes("Run it now?", true);
    let save_profile = if ask_yes("Save these args as a profile?", false) {
        let path = ask("Profile path", "scan.toml");
        Some(path)
    } else {
        None
    };

    Ok(WizardOutput {
        args,
        run_now,
        save_profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wizard reads from stdin so we can't fully unit-test it
    // without mocking — these tests cover the helpers that DO have
    // pure inputs.

    #[test]
    fn ask_choice_default_when_blank_input() {
        // Can't drive stdin in a unit test without unsafe stdin
        // redirection — exercise the bounds-check helper directly.
        let parsed: Option<usize> = "0".parse::<usize>().ok().filter(|n| (1..=3).contains(n));
        assert!(parsed.is_none());
        let parsed: Option<usize> = "2".parse::<usize>().ok().filter(|n| (1..=3).contains(n));
        assert_eq!(parsed, Some(2));
    }

    #[test]
    fn output_holds_args_and_flags() {
        let o = WizardOutput {
            args: vec!["10.0.0.1".into(), "-sV".into()],
            run_now: true,
            save_profile: Some("p.toml".into()),
        };
        assert_eq!(o.args.len(), 2);
        assert!(o.run_now);
        assert_eq!(o.save_profile.as_deref(), Some("p.toml"));
    }
}
