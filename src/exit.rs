//! Exit-code discipline (Fase 28).
//!
//! RustyMap maps its outcome to a small, scriptable set of process exit
//! codes so a wrapper script or CI step can branch on the result without
//! parsing stdout:
//!
//! | code | meaning     | when                                               |
//! |------|-------------|----------------------------------------------------|
//! | 0    | clean       | scan completed, nothing of note found              |
//! | 1    | findings    | scan completed and surfaced findings (CVE hits,    |
//! |      |             | script findings, deprecated/weak TLS)              |
//! | 2    | scan error  | a runtime/IO failure while scanning                |
//! | 3    | config error| the invocation itself was wrong (bad flag combo,   |
//! |      |             | unreadable profile, invalid spec) — fix the command|
//! | 130  | interrupted | Ctrl-C / SIGINT (128 + SIGINT), matching shells    |
//!
//! The `main` wrapper reads [`success_code`] on the ok path and calls
//! [`classify`] on any error that bubbles up. "Findings" is deliberately
//! security-relevant (something a CI gate would want to fail on), not merely
//! "a port was open" — see [`note_findings`] call sites in `main`.

use std::sync::atomic::{AtomicBool, Ordering};

pub const CLEAN: u8 = 0;
pub const FINDINGS: u8 = 1;
pub const SCAN_ERROR: u8 = 2;
pub const CONFIG_ERROR: u8 = 3;
pub const INTERRUPTED: u8 = 130;

/// Set by the scan path when it surfaces anything worth a non-zero exit.
/// A process-global flag is the least-invasive way to carry one bit of
/// state out of `main`'s large, monolithic body without threading a return
/// type through its many early-return sites.
static FINDINGS_SEEN: AtomicBool = AtomicBool::new(false);

/// Record that the scan found something (OR-accumulating / idempotent).
pub fn note_findings(found: bool) {
    if found {
        FINDINGS_SEEN.store(true, Ordering::Relaxed);
    }
}

/// True if any finding was recorded during this run.
pub fn had_findings() -> bool {
    FINDINGS_SEEN.load(Ordering::Relaxed)
}

/// Success exit code: [`FINDINGS`] if any were recorded, else [`CLEAN`].
pub fn success_code() -> u8 {
    if had_findings() {
        FINDINGS
    } else {
        CLEAN
    }
}

/// A configuration-level error — the user's invocation was wrong, as opposed
/// to a runtime scan failure. Attach it so [`classify`] maps to exit code 3;
/// build one with [`config_err`].
#[derive(Debug)]
pub struct ConfigError;

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error")
    }
}
impl std::error::Error for ConfigError {}

/// Build a configuration error (exit code 3) carrying a human-readable
/// message. The message is what the user sees; the [`ConfigError`] marker in
/// the chain is what [`classify`] keys off.
pub fn config_err(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ConfigError).context(msg.into())
}

/// Classify a bubbled-up error into a process exit code. A [`ConfigError`]
/// anywhere in the chain maps to [`CONFIG_ERROR`] (3); everything else is
/// treated as a runtime [`SCAN_ERROR`] (2), the safe "scan did not complete"
/// signal.
pub fn classify(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        if cause.is::<ConfigError>() {
            return CONFIG_ERROR;
        }
    }
    SCAN_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn plain_error_is_scan_error() {
        let e = anyhow!("socket timed out");
        assert_eq!(classify(&e), SCAN_ERROR);
    }

    #[test]
    fn config_err_is_config_error() {
        let e = config_err("--msf-url is required for --msf-import");
        assert_eq!(classify(&e), CONFIG_ERROR);
        // The human message is preserved as the top-level display.
        assert!(e.to_string().contains("--msf-url"));
    }

    #[test]
    fn config_marker_survives_further_context() {
        let e = config_err("bad --every spec").context("while applying profile");
        assert_eq!(classify(&e), CONFIG_ERROR);
    }

    #[test]
    fn findings_flag_accumulates() {
        // Note: process-global; this is the only test that sets it true.
        assert_eq!(success_code(), CLEAN);
        note_findings(false);
        assert_eq!(success_code(), CLEAN);
        note_findings(true);
        assert_eq!(success_code(), FINDINGS);
        assert!(had_findings());
    }
}
