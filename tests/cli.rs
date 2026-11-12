//! End-to-end CLI integration tests (review #26).
//!
//! These spawn the built binary as a subprocess and exercise only
//! *unprivileged, offline* paths — no raw sockets, no network — so they run
//! anywhere (CI, Windows, an unprivileged user). Privileged scan paths are
//! covered by the in-tree unit tests and lab validation on Kali.

use std::process::Command;

fn rustymap() -> Command {
    // Cargo sets this to the freshly built binary for integration tests.
    Command::new(env!("CARGO_BIN_EXE_rustymap"))
}

#[test]
fn version_flag_reports_the_crate_name() {
    let out = rustymap().arg("--version").output().expect("spawn rustymap");
    assert!(out.status.success(), "status: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rustymap"), "stdout was: {stdout:?}");
}

#[test]
fn help_flag_succeeds_and_prints_to_stdout() {
    let out = rustymap().arg("--help").output().expect("spawn rustymap");
    assert!(out.status.success(), "status: {:?}", out.status);
    assert!(!out.stdout.is_empty(), "--help should print usage to stdout");
}

#[test]
fn list_scan_enumerates_targets_offline() {
    // -sL just resolves + lists; with -n there is no DNS and no probing, so
    // this is fully offline and needs no privileges. Targets are TEST-NET-1
    // (RFC 5737) so nothing real is touched even if DNS were on.
    let out = rustymap()
        .args(["--sL", "-n", "192.0.2.0/30"])
        .output()
        .expect("spawn rustymap");
    assert!(
        out.status.success(),
        "status: {:?}, stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("192.0.2.1"), "missing .1 in: {stdout}");
    assert!(stdout.contains("192.0.2.2"), "missing .2 in: {stdout}");
    assert!(stdout.contains("Resolved 2 target"), "missing summary in: {stdout}");
}

#[test]
fn unknown_flag_is_rejected_with_nonzero_exit() {
    let out = rustymap()
        .arg("--definitely-not-a-real-flag")
        .output()
        .expect("spawn rustymap");
    assert!(
        !out.status.success(),
        "an unknown flag must exit non-zero, got: {:?}",
        out.status
    );
}
