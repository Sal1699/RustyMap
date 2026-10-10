//! `--self-test`: spawn this binary with a set of no-privilege invocations
//! against localhost and verify none of them crash.
//!
//! This is a pre-release smoke net — it does NOT check scan correctness, only
//! that the common command paths parse their args, run, and exit cleanly
//! rather than panicking. A Rust panic aborts the child with exit code 101,
//! so any other exit (0 clean / 1 findings / 2 scan-error / 3 config-error)
//! counts as "handled". Needs no root/Npcap: every case is connect-based or a
//! pure utility command.

use anyhow::Result;
use std::process::Command;

/// (label, argv). Keep every case privilege-free AND fast: small fixed port
/// sets plus a short `--timeout`/`--max-retries 0` so filtered-port waits on
/// localhost don't stretch the suite out. These exercise code paths, not
/// scan depth.
const CASES: &[(&str, &[&str])] = &[
    ("connect scan", &["127.0.0.1", "-p", "80,443,445", "--sT", "--timeout", "200", "--max-retries", "0", "--no-db", "--no-builtin-scripts"]),
    ("service detect", &["127.0.0.1", "-p", "135,445", "--sV", "--timeout", "200", "--max-retries", "0", "--no-db", "--no-builtin-scripts"]),
    ("ping sweep", &["--sn", "127.0.0.1/31", "--timeout", "200", "--no-db"]),
    ("list scan", &["--sL", "127.0.0.1/30"]),
    ("rich output", &["127.0.0.1", "-p", "80,445", "--timeout", "200", "--max-retries", "0", "--no-db", "--no-builtin-scripts"]),
    ("terse output", &["127.0.0.1", "-p", "80", "--output-style", "terse", "--timeout", "200", "--no-db", "--no-builtin-scripts"]),
    ("recommend", &["--recommend", "127.0.0.1", "-p", "80,443"]),
    ("explain", &["--explain", "--sS", "-p", "1-100", "127.0.0.1"]),
    ("guide", &["--guide"]),
    ("examples", &["--examples"]),
    // Error path: a bad flag must exit 3 (config error), not panic.
    ("config-error path", &["--output-style", "bogus", "127.0.0.1"]),
];

/// Run the smoke suite. Returns `Err` (→ exit 2) if any case crashed.
pub fn run() -> Result<()> {
    let exe = std::env::current_exe()?;
    println!("RustyMap self-test — {} no-privilege case(s) against 127.0.0.1\n", CASES.len());

    let mut pass = 0usize;
    let mut fail = 0usize;
    for (label, args) in CASES {
        // Re-run ourselves; suppress the child's own stdout/stderr so the
        // self-test output stays a clean checklist.
        let result = Command::new(&exe)
            .args(*args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let (ok, detail) = match result {
            // A panic aborts with 101 (or no code on a signal); everything
            // else is a handled exit.
            Ok(st) => match st.code() {
                Some(101) => (false, "panicked (exit 101)".to_string()),
                Some(c) => (true, format!("exit {}", c)),
                None => (false, "killed by signal".to_string()),
            },
            Err(e) => (false, format!("spawn failed: {}", e)),
        };
        if ok {
            pass += 1;
            println!("  [ok]   {:<18} {}", label, detail);
        } else {
            fail += 1;
            println!("  [FAIL] {:<18} {}", label, detail);
        }
    }

    println!("\n{} passed, {} failed", pass, fail);
    if fail > 0 {
        Err(anyhow::anyhow!(
            "self-test: {} case(s) crashed — see [FAIL] rows above",
            fail
        ))
    } else {
        Ok(())
    }
}
