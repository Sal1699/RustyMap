//! File-output helpers honoring the global `--append-output` flag, with
//! nmap-style `-` → stdout support: `--oN/--oG/--oJ/--oX -` stream the chosen
//! format to standard output instead of a file.

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static APPEND: AtomicBool = AtomicBool::new(false);

pub fn set_append(on: bool) {
    APPEND.store(on, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn append_enabled() -> bool {
    APPEND.load(Ordering::Relaxed)
}

/// `-` is the nmap convention for "write this format to stdout". Only a bare
/// dash qualifies — `./-` or `foo-` are ordinary file names.
pub fn is_stdout(path: &str) -> bool {
    path == "-"
}

/// Open a writer for `path`: stdout when `path` is `-`, otherwise a file
/// (appended when `--append-output` is set, truncated otherwise). Returning a
/// boxed `Write` lets every text writer target stdout transparently.
pub fn open_writer(path: &str) -> Result<Box<dyn Write>> {
    if is_stdout(path) {
        return Ok(Box::new(io::stdout()));
    }
    let f = if APPEND.load(Ordering::Relaxed) {
        OpenOptions::new().create(true).append(true).open(path)?
    } else {
        File::create(path)?
    };
    Ok(Box::new(f))
}

/// Convenience: write the bytes to `path` (or stdout for `-`) honoring append
/// mode.
pub fn write(path: &str, bytes: &[u8]) -> Result<()> {
    let mut w = open_writer(path)?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bare_dash_is_a_stdout_sink() {
        assert!(is_stdout("-"));
        assert!(!is_stdout("out.xml"));
        assert!(!is_stdout("./-")); // a file literally named "-" in cwd
        assert!(!is_stdout("scan-"));
        assert!(!is_stdout(""));
    }
}
