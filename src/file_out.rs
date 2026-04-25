//! File-output helpers honoring the global `--append-output` flag.

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static APPEND: AtomicBool = AtomicBool::new(false);

pub fn set_append(on: bool) {
    APPEND.store(on, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn append_enabled() -> bool {
    APPEND.load(Ordering::Relaxed)
}

/// Open a file for writing — appends when `--append-output` is set,
/// truncates otherwise.
pub fn open(path: &str) -> Result<File> {
    let f = if APPEND.load(Ordering::Relaxed) {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
    } else {
        File::create(path)?
    };
    Ok(f)
}

/// Convenience: write the bytes to `path` honoring append mode.
pub fn write(path: &str, bytes: &[u8]) -> Result<()> {
    let mut f = open(path)?;
    f.write_all(bytes)?;
    Ok(())
}
