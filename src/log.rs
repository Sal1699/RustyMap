//! Tiny category-aware debug logger.
//!
//! Three levels (1, 2, 3) controlled by the global `DEBUG_LEVEL`. Each
//! line is tagged with a category (`[net]`, `[probe]`, `[parse]`,
//! `[scan]`, `[evasion]`, `[script]`) so users can filter with
//! `rustymap -dd ... 2>&1 | rg '^\\[probe\\]'`.

use std::sync::atomic::{AtomicU8, Ordering};

static DEBUG_LEVEL: AtomicU8 = AtomicU8::new(0);

pub fn set_level(level: u8) {
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn level() -> u8 {
    DEBUG_LEVEL.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! dbgln {
    ($lvl:expr, $cat:expr, $($arg:tt)*) => {{
        if $crate::log::level() >= $lvl {
            eprintln!("[{}] {}", $cat, format_args!($($arg)*));
        }
    }};
}
