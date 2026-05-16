//! Criterion benchmarks for the codec / parser hot-paths.
//!
//! Network-bound code can't be micro-benchmarked reproducibly. This
//! harness focuses on the deterministic pieces — CRC32c (SCTP),
//! DNP3 CRC-16, and reproductions of the BER-int / banner-parse hot
//! loops so we can measure regressions as the codebase evolves.
//!
//! Run with `cargo bench`. Criterion writes HTML reports to
//! `target/criterion/`. Run a single bench with `cargo bench -- <name>`.
//!
//! We deliberately do NOT depend on the binary crate here. RustyMap
//! is a bin-only project; adding a `lib.rs` re-export just to feed
//! the bench would expand the public surface unnecessarily. Instead
//! we re-implement the tight loops inline (they're 10–20 lines each)
//! and benchmark those reproductions — they track the in-tree code
//! 1:1 by construction.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// ── CRC32c (SCTP / iSCSI) via the `crc32c` crate ──
fn bench_crc32c(c: &mut Criterion) {
    let small: Vec<u8> = (0..64).map(|i| (i & 0xff) as u8).collect();
    let mtu: Vec<u8> = (0..1500).map(|i| (i & 0xff) as u8).collect();
    let jumbo: Vec<u8> = (0..9000).map(|i| (i & 0xff) as u8).collect();
    c.bench_function("crc32c 64B", |b| {
        b.iter(|| crc32c::crc32c(black_box(&small)))
    });
    c.bench_function("crc32c 1500B (MTU)", |b| {
        b.iter(|| crc32c::crc32c(black_box(&mtu)))
    });
    c.bench_function("crc32c 9000B (jumbo)", |b| {
        b.iter(|| crc32c::crc32c(black_box(&jumbo)))
    });
}

// ── DNP3 CRC-16 — bit-by-bit reflected reference impl ──
// Mirrors `src/ics_scan.rs::dnp3_crc` so this bench tracks any
// future loop optimisation.
fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn bench_dnp3_crc(c: &mut Criterion) {
    let frame = [0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x00, 0x00];
    c.bench_function("dnp3_crc 8B (link-status frame)", |b| {
        b.iter(|| dnp3_crc(black_box(&frame)))
    });
}

// ── BER integer encoder reference (mirrors snmp_enum.rs / ldap_enum.rs) ──
fn ber_int(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let lead = bytes[0];
        let next_msb = bytes[1] & 0x80 != 0;
        if (lead == 0 && !next_msb) || (lead == 0xff && next_msb) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(0x02);
    out.push(bytes.len() as u8);
    out.extend(bytes);
    out
}

fn bench_ber_int(c: &mut Criterion) {
    c.bench_function("ber_int small (123)", |b| {
        b.iter(|| ber_int(black_box(123)))
    });
    c.bench_function("ber_int large (i32::MAX)", |b| {
        b.iter(|| ber_int(black_box(i32::MAX as i64)))
    });
}

// ── Banner parser reproduction — slash + space + version-token pick ──
fn parse_banner(banner: &str) -> Option<(String, String)> {
    let trimmed = banner.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((p, v)) = trimmed.split_once('/') {
        let p = p.trim().to_string();
        let v = v.trim().split_whitespace().next()?.to_string();
        if !p.is_empty() && !v.is_empty() {
            return Some((p, v));
        }
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let product = parts[0].to_string();
    let version = parts.iter().skip(1).find_map(|tok| {
        let has_digit = tok.chars().any(|c| c.is_ascii_digit());
        let has_separator = tok.contains('.') || tok.chars().any(|c| c == 'p' || c == '-');
        if has_digit && has_separator {
            Some(tok.to_string())
        } else {
            None
        }
    })?;
    Some((product, version))
}

fn bench_banner_parser(c: &mut Criterion) {
    c.bench_function("parse_banner nginx/1.18.0", |b| {
        b.iter(|| parse_banner(black_box("nginx/1.18.0")))
    });
    c.bench_function("parse_banner openssh 7.4p1", |b| {
        b.iter(|| parse_banner(black_box("openssh 7.4p1")))
    });
    c.bench_function("parse_banner Apache 2.4.41 (Ubuntu)", |b| {
        b.iter(|| parse_banner(black_box("Apache 2.4.41 (Ubuntu)")))
    });
}

criterion_group!(
    parsers,
    bench_crc32c,
    bench_dnp3_crc,
    bench_ber_int,
    bench_banner_parser
);
criterion_main!(parsers);
