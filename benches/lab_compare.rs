//! Criterion benchmarks for the CPU-bound work on the critical path of the
//! four lab scan scenarios (SYN /24, full-TCP, service detect, OS detect).
//!
//! Why these and not an end-to-end `rustymap` vs `nmap` race? Network I/O
//! dominates a real scan's wall-clock and is *not* reproducible under
//! Criterion (RTT, loss, and kernel scheduling swamp the signal) — that
//! comparison lives in `PERFORMANCE.md` as a documented, hyperfine-driven
//! methodology against real lab targets. What *is* reproducible, and what a
//! regression here would silently tax on every host, is the deterministic
//! per-scenario compute: enumerating targets and ports, scoring an observed
//! fingerprint against the OS DB, the SEQ statistics, and matching service
//! banners. This harness measures exactly that.
//!
//! Like `benches/parsers.rs`, RustyMap is a bin-only crate (no `lib.rs`), so
//! each bench re-implements its hot loop inline. The reproductions mirror the
//! in-tree code 1:1 and name the source they track, so they move together.
//!
//! Run with `cargo bench`. Criterion writes HTML to `target/criterion/`.
//! Run one group with `cargo bench -- osdb`. The >10% regression gate in
//! `PERFORMANCE.md` reads these numbers.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

// ─────────────────────────────────────────────────────────────
// Scenario: SYN /24 and full-TCP /24 — target host enumeration.
// Mirrors the CIDR → host expansion in `src/target.rs`.
// ─────────────────────────────────────────────────────────────
fn expand_cidr_v4(base: u32, prefix: u8) -> Vec<Ipv4Addr> {
    let host_bits = 32 - prefix as u32;
    let count = 1u32 << host_bits;
    let network = base & !(count - 1);
    // Skip network + broadcast for /<31, as a host sweep does.
    let (lo, hi) = if host_bits >= 2 {
        (network + 1, network + count - 1)
    } else {
        (network, network + count)
    };
    (lo..hi).map(Ipv4Addr::from).collect()
}

fn bench_target_cidr(c: &mut Criterion) {
    let base = u32::from(Ipv4Addr::new(192, 168, 1, 0));
    c.bench_function("target_cidr /24 (254 hosts)", |b| {
        b.iter(|| expand_cidr_v4(black_box(base), black_box(24)))
    });
    c.bench_function("target_cidr /22 (1022 hosts)", |b| {
        b.iter(|| expand_cidr_v4(black_box(base), black_box(22)))
    });
}

// ─────────────────────────────────────────────────────────────
// Scenario: full-TCP (all ports) and SYN (top set) — port expansion.
// Mirrors `src/ports.rs::parse_ports` (BTreeSet dedup + range walk).
// ─────────────────────────────────────────────────────────────
fn parse_ports(spec: &str) -> Vec<u16> {
    let mut set: BTreeSet<u16> = BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = part.split_once('-') {
            let start: u32 = if lhs.is_empty() { 1 } else { lhs.parse().unwrap_or(1) };
            let end: u32 = if rhs.is_empty() { 65535 } else { rhs.parse().unwrap_or(65535) };
            if start == 0 || end > 65535 || start > end {
                continue;
            }
            for p in start..=end {
                set.insert(p as u16);
            }
        } else if let Ok(p) = part.parse::<u32>() {
            if p >= 1 && p <= 65535 {
                set.insert(p as u16);
            }
        }
    }
    set.into_iter().collect()
}

fn bench_port_expand(c: &mut Criterion) {
    c.bench_function("port_expand 1-65535 (all)", |b| {
        b.iter(|| parse_ports(black_box("1-65535")))
    });
    c.bench_function("port_expand 1-1000,8080,8443 (top-ish)", |b| {
        b.iter(|| parse_ports(black_box("1-1000,8080,8443,9000-9200")))
    });
}

// ─────────────────────────────────────────────────────────────
// Scenario: OS detect — score an observed fingerprint against the DB.
// Mirrors `src/nmap_db.rs` field_matches/alt_matches/hexval + the
// match_fingerprint weighted-score loop.
// ─────────────────────────────────────────────────────────────
fn hexval(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim(), 16).ok()
}

fn alt_matches(observed: &str, alt: &str) -> bool {
    if alt.is_empty() {
        return observed.is_empty();
    }
    if let Some(rest) = alt.strip_prefix('>') {
        return matches!((hexval(observed), hexval(rest)), (Some(o), Some(b)) if o > b);
    }
    if let Some(rest) = alt.strip_prefix('<') {
        return matches!((hexval(observed), hexval(rest)), (Some(o), Some(b)) if o < b);
    }
    if let Some((lo, hi)) = alt.split_once('-') {
        if let (Some(o), Some(a), Some(b)) = (hexval(observed), hexval(lo), hexval(hi)) {
            return o >= a && o <= b;
        }
    }
    observed.eq_ignore_ascii_case(alt)
}

fn field_matches(observed: &str, expr: &str) -> bool {
    expr.split('|').any(|alt| alt_matches(observed, alt))
}

type Fp = HashMap<&'static str, HashMap<&'static str, String>>;

/// A representative observed fingerprint (the ~16-test nmap field set).
fn observed_fp() -> Fp {
    let mut fp: Fp = HashMap::new();
    let mut seq = HashMap::new();
    seq.insert("SP", "FD".to_string());
    seq.insert("GCD", "1".to_string());
    seq.insert("ISR", "106".to_string());
    seq.insert("TI", "Z".to_string());
    seq.insert("CI", "RI".to_string());
    seq.insert("II", "I".to_string());
    seq.insert("TS", "21".to_string());
    fp.insert("SEQ", seq);
    for (t, w, o) in [
        ("T1", "FFCB", "O=M"),
        ("T3", "0", "A=S+"),
        ("T4", "0", "A=Z"),
        ("ECN", "FFFF", "CC=N"),
    ] {
        let mut m = HashMap::new();
        m.insert("W", w.to_string());
        m.insert("O", o.to_string());
        m.insert("DF", "Y".to_string());
        m.insert("T", "40".to_string());
        fp.insert(t, m);
    }
    fp
}

/// Build N synthetic reference entries with a mix of exact / hex-range /
/// `>`/`<` / `A|B` expressions, so field_matches exercises every branch.
fn synth_refs(n: usize) -> Vec<Fp> {
    let exprs = ["FD", "F5-107", ">80", "Z|A|A+", "FFCB", "40", "Y", "RI", "A=S+"];
    (0..n)
        .map(|i| {
            let mut fp: Fp = HashMap::new();
            let mut seq = HashMap::new();
            seq.insert("SP", exprs[i % exprs.len()].to_string());
            seq.insert("GCD", "1-6".to_string());
            seq.insert("ISR", "103-10D".to_string());
            seq.insert("TI", "Z|I|RI".to_string());
            fp.insert("SEQ", seq);
            for t in ["T1", "T3", "T4", "ECN"] {
                let mut m = HashMap::new();
                m.insert("W", exprs[(i + 1) % exprs.len()].to_string());
                m.insert("DF", "Y|N".to_string());
                m.insert("T", "38-40".to_string());
                fp.insert(t, m);
            }
            fp
        })
        .collect()
}

fn match_points() -> HashMap<&'static str, HashMap<&'static str, u32>> {
    let mut mp = HashMap::new();
    let mut seq = HashMap::new();
    for (f, w) in [("SP", 25u32), ("GCD", 75), ("ISR", 25), ("TI", 100), ("CI", 50), ("II", 100), ("TS", 100)] {
        seq.insert(f, w);
    }
    mp.insert("SEQ", seq);
    for t in ["T1", "T3", "T4", "ECN"] {
        let mut m = HashMap::new();
        for (f, w) in [("W", 15u32), ("DF", 20), ("T", 15)] {
            m.insert(f, w);
        }
        mp.insert(t, m);
    }
    mp
}

/// Mirrors nmap_db::match_fingerprint: weighted score vs every entry, with
/// the B25/B27 denominator rule (observed fields lacking a MatchPoints weight
/// are skipped) and a top-5 sort.
fn score_all(observed: &Fp, refs: &[Fp], mp: &HashMap<&'static str, HashMap<&'static str, u32>>) -> Vec<u8> {
    let mut scored: Vec<u8> = Vec::with_capacity(refs.len());
    for e in refs {
        let mut matched: u32 = 0;
        let mut total: u32 = 0;
        for (test, fields) in observed {
            for (field, val) in fields {
                let w = match mp.get(test).and_then(|t| t.get(field)) {
                    Some(&w) => w,
                    None => continue, // no MatchPoints weight → not in denominator
                };
                total += w;
                if let Some(expr) = e.get(test).and_then(|rf| rf.get(field)) {
                    if field_matches(val, expr) {
                        matched += w;
                    }
                }
            }
        }
        if total > 0 {
            scored.push((matched as u64 * 100 / total as u64) as u8);
        }
    }
    scored.sort_unstable_by(|a, b| b.cmp(a));
    scored.truncate(5);
    scored
}

fn bench_osdb_score(c: &mut Criterion) {
    let observed = observed_fp();
    let mp = match_points();
    // The real nmap-os-db is ~6500 entries; bench a representative slice and
    // read the cost as linear in entry count (see PERFORMANCE.md).
    let refs_1k = synth_refs(1000);
    let refs_6k = synth_refs(6500);
    c.bench_function("osdb_score vs 1000 entries", |b| {
        b.iter(|| score_all(black_box(&observed), black_box(&refs_1k), black_box(&mp)))
    });
    c.bench_function("osdb_score vs 6500 entries (~full DB)", |b| {
        b.iter(|| score_all(black_box(&observed), black_box(&refs_6k), black_box(&mp)))
    });
}

// ─────────────────────────────────────────────────────────────
// Scenario: OS detect — SEQ statistics over nmap's six SEQ probes.
// Mirrors `src/nmap_fp.rs::seq_analysis` (gcd + ISR + SP + jackknife band).
// ─────────────────────────────────────────────────────────────
fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn seq_analysis(isns: &[u32], times_us: &[u64]) -> (u32, u32, u32) {
    if isns.len() < 3 || isns.len() != times_us.len() {
        return (1, 0, 0);
    }
    let diffs: Vec<u32> = isns
        .windows(2)
        .map(|w| w[1].wrapping_sub(w[0]).min(w[0].wrapping_sub(w[1])))
        .collect();
    let g = diffs.iter().copied().reduce(gcd).unwrap_or(1).max(1);
    let mut rates: Vec<f64> = Vec::new();
    for i in 0..diffs.len() {
        let dt = (times_us[i + 1].saturating_sub(times_us[i])) as f64 / 1_000_000.0;
        if dt > 0.0 {
            rates.push(diffs[i] as f64 / dt);
        }
    }
    let isr_of = |rs: &[f64]| -> u32 {
        if rs.is_empty() { return 0; }
        let m = rs.iter().sum::<f64>() / rs.len() as f64;
        if m < 1.0 { 0 } else { (8.0 * m.log2()).round() as u32 }
    };
    let sp_of = |rs: &[f64]| -> u32 {
        if rs.len() < 2 { return 0; }
        let mean = rs.iter().sum::<f64>() / rs.len() as f64;
        let var = rs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (rs.len() as f64 - 1.0);
        let sd = var.sqrt();
        if sd <= 1.0 { 0 } else { (8.0 * sd.log2()).round() as u32 }
    };
    let isr = isr_of(&rates);
    let sp_vals: Vec<f64> = if g > 9 { rates.iter().map(|r| r / g as f64).collect() } else { rates.clone() };
    let sp = if isns.len() >= 4 && rates.len() >= 2 { sp_of(&sp_vals) } else { 0 };
    // Jackknife (leave-one-out) band, as v0.79.0 added.
    if rates.len() >= 3 {
        for skip in 0..rates.len() {
            let kept: Vec<f64> = rates.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, r)| *r).collect();
            let _ = isr_of(&kept);
            let _ = sp_of(&kept);
        }
    }
    (g, isr, sp)
}

fn bench_seq_analysis(c: &mut Criterion) {
    // Six ISNs from nmap's six SEQ probes, ~100ms apart.
    let isns = [0x1000_0000u32, 0x1000_2a00, 0x1000_5400, 0x1000_7e00, 0x1000_a800, 0x1000_d200];
    let times = [0u64, 100_000, 200_000, 300_000, 400_000, 500_000];
    c.bench_function("seq_analysis 6 ISNs (GCD/ISR/SP/band)", |b| {
        b.iter(|| seq_analysis(black_box(&isns), black_box(&times)))
    });
}

// ─────────────────────────────────────────────────────────────
// Scenario: service detect (-sV) — match a banner against the probe table.
// Mirrors the regex matching in `src/nmap_db.rs` ServiceMatch.
// ─────────────────────────────────────────────────────────────
fn service_patterns() -> Vec<regex::Regex> {
    [
        r"^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)",
        r"^220.*\bFTP\b",
        r"^HTTP/1\.[01] \d{3}",
        r"Server: nginx/?([\d.]+)?",
        r"Server: Apache/?([\d.]+)?",
        r"^\* OK.*IMAP",
        r"^\+OK.*POP3",
        r"^220.*SMTP",
        r"MySQL|mariadb",
        r"^RFB (\d{3})\.(\d{3})",
        r"Microsoft-IIS/([\d.]+)",
        r"Redis|^-NOAUTH",
        r"PostgreSQL",
        r"MongoDB",
        r"^\x00\x00\x00.*SMB",
    ]
    .iter()
    .filter_map(|p| regex::Regex::new(p).ok())
    .collect()
}

fn match_banner(pats: &[regex::Regex], banner: &str) -> usize {
    pats.iter().position(|re| re.is_match(banner)).unwrap_or(usize::MAX)
}

fn bench_service_regex(c: &mut Criterion) {
    let pats = service_patterns();
    c.bench_function("service_regex SSH banner (early hit)", |b| {
        b.iter(|| match_banner(black_box(&pats), black_box("SSH-2.0-OpenSSH_8.9p1 Ubuntu")))
    });
    c.bench_function("service_regex HTTP nginx (mid hit)", |b| {
        b.iter(|| match_banner(black_box(&pats), black_box("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")))
    });
    c.bench_function("service_regex no-match (full scan)", |b| {
        b.iter(|| match_banner(black_box(&pats), black_box("some entirely unrecognised banner text")))
    });
}

criterion_group!(
    lab_compare,
    bench_target_cidr,
    bench_port_expand,
    bench_osdb_score,
    bench_seq_analysis,
    bench_service_regex
);
criterion_main!(lab_compare);
