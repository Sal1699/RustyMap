//! nmap-compatible OS-fingerprint field computation.
//!
//! nmap's OS engine doesn't just look at TTL/window — it derives ~30
//! coded fields across the SEQ / OPS / WIN / ECN / T1–T7 / IE / U1 tests
//! and matches them against `nmap-os-db`. This module holds the **pure**
//! classification logic for those fields (no sockets), so it can be
//! unit-tested on any platform; `tcp_probe_suite` feeds it the raw
//! response values captured over the wire.
//!
//! Implemented fields:
//!   - SEQ line: GCD, SP, ISR, TI/CI/II (IP-ID generation), TS (timestamp
//!     rate class)
//!   - Per-probe: S (seq), A (ack), F (flags), O (options), W (window),
//!     Q (quirks), RD (RST data), and CC (ECN congestion control)
//!
//! The classifications follow nmap's definitions closely enough to make
//! RustyMap's fingerprint block directly comparable with `nmap -O -d`.
//! Full `nmap-os-db` pattern-language matching (ranges / `|` / `&`) is a
//! separate, larger effort; here we generate the fingerprint and score
//! it heuristically.

/// Euclid's GCD (used for the SEQ GCD field and ISN analysis).
pub fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// SEQ analysis result (nmap SEQ line, numeric part).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqResult {
    /// Greatest common divisor of the ISN differences.
    pub gcd: u32,
    /// Initial Sequence Rate: `round(8 * log2(avg_isn_rate_per_sec))`.
    pub isr: u32,
    /// Sequence Predictability: `round(8 * log2(stddev_of_normalized_diffs))`.
    pub sp: u32,
    /// Jackknife (leave-one-out) min/max of ISR across the rate samples.
    /// SP and ISR are the only sampling-dependent SEQ fields, which is why
    /// nmap records them as *ranges* in its DB (aggregated over many hosts).
    /// A single live scan can't reproduce that cross-host spread, but the
    /// jackknife band quantifies this run's own sensitivity to each sample
    /// so the `nmap -O` comparison can show "falls inside nmap's range".
    pub isr_lo: u32,
    pub isr_hi: u32,
    /// Jackknife (leave-one-out) min/max of SP across the rate samples.
    pub sp_lo: u32,
    pub sp_hi: u32,
}

/// nmap's SEQ GCD/ISR/SP from a set of ISNs and their capture times (µs).
/// Needs at least 3 ISNs. Mirrors nmap's `seq_analysis` closely enough
/// for the numbers to line up in practice.
pub fn seq_analysis(isns: &[u32], times_us: &[u64]) -> Option<SeqResult> {
    if isns.len() < 3 || isns.len() != times_us.len() {
        return None;
    }
    let diffs: Vec<u32> = isns
        .windows(2)
        .map(|w| {
            let fwd = w[1].wrapping_sub(w[0]);
            let rev = w[0].wrapping_sub(w[1]);
            fwd.min(rev) // nmap uses the smaller of the two wrap directions
        })
        .collect();

    let g = diffs.iter().copied().reduce(gcd).unwrap_or(1).max(1);

    // ISR: average rate of ISN increase per second.
    let mut rates: Vec<f64> = Vec::new();
    for i in 0..diffs.len() {
        let dt = (times_us[i + 1].saturating_sub(times_us[i])) as f64 / 1_000_000.0;
        if dt > 0.0 {
            rates.push(diffs[i] as f64 / dt);
        }
    }
    // ISR from a set of rate samples: round(8 * log2(mean_rate)).
    let isr_of = |rs: &[f64]| -> u32 {
        if rs.is_empty() {
            return 0;
        }
        let m = rs.iter().sum::<f64>() / rs.len() as f64;
        if m < 1.0 {
            0
        } else {
            (8.0 * m.log2()).round() as u32
        }
    };
    // SP statistic from a set of (already GCD-normalized) rate samples:
    // round(8 * log2(stddev)), sample variance (n-1), 0 when stddev ≤ 1.
    let sp_of = |rs: &[f64]| -> u32 {
        if rs.len() < 2 {
            return 0;
        }
        let mean = rs.iter().sum::<f64>() / rs.len() as f64;
        let var = rs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (rs.len() as f64 - 1.0);
        let sd = var.sqrt();
        if sd <= 1.0 {
            0
        } else {
            (8.0 * sd.log2()).round() as u32
        }
    };

    let isr = isr_of(&rates);

    // SP: standard deviation of the **rate** values (not the raw diffs),
    // divided by GCD only when GCD > 9 — exactly as nmap. nmap reports SP
    // only with ≥4 responses; sample variance (n-1); SP=0 if stddev ≤ 1.
    let sp_vals: Vec<f64> = if g > 9 {
        rates.iter().map(|r| r / g as f64).collect()
    } else {
        rates.clone()
    };
    let sp = if isns.len() >= 4 && rates.len() >= 2 {
        sp_of(&sp_vals)
    } else {
        0
    };

    // Jackknife (leave-one-out) bands: recompute ISR/SP with each rate
    // sample dropped in turn and take the min/max. This is the run's own
    // sampling spread, the live analogue of nmap's DB SP/ISR ranges.
    let mut isr_band = vec![isr];
    let mut sp_band = vec![sp];
    if rates.len() >= 3 {
        for skip in 0..rates.len() {
            let r_kept: Vec<f64> = rates
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, x)| *x)
                .collect();
            isr_band.push(isr_of(&r_kept));
            if isns.len() >= 4 {
                let s_kept: Vec<f64> = sp_vals
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != skip)
                    .map(|(_, x)| *x)
                    .collect();
                sp_band.push(sp_of(&s_kept));
            }
        }
    }
    let isr_lo = *isr_band.iter().min().unwrap_or(&isr);
    let isr_hi = *isr_band.iter().max().unwrap_or(&isr);
    let sp_lo = *sp_band.iter().min().unwrap_or(&sp);
    let sp_hi = *sp_band.iter().max().unwrap_or(&sp);

    Some(SeqResult { gcd: g, isr, sp, isr_lo, isr_hi, sp_lo, sp_hi })
}

/// nmap S field — response SEQ vs the probe's ACK number.
pub fn seq_field(resp_seq: u32, sent_ack: u32) -> &'static str {
    if resp_seq == 0 {
        "Z"
    } else if resp_seq == sent_ack {
        "A"
    } else if resp_seq == sent_ack.wrapping_add(1) {
        "A+"
    } else {
        "O"
    }
}

/// nmap A field — response ACK vs the probe's SEQ number.
pub fn ack_field(resp_ack: u32, sent_seq: u32) -> &'static str {
    if resp_ack == 0 {
        "Z"
    } else if resp_ack == sent_seq {
        "S"
    } else if resp_ack == sent_seq.wrapping_add(1) {
        "S+"
    } else {
        "O"
    }
}

/// nmap Q (quirks) field: `R` = reserved TCP header bits set,
/// `U` = urgent pointer non-zero while the URG flag is clear.
pub fn quirks(reserved_nonzero: bool, urg_ptr: u16, urg_flag: bool) -> String {
    let mut q = String::new();
    if reserved_nonzero {
        q.push('R');
    }
    if urg_ptr != 0 && !urg_flag {
        q.push('U');
    }
    q
}

/// nmap RD field: CRC32 of any data carried in a RST, else 0. Almost
/// every stack sends empty RSTs; a non-zero value flags exotic stacks
/// (some load-balancers embed an explanatory string).
pub fn rst_data(payload: &[u8]) -> u32 {
    if payload.is_empty() {
        0
    } else {
        crc32(payload)
    }
}

/// nmap ECN CC field from the response's ECE/CWR flags.
pub fn ecn_cc(ece: bool, cwr: bool) -> char {
    match (ece, cwr) {
        (true, false) => 'Y', // ECN echoed, CWR cleared → supported
        (false, false) => 'N', // neither → not supported
        (true, true) => 'S',  // both set → reflected/stupid
        (false, true) => 'O', // only CWR → other
    }
}

/// nmap TI/CI/II field: IP-ID generation algorithm from a sample series,
/// following nmap's exact classification order:
///   Z  = all zero
///   RD = any increment ≥ 20000 (fully randomized) — checked *before* RI
///   C  = all identical (constant, non-zero)
///   RI = all increments > 1000 (random positive increments)
///   BI = all increments divisible by 256 and ≤ 5120 (broken byte order)
///   I  = all increments < 10 (sequential)
///   "" = otherwise (omitted)
pub fn ip_id_class(ids: &[u16]) -> &'static str {
    if ids.len() < 2 {
        return "";
    }
    if ids.iter().all(|&x| x == 0) {
        return "Z";
    }
    let diffs: Vec<u32> = ids
        .windows(2)
        .map(|w| (w[1] as i32 - w[0] as i32).rem_euclid(65536) as u32)
        .collect();
    // A large jump means the IP-ID is randomized (RD), checked ahead of the
    // incremental cases (lab bug B22). BUT RD needs enough evidence: nmap
    // never assigns RD to II (2 samples) and, with only a couple of diffs,
    // treats a big jump as RI rather than RD — so require ≥3 diffs (≥4
    // samples). This keeps TI=RD while CI/II (few samples) read RI (B26).
    if diffs.len() >= 3 && diffs.iter().any(|&d| d >= 20000) {
        return "RD";
    }
    if diffs.iter().all(|&d| d == 0) {
        return "C";
    }
    if diffs.iter().all(|&d| d > 1000) {
        return "RI";
    }
    if diffs.iter().all(|&d| d != 0 && d % 256 == 0) && diffs.iter().all(|&d| d <= 5120) {
        return "BI";
    }
    if diffs.iter().all(|&d| d < 10) {
        return "I";
    }
    ""
}

/// nmap TS field: timestamp-option rate class = `round(log2(freq))` in
/// uppercase hex (so ~2 Hz → "1", ~100 Hz → "7", ~200 Hz → "8", ~1000 Hz
/// → "A"). `U` = option not supported, `0` = present but always zero.
pub fn ts_field(supported: bool, always_zero: bool, hz: Option<f64>) -> String {
    if !supported {
        return "U".to_string();
    }
    if always_zero {
        return "0".to_string();
    }
    match hz {
        Some(h) if h >= 1.0 => format!("{:X}", h.log2().round() as u32),
        _ => "U".to_string(),
    }
}

/// A single probe's coded response, in nmap `%`-separated notation.
#[derive(Debug, Clone, Default)]
pub struct ProbeFields {
    pub name: String,
    pub responded: bool,
    pub df: Option<bool>,
    pub ttl: Option<u8>,
    pub window: Option<u16>,
    pub seq: Option<&'static str>,
    pub ack: Option<&'static str>,
    pub flags: Option<String>,
    pub options: Option<String>,
    pub rd: Option<u32>,
    pub quirks: Option<String>,
    pub cc: Option<char>,
}

impl ProbeFields {
    pub fn not_responded(name: &str) -> Self {
        ProbeFields { name: name.to_string(), responded: false, ..Default::default() }
    }

    /// Render as an nmap fingerprint line, e.g.
    /// `T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)`.
    pub fn line(&self) -> String {
        if !self.responded {
            return format!("{}(R=N)", self.name);
        }
        let mut parts: Vec<String> = vec!["R=Y".to_string()];
        if let Some(df) = self.df {
            parts.push(format!("DF={}", if df { "Y" } else { "N" }));
        }
        if let Some(t) = self.ttl {
            parts.push(format!("T={:X}", t)); // nmap prints TTL in hex
        }
        if let Some(w) = self.window {
            parts.push(format!("W={:X}", w));
        }
        if let Some(s) = self.seq {
            parts.push(format!("S={}", s));
        }
        if let Some(a) = self.ack {
            parts.push(format!("A={}", a));
        }
        if let Some(f) = &self.flags {
            parts.push(format!("F={}", f));
        }
        if let Some(o) = &self.options {
            parts.push(format!("O={}", o));
        }
        if let Some(cc) = self.cc {
            parts.push(format!("CC={}", cc));
        }
        if let Some(rd) = self.rd {
            parts.push(format!("RD={}", rd));
        }
        if let Some(q) = &self.quirks {
            parts.push(format!("Q={}", q));
        }
        format!("{}({})", self.name, parts.join("%"))
    }
}

/// Minimal CRC-32 (IEEE) for the RD field. Table-free, bit-at-a-time.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_and_ack_fields() {
        // RST to our probe: resp.seq=0, resp.ack = our_seq+1.
        assert_eq!(seq_field(0, 12345), "Z");
        assert_eq!(ack_field(1001, 1000), "S+");
        assert_eq!(ack_field(1000, 1000), "S");
        assert_eq!(seq_field(500, 499), "A+");
        assert_eq!(seq_field(499, 499), "A");
        assert_eq!(seq_field(7, 100), "O");
        assert_eq!(ack_field(0, 5), "Z");
    }

    #[test]
    fn quirks_detects_reserved_and_urg() {
        assert_eq!(quirks(true, 0, false), "R");
        assert_eq!(quirks(false, 0xF7F5, false), "U");
        assert_eq!(quirks(true, 0xF7F5, false), "RU");
        assert_eq!(quirks(false, 0xF7F5, true), ""); // URG set → not a quirk
        assert_eq!(quirks(false, 0, false), "");
    }

    #[test]
    fn ecn_cc_classes() {
        assert_eq!(ecn_cc(true, false), 'Y');
        assert_eq!(ecn_cc(false, false), 'N');
        assert_eq!(ecn_cc(true, true), 'S');
        assert_eq!(ecn_cc(false, true), 'O');
    }

    #[test]
    fn ip_id_classification() {
        assert_eq!(ip_id_class(&[0, 0, 0]), "Z");
        assert_eq!(ip_id_class(&[10, 11, 12, 13]), "I"); // +1 increments
        // ≥3 diffs (≥4 samples) with a ≥20000 jump → RD (B22, TI flow).
        assert_eq!(ip_id_class(&[100, 40000, 5000, 61000]), "RD");
        // Few samples (CI/II) with a big jump must NOT be RD → RI (B26).
        assert_eq!(ip_id_class(&[100, 40000]), "RI"); // II: 1 diff
        assert_eq!(ip_id_class(&[100, 40000, 5000]), "RI"); // CI: 2 diffs
        // All increments > 1000 but < 20000 → RI.
        assert_eq!(ip_id_class(&[100, 2000, 4500, 7200]), "RI");
        assert_eq!(ip_id_class(&[256, 512, 768]), "BI"); // multiples of 256
        assert_eq!(ip_id_class(&[42]), "");
    }

    #[test]
    fn ts_classes() {
        assert_eq!(ts_field(false, false, None), "U");
        assert_eq!(ts_field(true, true, None), "0");
        assert_eq!(ts_field(true, false, Some(2.0)), "1");   // log2(2)=1
        assert_eq!(ts_field(true, false, Some(100.0)), "7"); // round(log2 100)=7
        assert_eq!(ts_field(true, false, Some(250.0)), "8"); // round(log2 250)=8
        assert_eq!(ts_field(true, false, Some(1000.0)), "A"); // round(log2 1000)=10=A
    }

    #[test]
    fn seq_analysis_incremental_is_low_sp() {
        // Perfectly linear ISN (+64000 every 100ms) → predictable, low SP.
        let isns = [1_000_000u32, 1_064_000, 1_128_000, 1_192_000, 1_256_000];
        let times = [0u64, 100_000, 200_000, 300_000, 400_000];
        let r = seq_analysis(&isns, &times).unwrap();
        assert_eq!(r.gcd, 64000);
        assert_eq!(r.sp, 0, "linear ISN must be maximally predictable");
        assert!(r.isr > 0);
    }

    #[test]
    fn seq_analysis_needs_three() {
        assert!(seq_analysis(&[1, 2], &[0, 1]).is_none());
    }

    #[test]
    fn seq_analysis_bands_bracket_point() {
        // Noisy-but-incrementing ISNs → non-trivial SP/ISR with a band.
        let isns = [
            1_000_000u32,
            1_070_000,
            1_131_000,
            1_205_000,
            1_259_000,
            1_338_000,
        ];
        let times = [0u64, 100_000, 205_000, 300_000, 405_000, 500_000];
        let r = seq_analysis(&isns, &times).unwrap();
        // The point estimate must sit inside its own jackknife band.
        assert!(r.isr_lo <= r.isr && r.isr <= r.isr_hi, "ISR point inside band");
        assert!(r.sp_lo <= r.sp && r.sp <= r.sp_hi, "SP point inside band");
    }

    #[test]
    fn seq_analysis_linear_band_is_tight() {
        // Perfectly linear ISN → SP=0 with a degenerate (0-width) band.
        let isns = [1_000_000u32, 1_064_000, 1_128_000, 1_192_000, 1_256_000];
        let times = [0u64, 100_000, 200_000, 300_000, 400_000];
        let r = seq_analysis(&isns, &times).unwrap();
        assert_eq!(r.sp_lo, 0);
        assert_eq!(r.sp_hi, 0);
        assert_eq!(r.isr_lo, r.isr_hi, "constant rate → single-point ISR band");
    }

    #[test]
    fn probe_line_matches_nmap_shape() {
        let p = ProbeFields {
            name: "T5".into(),
            responded: true,
            df: Some(true),
            ttl: Some(64),
            window: Some(0),
            seq: Some("Z"),
            ack: Some("S+"),
            flags: Some("AR".into()),
            options: Some(String::new()),
            rd: Some(0),
            quirks: Some(String::new()),
            cc: None,
        };
        assert_eq!(p.line(), "T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)");
        assert_eq!(ProbeFields::not_responded("T6").line(), "T6(R=N)");
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32/IEEE of "123456789" = 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
