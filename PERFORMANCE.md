# RustyMap — Performance methodology

Reproducible performance work for RustyMap, in two layers:

1. **Microbenchmarks** (`cargo bench`) — deterministic, CPU-bound hot paths.
   Fast, machine-local, regression-gated. No network, no root.
2. **End-to-end lab comparison vs nmap** — wall-clock of real scans against
   real targets. Not reproducible under a microbenchmark harness (RTT, loss
   and kernel scheduling dominate), so it is a *documented procedure* you run
   on the lab and record here per release.

The roadmap's **regression gate** (Fase 27): a release is blocked if any
scenario — micro or macro — is **>10% slower** than the recorded baseline
without a deliberate, noted reason.

---

## Layer 1 — Microbenchmarks (Criterion)

RustyMap is a bin-only crate (no `lib.rs`), so each bench re-implements its
hot loop inline; the reproductions mirror the in-tree code 1:1 and name the
source file they track (see the module docs in each bench).

### Benches

| File | Group | Covers (mirrors) |
|------|-------|------------------|
| `benches/parsers.rs` | `parsers` | CRC32c (SCTP), DNP3 CRC-16, BER-int, banner parse |
| `benches/lab_compare.rs` | `lab_compare` | target/CIDR expansion, port-set expansion, os-db scoring, SEQ stats, service-probe regex |

`lab_compare` maps to the four scan scenarios:

| Scenario | Bench(es) |
|----------|-----------|
| SYN /24, full-TCP /24 (enumeration) | `target_cidr`, `port_expand` |
| Service detect (`-sV`) | `service_regex` |
| OS detect (`-O`) | `osdb_score`, `seq_analysis` |

### Run

```bash
cargo bench                      # all groups; HTML → target/criterion/
cargo bench -- osdb              # only benches whose name contains "osdb"
cargo bench --bench lab_compare  # only the lab_compare harness
```

Criterion prints `change: [-x% +y%]` against the previous run and flags
`Performance has regressed` / `improved` when the change is statistically
significant.

### Regression gate (how to apply)

Before optimisation work, snapshot a baseline; after, compare:

```bash
cargo bench -- --save-baseline before     # e.g. on the release you branch from
# ... make changes ...
cargo bench -- --baseline before          # diff against it
```

**Block the release** if any bench is >10% slower vs the previous release's
baseline and the cause isn't understood and intended. Record the decision in
the CHANGELOG entry.

### Notes for stable numbers

- Build is `--release` (opt-level 3) implicitly under `cargo bench`.
- Close background load; on a laptop, pin the CPU governor to `performance`
  (`sudo cpupower frequency-set -g performance`) and stay on AC power.
- Criterion defaults (100 samples, 3 s measurement) are fine; raise with
  `--measurement-time` for noisy machines.
- Record the machine: CPU model, core count, OS, `rustc --version`.

### Recorded baseline — v0.80.0 (VirtualBox VM, noisy)

Stable anchors (the rest are dominated by VM jitter — 10–20% outliers, wide CIs,
so run-to-run "regressed"/"improved" flags here are noise, not code changes):

| Bench | Mean | Reads as |
|-------|------|----------|
| `osdb_score 6500` (~full DB scan) | ~26 ms | OS-detect scoring cost per host |
| `port_expand 1-65535` (all ports) | ~8.4 ms | full-TCP port-set build |
| `target_cidr /24` | ~0.1 µs | negligible |
| `seq_analysis 6 ISNs` | ~0.4 µs | negligible |
| `service_regex` (per banner) | ~0.1–0.7 µs | negligible |

Takeaway: the microbench hot paths are **not** where scan wall-clock goes — the
real cost is network I/O and the scan engine (see Layer 2). Re-run on bare metal
for numbers worth gating on.

---

## Layer 2 — End-to-end comparison vs nmap (lab)

Run on Kali (root for raw scans). Use **hyperfine** for warm-up + repeats +
stats; fall back to `time` if hyperfine is unavailable.

```bash
sudo apt install -y hyperfine nmap
```

### Fixed inputs (adapt to your lab, then keep them constant across releases)

```bash
NET=192.168.1.0/24          # a /24 you own
HOST=192.168.1.15           # one responsive host
HOSTS="192.168.1.15 192.168.1.20 192.168.1.1"   # a small heterogeneous set
```

Keep the target set, the machine and the flags **identical** release-to-release
— only then are the numbers comparable.

### Scenarios + command pairs

Each `hyperfine` call races RustyMap against nmap with matched flags. `-w 1`
does one warm-up run; `-r 5` takes five measured runs.

**A. SYN sweep, top-1000 ports, /24** (host + port discovery throughput)

```bash
sudo hyperfine -w 1 -r 5 \
  "rustymap --sS $NET" \
  "nmap -sS $NET"
```

**B. Full-TCP, all 65535 ports, single host** (port-rate ceiling)

```bash
sudo hyperfine -w 1 -r 3 \
  "rustymap --sS -p 1-65535 $HOST" \
  "nmap -sS -p 1-65535 $HOST"
```

**C. Service detection (`-sV`), small host set** (probe/banner pipeline)

```bash
hyperfine -w 1 -r 5 \
  "rustymap --sV $HOSTS" \
  "nmap -sV $HOSTS"
```

**D. OS detection (`-O`), small host set** (fingerprint pipeline)

```bash
sudo hyperfine -w 1 -r 5 \
  "rustymap -O $HOSTS" \
  "nmap -O $HOSTS"
```

**E. Aggressive (`-A`), single host** (full pipeline: -sV + -O + scripts)

```bash
sudo hyperfine -w 1 -r 3 \
  "rustymap -A $HOST" \
  "nmap -A $HOST"
```

> Correctness first: a speed win only counts if the results still match the
> validation matrix (`LAB_VALIDATION.md` / `VALIDATION_*.md`). A faster scan
> that misses ports or fields is a regression, not a win.

### Results — record per release

Fill this in from the hyperfine `mean ± σ` on your machine. Ratio = nmap /
RustyMap (>1 means RustyMap is faster).

| Release | Scenario | RustyMap (mean) | nmap (mean) | Ratio | Notes |
|---------|----------|-----------------|-------------|-------|-------|
| v0.80.0 | A SYN /24 | — | — | — | not run (no /24 behind VBox NAT) |
| v0.80.0 | B SYN -p 1-65535 (localhost) | 4.70 s | 0.79 s | **0.17×** | **nmap ~6× faster** — raw port-scan engine |
| v0.80.0 | Connect -p 1-1000 (NAT) | 9.54 s | 5.42 s | **0.57×** | nmap ~1.8× faster |
| v0.80.0 | C -sV -p 80,443 (localhost) | 4.31 s | 12.41 s | 2.88× | RustyMap (parallel probes) |
| v0.80.0 | D -O (localhost) | 3.71 s | 12.29 s | 3.31× | RustyMap |
| v0.80.0 | E -A (localhost) | 6.67 s | 105.37 s | **15.8×** | RustyMap (parallelism compounds) |

_Measured on Kali 6.19 in a VirtualBox VM, localhost/NAT targets. Ratio = nmap /
RustyMap (>1 = RustyMap faster). Correctness: `-O`/`-sV` cross-checked in
`VALIDATION_0.79.md`; SYN/connect port sets match Tier 0. **Honest headline:
RustyMap LOSES on raw port scanning (SYN ~6×, connect ~1.8×) and WINS on the
higher-level phases (-sV/-O/-A) via parallelism.** The large `-A` gap is
dominated by the parallel service/script phase, not port-scan speed._

### Previously observed (earlier lab runs — re-measure, don't trust blindly)

Point-in-time figures from prior validation runs, kept for context. They are
machine- and lab-specific; re-measure each release before claiming them.

| Scenario | Observed | Where | Status vs v0.80.0 |
|----------|----------|-------|-------------------|
| `-A` single host | ~26× faster (5.72 s vs 149.94 s) | v0.71 | Consistent (v0.80.0: 15.8× on localhost VM) |
| `-A` single host | ~22× faster | v0.75 | Consistent |
| SYN scan | ~1.4–7× faster | v0.69.1 | **CONTRADICTED for deep single-host.** v0.80.0 measured nmap **~6× faster** on `-p 1-65535`. The old figure was almost certainly a **/24 sweep** (many hosts, few ports — host-parallel, where RustyMap wins) — a different workload shape than port-depth. The /24 case was NOT re-measured (no /24 in the NAT lab); treat it as unverified until it is. |

**Honest correction:** raw `--sS` is NOT a RustyMap strength on deep single-host
scans — nmap's pcap-based bulk SYN engine (congestion control + send batching)
is ~6× faster on localhost, where there is no network latency to hide behind.
RustyMap's wins are in the **parallel higher-level phases** (`-sV`/`-O`/`-A`).
The honest split: *nmap for port-discovery throughput, RustyMap for the
detect/script pipeline.*

---

## Choosing optimisations

Per the roadmap: pick **2–3 perf wins only after** the bench numbers point at
them — do not optimise on assumption.

**What the v0.80.0 data points at (ranked):**
1. **Raw SYN scan engine** — the clear #1. ~6× behind nmap on `-p 1-65535`
   localhost (14k vs 83k ports/s with no network latency), so it is an engine
   gap, not a network one. Likely levers: batch packet sends instead of
   per-port, a less conservative adaptive limiter on low-loss links, and
   tighter receive-loop/timeout handling. Profile with `perf` before changing.
2. **Connect-scan timeout handling** — ~1.8× behind on NAT; secondary.
3. Everything else (detect/script phases) already beats nmap — don't touch.

Workflow:

1. `cargo bench -- --save-baseline pre` and run Layer-2 scenarios, record.
2. Profile the worst offender (`perf record` / `cargo flamegraph` on a hot
   scenario) to find the real cost, not the guessed one.
3. Make one change; re-run the relevant bench with `--baseline pre`.
4. Keep it only if it's a real, correctness-preserving win; note it in the
   CHANGELOG.
