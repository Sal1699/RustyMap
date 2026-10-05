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

| Release | Scenario | RustyMap (mean) | nmap (mean) | Ratio | Correctness |
|---------|----------|-----------------|-------------|-------|-------------|
| v0.79.1 | A SYN /24 | _TBD_ | _TBD_ | _TBD_ | _vs matrix_ |
| v0.79.1 | B full-TCP host | _TBD_ | _TBD_ | _TBD_ | |
| v0.79.1 | C service detect | _TBD_ | _TBD_ | _TBD_ | |
| v0.79.1 | D OS detect | _TBD_ | _TBD_ | _TBD_ | |
| v0.79.1 | E aggressive | _TBD_ | _TBD_ | _TBD_ | |

### Previously observed (earlier lab runs — re-measure, don't trust blindly)

Point-in-time figures from prior validation runs, kept for context. They are
machine- and lab-specific; re-measure each release before claiming them.

| Scenario | Observed | Where |
|----------|----------|-------|
| `-A` single host (LAN) | ~26× faster than nmap (5.72 s vs 149.94 s) | v0.71 lab run |
| `-A` single host (LAN) | ~22× faster than nmap | v0.75 lab run |
| SYN scan | ~1.4–7× faster than nmap | v0.69.1 lab run (57-test wave) |

The `-A` gap is large mainly because RustyMap parallelises the service/script
phase aggressively; raw `--sS` is the honest apples-to-apples number and is the
one to watch for regressions.

---

## Choosing optimisations

Per the roadmap: pick **2–3 perf wins only after** the bench numbers point at
them — do not optimise on assumption. Workflow:

1. `cargo bench -- --save-baseline pre` and run Layer-2 scenarios, record.
2. Profile the worst offender (`perf record` / `cargo flamegraph` on a hot
   scenario) to find the real cost, not the guessed one.
3. Make one change; re-run the relevant bench with `--baseline pre`.
4. Keep it only if it's a real, correctness-preserving win; note it in the
   CHANGELOG.
