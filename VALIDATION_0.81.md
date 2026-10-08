# RustyMap v0.81.0 — Lab Validation Report

**Date:** 2026-10-07/08 · **Tester:** Kali 192.168.1.79 · **Tool:** hyperfine + manual
**Lab:** home /24 (19 hosts). Targets: ROUTER 192.168.1.1 (TIM/Vantiva),
SERVER .31 (Alcatel-Lucent AP/OpenWrt), CAM .34 (Reolink), MAC .53, WIN .64 &
WIN2 .85 (Win 11), LINUX .148 (printer).

---

## PART A — the 6 v0.81.0 fixes

### A1 — SYN/connect adaptive timeout — **PARTIAL**
| Test | RM 0.81 | nmap | Ratio | v0.80 | Verdict |
|------|---------|------|-------|-------|---------|
| SYN 1-1000 ROUTER | **24.7s** | 47.4s | **RM 1.9× faster** | 35× slower | **fixed** |
| SYN -F ROUTER | 33.5s | 4.1s | nmap 8.2× | 10× | improved, still slow |
| SYN full 65535 CAM | 73.9s | 56.5s | nmap 1.3× | 1.2× | ~par |
| Connect 1-1000 ROUTER | 46.9s | 44.3s | ~par | — | par |
| SYN -F SERVER | 19.3s | 0.77s | nmap 25× | — | still slow (many closed) |
| SYN -F CAM | 19.4s | 0.30s | nmap 64× | — | still slow (responsive) |
| SYN -F WIN | **1.6s** | 2.1s | **RM faster** | — | firewalled → few open |
| SYN top-1000 SERVER | 17.5s | 1.3s | nmap 13× | — | gap |

The filtered-heavy case (ROUTER 1-1000) went from **35× slower to 1.9× faster** —
the adaptive timeout works. The residual slowness is on hosts with **open**
ports (CAM/SERVER): see the follow-up analysis — it is **auto-script overhead**,
not the SYN engine (WIN, firewalled → few open ports → 1.6s, beats nmap).

**Ports lost?** No. CAM `-p 1-9000` gave the same open set as nmap. **But** RM
with `-p 1-1000` surfaced 1935/8000/9000 (outside the range) — see bug #1.

### A2 — `-sV` version detection — **PASS (huge gain vs v0.80)**
Identical to nmap: SSH *Dropbear sshd 2017.75 (protocol 2.0)*, DNS *dnsmasq 2.73*
(via the new version.bind probe), HTTP *nginx*, SOAP *gSOAP 2.8*, VMware authd
*1.10*. RM **more** detailed on SMB (*dialect 3.0.2*) and MSRPC (*DCE/RPC endpoint
mapper*). Residual gaps (nmap wins): TLS-wrapped (lighttpd on 443), RTSP
(webcam rtspd), rsync (protocol 31).

### A3 — SCTP no longer hangs — **PASS**
v0.80 hung forever; v0.81 terminates in 3–6s with correct `filtered`. Residual:
(1) without `--Pn` → "Host seems down" (SCTP host-discovery weak), (2) prints
`132/tcp` instead of `132/sctp` (label bug), (3) nmap ~10–30× faster.

### A4 — scripts skipped on sweep — **PASS**
`/24` → "[scripts] 19 hosts up — built-in scripts skipped on sweeps";
`--force-scripts` runs them; single host auto-runs (5 findings on SERVER).

### A5 — `-O` auto-loads nmap-os-db — **PASS (excellent)**
"[nmap-os-db] auto-loaded 6108 fingerprints" on every scan. SERVER → *OpenWrt
Chaos Calmer 15.05* (identical to nmap). WIN → *Windows 11 24H2* vs nmap's
*Windows 11|10|2022 (97% GUESSING)* — **RM more precise**. From "server 55%" to
real CPEs.

---

## PART B — head-to-head (highlights)
| Test | RM | nmap | Ratio |
|------|----|------|-------|
| Ping sweep /24 | **3.3s** | 6.5s | **RM 2×** |
| TCP SYN ping | 0.04s | 0.63s | **RM 15×** |
| ARP discovery count | 14 hosts | 18 hosts | nmap finds more (bug #5) |
| UDP top-20 | 25.2s | 16.2s | nmap 1.6× (RM more open\|filtered) |
| FIN/NULL/Xmas | identical | identical | **par** |
| ACK/Window/Maimon | identical | identical | **par** |
| IP-protocol `-sO` SERVER | **~10s** | **295s** | **RM 30×** |
| `-O` SERVER | 22.5s | 3.1s | nmap 7× (same accuracy) |
| `-A` SERVER | **25.3s** | 76.7s | **RM 3×** (less deep) |
| T3 vs T5 `-F` CAM | 16.8 / 19.8s | 0.24s | nmap ~70× (timing templates weak — bug #4) |

Wins: ping/SYN-ping, IP-proto (30×), `-A` (3×), OS precision on Windows, SMB/RPC
detail, and the exclusive features (`--tls-scan` JARM, `--web-scan`, `--recommend`,
`--detect-preview`, PDF/SVG/HTML/MD/JSON output). Losses: `-F` on responsive
hosts, TLS/RTSP/rsync `-sV`, UDP accuracy, SCTP speed/labels, 612 NSE vs 117 Rhai.

---

## Bugs found in v0.81.0
1. **`-p 1-1000` surfaces ports >1000** (1935/8000/9000). *Root cause (verified in
   code): `effective_ports("1-1000")` is exact, so the scan list is 1–1000 — the
   extra ports come from the **auto-run scripts** probing their own ports and
   surfacing findings. Fix = don't auto-run scripts on a bare port scan.*
2. **SCTP label `tcp` not `sctp`** — `132/tcp filtered` should read `132/sctp`.
3. **SCTP host discovery fails without `--Pn`** — "Host seems down" though the host
   answers ARP/ICMP.
4. **Timing templates (`-T0..5`) barely move small scans** — the script overhead +
   timeout floor dominate (same root as #1/A1).
5. **ARP discovery finds fewer hosts** (14 vs 18) — sleeping/mobile devices miss the
   ARP probe window.
6. **`--web-scan` false positives** — `.env`/`backup.zip` flagged on a router that
   returns 200 to everything (needs content validation, not just status code).

---

## Follow-up analysis (Claude) — the central finding

**A1's residual slowness and bug #1 share one root cause: built-in scripts
auto-run on *every* scan, including a bare `--sS`/`-F`.** Evidence:
- `--sS` with no `-sV`/`-sC` still fires all ~117 Rhai scripts against open ports
  (`main.rs` auto-runs them unless `--no-builtin-scripts`, for ≤8 hosts).
- CAM/SERVER (many open ports) → scripts fire → ~19s for `-F`; WIN (firewalled,
  few open) → few scripts → 1.6s (beats nmap). The gap tracks open-port count,
  not the SYN engine.
- nmap `-sS -F` runs **no** scripts (0.3s). So the `-F` comparison is
  apples-to-oranges: RM does scan **+ scripts**, nmap does scan only.
- The "ports >1000 with `-p 1-1000`" (bug #1) is scripts probing their own ports.

**Proposed fix (nmap-aligned): make built-in scripts opt-in, not automatic on a
bare port scan.** Auto-run only when the user asks for depth (`-sV`/`-A`/a new
`-sC`/`--scripts`), or explicitly. Expected effect: `--sS -F` becomes
sub-second and nmap-comparable (closes A1's residual + bug #1 + bug #4), while
`-sV`/`-A` keep today's rich output.

**Confirm before changing:** re-run `rustymap --sS -F --no-builtin-scripts $CAM`
— it should drop from ~19s to sub-second, proving the engine is already fast.

### Triage for the next release
| Bug | Severity | Fix sketch |
|-----|----------|-----------|
| #1 + A1 residual + #4 | HIGH | scripts opt-in on bare scans (not auto) |
| #2 SCTP label | LOW | emit `sctp` proto label for `--sY/--sZ` |
| #3 SCTP discovery | MED | treat SCTP INIT/ABORT + ICMP as host-up; or auto `-Pn` for `--sY` |
| #6 web-scan FP | MED | validate path hits (content/length/content-type), not just 200 |
| #5 ARP count | MED | extra ARP retransmit / longer window on sweeps |
