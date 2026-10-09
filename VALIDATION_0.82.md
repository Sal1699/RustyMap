# RustyMap v0.82.0 — Lab Validation Report

**Date:** 2026-10-09 · **Tester:** Kali 192.168.1.79 · **Tool:** hyperfine + manual
**Lab:** home /24. ROUTER 192.168.1.1 (TIM/Vantiva), SERVER .31 (OpenWrt AP),
CAM .34 (Reolink), WIN .64 (Win 11), LINUX .148 (printer).

## Headline — the script opt-in transformed raw-scan speed
`--sS -F` went from **64× SLOWER to 1.6–4.7× FASTER** than nmap; timing
templates from **71–80× slower to 1.1–1.6× faster**. RustyMap is now
competitive-to-faster than nmap on most scan types.

| Test | v0.82 RM | nmap | Ratio | v0.81 was | Δ |
|------|----------|------|-------|-----------|---|
| SYN -F CAM | 136 ms | 222 ms | **RM 1.6×** | nmap 64× | ~102× better |
| SYN -F SERVER | 183 ms | 747 ms | **RM 4.1×** | nmap 25× | ~102× better |
| SYN 1-1000 ROUTER | 1.4 s | 42.8 s | **RM 30×** | RM 1.9× | 15× better |
| Connect -F SERVER | 131 ms | 1.15 s | **RM 8.8×** | nmap 24× | ~211× better |
| Ping sweep /24 | 3.5 s | 18.8 s | **RM 5.4×** | RM 2× | 2.7× |
| Full 65535 CAM | 9.2 s | 14.7 s | **RM 1.6×** | nmap 1.3× | 2.1× |
| IP-proto -sO | 1.6 s | 335 s | **RM 213×** | RM 30× | 7× |
| -A SERVER | 22.9 s | 76.9 s | **RM 3.4×** | RM 3× | ~par |
| Timing T3 -F | 148 ms | 216 ms | **RM 1.5×** | nmap 71× | ~107× better |
| -sV -F | 19.8 s | 14.5 s | nmap 1.4× | nmap 1.4× | par |
| -O | 20.3 s | 2.2 s | nmap 9× | nmap 7× | ~same |
| SCTP -sY | 3.0 s | 0.65 s | nmap 4.6× | ∞ (hung) | fix works |

## Fix verdicts
- **A1 script opt-in — PASS** (headline). `--sS -F`→0 findings, default/`-sV`/`--force-scripts`→findings. The one big win of the release.
- **A2 SCTP `/sctp` label — PASS.**
- **A3 SCTP implies -Pn — PASS** ("[i] SctpInit scan implies -Pn", scans instead of "Host down").
- **A4 ARP — IMPROVED** (14→14-18 variable; reaches nmap by round 3; retransmit covers sleeping devices).
- **A5 web-scan — PARTIAL** (catch-all note + CORS work; `.env*`/`config.json` still flagged).
- **A6 --msf-suggest — PARTIAL** (connect/auth/integration OK; `module.search` returns 0 modules).
- Scan types FIN/NULL/Xmas/ACK/Window/Maimon all identical to nmap. -sV SSH/DNS/gSOAP/SMB/RPC identical.

## Residual bugs + ROOT CAUSES (Claude, verified in code) → fixed in v0.82.1
1. **`-p 1-1000` scans top-1000-by-frequency (incl. 1935/8000/9000), not sequential 1-1000.**
   Root cause: `--ports` default is the string `"1-1000"`, and
   `p_was_set_explicitly = args.ports != "1-1000"` — so an explicit `-p 1-1000`
   is indistinguishable from the default and falls into the top-1000-by-freq
   branch. NOT "adds top-ports" and NOT scripts (those are off on raw scans
   now). **Fix:** make `--ports` an `Option<String>`; explicit = `is_some()`.
2. **web-scan still flags `.env`/`config.json` on a catch-all server.**
   Root cause: the soft-404 suppression only covers *marker-less* paths; `.env`
   (marker `=`) and `config.json` (marker `{`) match the catch-all HTML page
   (which contains `=`/`{`). **Fix:** on `catch_all`, also suppress a marker hit
   whose body length ≈ the soft-404 baseline (same page).
3. **`--msf-suggest` / `--msf-suggest-cve` find 0 modules even for EternalBlue.**
   Root cause: msfrpcd `module.search` returns a bare **array** of module
   hashes, but `parse_search_result` calls `resp.as_map()` then looks for a
   `"modules"` key → `as_map()` is `None` → empty. **Fix:** parse a top-level
   array first, keep the `{"modules":[...]}` path as a fallback.

## Known gaps (deferred, not v0.82.1)
- `-sV` on TLS-wrapped services (lighttpd on 443 → name-only) — needs HTTP-over-TLS probe.
- Raw SYN throughput vs nmap on the very most responsive hosts (engine, not timeout).
- `-O` ~9× slower than nmap (fingerprint collection latency).
