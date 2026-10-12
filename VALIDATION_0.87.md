# VALIDATION_0.87.md — Script Engine 117→307 (Fase 29)

**Date:** 2026-10-12 · **Version:** v0.87.0 · **Tester:** Kali 6.19 192.168.1.198
**Lab:** ROUTER 192.168.1.1 · SERVER .31 · CAM .226 · NET /24

> **v0.87.1 resolution note (assistant):** all 5 bugs below fixed in v0.87.1 —
> BUG-2 soft-404 guard in the HTTP-detect scripts, BUG-5 banner scripts now
> check banner+product+version, BUG-3 ambiguous port-only scripts now require a
> service marker, BUG-1 catalog export honours --script-category/--script-tag,
> BUG-4 rtsp trigger. See CHANGELOG [0.87.1].

## Esiti (18 PASS / 5 FAIL su 23 = 78%)
- **S0 Smoke 3/3** — catalog "307 scripts exported", --script-help lists, categories correct.
- **S1 Catalog filter 1/4** — **BUG-1**: `--script-category`/`--script-tag` don't filter the FILE export (all 307 dumped); stdout print does filter. `.md`/`.json` export OK otherwise.
- **S2 Execution 6/6** — triage auto-run, raw-scan skip, --force-scripts, sweep skip (>8 hosts), --no-builtin-scripts all correct.
- **S3 Accuracy 2/3** — legit findings correct (dns-zone-transfer, smb-exposed, rsync-exposed, http-missing-security-headers); FP on catch-all + 2 misses (rtsp, ssh-dropbear).
- **S4 False-positives 1/2** — **BUG-2**: HTTP marker scripts fire on catch-all 200 pages (7 FP on router :8080); **BUG-3**: port-only scripts assert on shared ports (clickhouse/vmware/exposed-management on camera :9000/:8443).
- **S5 Performance 2/2** — 34.5s single host (--force-scripts), 54s sweep (skipped), sub-second --no-builtin-scripts.
- **S6 Regression v0.86.1 3/3** — `--sS -p 1-1000` footer "1000 port-probes", `--cms-detect` http://, `--iot-discover` CIDR exit 3 — all hold.

## Bug → fix v0.87.1
| ID | Sev | Summary | Fix |
|----|-----|---------|-----|
| BUG-2 | HIGH | HTTP marker scripts FP on catch-all 200 (no soft-404) | inline soft-404 baseline in the regenerated http-detect scripts: skip when a random path also 200s with the same marker / empty marker |
| BUG-3 | MED | port-only scripts assert shared ports (clickhouse :9000, vmware :8443, exposed-management) on cameras | require a service.product/banner marker before asserting; else silent |
| BUG-1 | LOW | catalog FILE export ignores category/tag filter | apply CatalogFilter before export (json+md) |
| BUG-5 | LOW | banner scripts miss when -sV stored string in product/version not banner (Dropbear) | banner scripts check banner+product+version combined |
| BUG-4 | LOW | rtsp-* didn't fire on camera :554 | widen rtsp trigger / fix OPTIONS probe |

## Works well
Script lifecycle (triage/sweep/force/disable) solid; perf good; catalog export clean; 307 enumerate; no v0.86.1 regressions; legit findings accurate.
