# Lab validation matrix

Fase 24 (v0.66.0) introduced explicit feature tiers — see `src/maturity.rs`
and `--guide` (MATURITY MATRIX section).

This file tracks the **actual lab work** that promotes features between
tiers. A feature is only promoted from Beta → Production after a
documented run against a real target with the result compared to a
reference tool.

## Tier ladder

| Tier | Meaning |
|---|---|
| Production | Validated in lab against a reference (nmap / hydra / sslscan / etc.). Trust the output unless explicitly disclaimed. |
| Beta | Passes synthetic tests, likely correct, **not yet validated against real targets**. Spot-check before reporting findings to a stakeholder. |
| Alpha | Known limitations OR freshly landed (<2 weeks). Requires `--experimental-confirm` flag. Treat positive results as hints, not evidence. |

## Promotion procedure

To promote a feature from one tier to the next:

1. Run RustyMap against ≥1 real lab target with the feature enabled
2. Run the reference tool against the same target with equivalent options
3. Compare outputs — flag every divergence
4. Either: fix the divergence and retest, OR document it in the feature's
   `note` field (`src/maturity.rs`) and promote anyway if the divergence
   is acceptable
5. Add a row in the table below with date + result
6. Edit `src/maturity.rs` to bump the tier

## Validation log

| Date | Feature | Lab target | Reference | Result | Notes | Promoted? |
|---|---|---|---|---|---|---|
| _yyyy-mm-dd_ | _e.g. `--brute-protocol ssh`_ | _e.g. ubuntu-22 sshd on 10.0.0.5_ | _hydra ssh://_ | _e.g. ✓ same 3/5 hits_ | _free-form_ | _Beta → Prod_ |
| 2026-05-22 | `[KEV]` badge | OpenSSH banner (`--cve-for "OpenSSH 7.4p1"`) | live CISA KEV feed | ✓ pipeline correct — badge absent is right | **Not a bug.** CVE-2024-6387 (regreSSHion) is NOT in CISA KEV (verified: 1721 entries, zero OpenSSH). No confirmed in-the-wild exploitation → never entered KEV. v0.67.3–0.67.5 chased a badge that was correctly absent. | n/a |
| 2026-10-05 | `-O` OPS/WIN/T1 + SEQ band (v0.79.0) | 127.0.0.1 (Kali 6.19), 10.0.2.2 (VBox Slirp) | `nmap -O -d` 7.99 | ✓ OPS O1-O6/WIN W1-W6/T2-T7/ECN/U1/IE byte-identical; SP/ISR/TS point inside band & band overlaps nmap | Full report: `VALIDATION_0.79.md`. B26 confirmed (gateway TI=RD,CI=RI,II=RI). **B27 found:** T1 line carries redundant W=/O= nmap omits — display-only, scoring safe. | Beta → Prod |
| 2026-10-05 | `--nmap-os-db` match (v0.79.0) | 127.0.0.1, 10.0.2.2 | `nmap -O` | ✓ localhost→Linux 90% (was wrongly "Adtran 95%" pre-B25); gateway→AT&T BGW210 top-1 like nmap, Slirp/QEMU in runner-ups | OPS/WIN/T1 fields + B25 denominator fix pay off. % slightly below nmap (expected, conservative). | Beta → Prod |
| 2026-10-05 | JARM + cert flags (v0.79.0) | cloudflare/google/microsoft/apache, badssl | pyjarm 0.0.5, openssl | ✓ JARM 4/4 byte-identical; self-signed + expired flags correct | B21 stays resolved. | Prod (holds) |
| 2026-10-08 | v0.81.0 six fixes | home /24 (ROUTER/OpenWrt AP/Reolink cam/Win11/printer) | nmap 7.99 + hyperfine | A2 -sV PASS (SSH/DNS/gSOAP/SMB/RPC/VMware identical); A3 SCTP PASS (no more infinite hang); A4 sweep-skip PASS; A5 -O auto-load 6108 fp PASS (Win11 more precise than nmap); A1 PARTIAL | Full report: `VALIDATION_0.81.md`. **Key finding:** A1 residual slowness + bug#1 (ports>1000 on -p 1-1000) share one root — built-in scripts auto-run on bare `--sS`/`-F` (CAM/SERVER many open → ~19s; WIN firewalled → 1.6s beats nmap). Engine is fast; scripts are the overhead. | -sV/SCTP/sweep/-O → Prod; SYN perf → still Beta |
| 2026-10-08 | New bugs (v0.81.0) | same lab | nmap 7.99 | Found 6: #1 scripts surface out-of-range ports, #2 SCTP label tcp≠sctp, #3 SCTP discovery needs --Pn, #4 timing templates weak on small scans, #5 ARP finds 14 vs 18, #6 web-scan FP on always-200 router | Triage in `VALIDATION_0.81.md`; proposed fix: make built-in scripts opt-in on bare scans (closes #1+#4+A1 residual). | n/a |
| 2026-10-09 | v0.82.0 six items | home /24 | nmap 7.99 + hyperfine | **HEADLINE: script opt-in transformed raw speed** — SYN -F 64×-slower→1.6-4.7×-FASTER, timing templates 71-80×-slower→1.1-1.6×-faster, connect -F 24×-slower→8.8×-faster, IP-proto 213×, ping 5.4×. A2/A3 PASS (/sctp label, SCTP -Pn), A4 ARP improved (reaches nmap by round 3). -sV SSH/DNS/gSOAP/SMB/RPC identical. A5 web + A6 MSF PARTIAL. | Full report: `VALIDATION_0.82.md`. RustyMap now competitive-to-faster than nmap on most scan types; nmap still wins -sV-depth/-O-speed. | raw scans → Prod |
| 2026-10-09 | v0.82.1 residual fixes | (code; needs re-run) | nmap 7.99 | Fixed the 3 residuals: #1 -p 1-1000 now sequential not top-1000-by-freq (--ports → Option<String>); #2 web-scan catch-all FP suppressed (marker hit needs body≠soft-404-baseline); #3 --msf-suggest module.search now parses msfrpcd's bare array (was 0 modules). 596/596 tests. | Re-run on Kali: -p 1-1000 exact range, web-scan no .env FP on router, --msf-suggest finds EternalBlue for CVE-2017-0144. | n/a |
| 2026-10-10 | v0.82.1 full re-validation | Kali 192.168.1.79, home /24 | nmap/sslscan/openssl/hydra/msfconsole | **3/3 A-fixes PASS.** Never-tested sweep N1–N13: evasion 6/7 identical to nmap, ssh-audit superior (auto weakness analysis), vuln checks (CCS/shellshock/webdav/known-keys) clear+correct, MSF suggest+fire OK, XML/JSON valid, QUIC v1 OK, brute gated+rate-limited, diff/history OK. | Full report: `VALIDATION_0.82.1.md`. Found 3 code bugs → all fixed in v0.83.0: N8 msf-import imported nothing, N6 ssl-enum ECDHE-only, smb-audit "bogus length 1" on firewall RST. N2 IPv6-raw + N5 broadcast = environment. | most areas → Prod |
| 2026-10-10 | v0.83.0 Fase 28 + 3 lab fixes | (code; needs re-run) | — | Exit-code discipline 0/1/2/3/130 (smoke-tested: config→3, clean→0, clap→3); `--color`+CI/TTY auto-detect (verified pipe strips ANSI, --color forces); curated `--profile` presets (homelab-discover/compliance-pci/… load); -vvv→debug bridge. Fixed N8 (import post-scan), N6 (ssl-enum per-version union), smb-audit verdict. 603/603 tests. | Re-run on Kali: msf-import e2e vs live msfrpcd (hosts/services/vulns land), ssl-enum lists DHE/RSA on router, smb-audit clear verdict, findings→exit 1 on a CVE/TLS target. | pending Kali |

## Targets in current lab

_Fill in once you've confirmed which targets are available. This list
becomes the "happy path" matrix for ongoing regression testing._

| Target | OS / version | Services exposed | Used for validating |
|---|---|---|---|
| 10.0.0.x | _e.g. Win Server 2019_ | _RDP, SMB, MSSQL_ | _RDP/MSSQL/SMB brute_ |

## Open validation tasks

Roughly grouped by feature. Tackle the high-uncertainty items first
(MSSQL TDS / RDP CredSSP), because those are where a real lab run is
most likely to reveal bugs the synthetic tests didn't.

### Brute adapters
- [ ] `--brute-protocol ssh` vs `hydra ssh://` — Linux sshd + Dropbear if available
- [ ] `--brute-protocol smb` vs `crackmapexec smb` — Windows + Samba
- [ ] `--brute-protocol mysql` vs `hydra mysql://` — MySQL 5.7 + 8.x + MariaDB
- [ ] `--brute-protocol postgres` vs `hydra postgres://` — verify SCRAM path is unsupported (intentional)
- [ ] `--brute-protocol ldap` vs `ldapsearch` — OpenLDAP + AD
- [ ] `--brute-protocol vnc` vs `hydra vnc://` — TightVNC / RealVNC / TigerVNC
- [ ] `--brute-protocol mssql` vs `hydra mssql://` — SQL Server 2019/2022
- [ ] `--brute-protocol rdp` vs `hydra rdp://` — Windows Server 2019/2022; verify pubKeyAuth omission consequences

### Scan accuracy
- [ ] `-O` vs `nmap -O` on 8-10 hosts (Linux, Win, BSD, router, printer)
- [ ] `-sV` vs `nmap -sV` on a representative service mix
- [ ] `--tls-grade` vs `testssl.sh` on 5 endpoints (real-world TLS configs)

### Vuln intel
- [ ] `--cve-for` — manually verify 20 matches across CPE styles
  (`openssh 7.4p1`, `nginx:1.18.0`, `apache 2.4.59-1ubuntu1`, etc.)
  → flag false positives + false negatives
- [x] `[KEV]` badge — **validate only against a CVE that is actually in
  CISA KEV.** Anchor: `CVE-2021-44228` (Log4Shell, permanent entry).
  Do NOT use CVE-2024-6387/regreSSHion or any OpenSSH CVE — none are in
  KEV. Use `--inspect-exploit-cache <CVE>`: if the Log4Shell anchor
  shows `kev:true` and your CVE doesn't, the pipeline is healthy and
  your CVE just isn't KEV-listed.

### Specialized
- [ ] `--ics-scan` against a real PLC (vs Conpot synthetic baseline)
- [ ] `--apk-scan` / `--ipa-scan` on real apps with known secret leaks
- [ ] `--threat-intel-sync` against a public MISP feed end-to-end

## Conventions

- **Don't** promote a feature based on "all our tests pass". Tests pass
  on synthetic inputs by construction. Promotion requires *one observed
  agreement with the reference tool against a real target*.
- **Do** keep this file even if entries are empty — its existence is the
  hardening commitment.
- Demotion is allowed: if a lab run shows divergence and we can't fix
  it before the next release, move the tier back down + update the note.
