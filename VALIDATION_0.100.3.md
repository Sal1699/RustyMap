# RustyMap v0.100.3 — Validation (Part A: pentest-ground.com, Part B: brute)

**Date:** 2026-10-24
**Tester:** Kali 192.168.1.198
**Build:** `rustymap 0.100.3` (commit adfc58e)
**Reference tools:** nmap 7.99, sslscan, hydra 9.6, crackmapexec

Plan: `PENTEST_GROUND_PLAN.md`. Part A = authorized remote playground
(pentest-ground.com, 178.79.134.182). Part B = Metasploitable 2
(`tleemcjr/metasploitable2` @ 172.17.0.2) + LDAP (osixia/openldap @ 127.0.0.1:389).

---

## Part A — pentest-ground.com

| Test | Result | Detail |
|------|--------|--------|
| A0 recon `-p- -sV` | **PASS** | 6/6 documented ports match nmap + 3 bonus (80, 443, **4445 = OpenSSH 8.4p1**). 65535 probes in 1689s (39 p/s, heavy remote filtering). |
| A1a WebLogic CVE | **PASS** | `--cve-for "WebLogic 14.1.1"` → 25 CVEs incl. **CVE-2023-21839** (KEV) + Console RCE chain. |
| A1b Redis CVE | **PASS** | `--cve-for "Redis 5.0.7"` → 25 CVEs incl. **CVE-2022-0543** (CRITICAL 10.0, KEV); inline correlator also flagged it during `-sV`. |
| A2a `--web-scan` | **PASS** | all 4 HTTP ports graded F (missing HSTS/CSP/XFO/…); no FP. Production reconfirmed. |
| A2b `--owasp-scan` | **N/A → fixed** | tester invoked `--owasp-probes` (doesn't exist). Real flag is **`--owasp-scan URL`**; maturity matrix mislabelled it → renamed in v0.100.4. |
| A2c `--web-crawl` | Alpha stays Alpha | can't handle DVWA cookie/CSRF login flow (0 pages). Expected for Alpha. |
| A4 `-A` aggressive | **PASS** | OS=Linux 5.X (100%), 20-hop traceroute, 6/6 services, script findings correct, **0 FP across 607 Rhai scripts**. |

**Part A gaps filed:** (1) `--owasp-probes`→`--owasp-scan` naming (fixed v0.100.4);
(2) `--web-crawl` no session/cookie handling (Alpha); (3) `--ssh-audit` only probes
:22, not a given non-standard port like 4445 (feature gap); (4) `--sV` doesn't
prepend `ssl/` for TLS-wrapped services (cosmetic vs nmap); (5) `http-form` (A3)
deferred — DVWA login.php CSRF token.

**Bonus:** OpenSSH 8.4p1 on `:4445` — a *modern* SSH server, ideal for the
definitive ssh-brute / ssh-audit test the Metasploitable box couldn't provide.

---

## Part B — Metasploitable 2 (brute adapters)

Services (nmap -sV): ftp vsftpd 2.3.4, ssh OpenSSH 4.7p1, telnet, smb Samba 3.x,
mysql 5.0.51a, postgres 8.3, vnc RFB 3.3.

| Adapter | RustyMap | hydra | Agreement | Promotion |
|---------|----------|-------|-----------|-----------|
| **ftp** | HIT `msfadmin:msfadmin` (single + needle) | HIT | **YES** | **Beta → Production** |
| **ssh** | 0 (KEX fail) | 0 (KEX fail) | YES (both fail) | Stays Beta — target too old |
| **smb** | 0 | HIT (SMBv1) | NO | Stays Beta — no SMBv1 fallback |
| **mysql** | 0 (`root:` empty) | HIT `root:` | NO | Stays Beta — empty-pass bug |
| **postgres** | HIT `postgres:postgres` | HIT | **YES** | **Beta → Production** |
| **vnc** | 0 | HIT `password` | NO | Stays Beta — RFB 3.3 DES |
| **ldap** | HIT `cn=admin,dc=example,dc=org:admin` | HIT (ldap3://) | **YES** | **Beta → Production** |

**Bugs filed:**
- BRUTE-1 (smb): no SMBv1 negotiate fallback — only SMB 3.1.1 (Win11). Old Samba 3.0.20 needs SMBv1 NTLM. *(deferred — larger change)*
- BRUTE-2 (mysql): empty password (`root:`) sent a 20-byte zero scramble instead of a zero-length response. **Fixed v0.100.4.**
- BRUTE-3 (vnc): RFB 3.3 security negotiation read as 3.7-style count+list. **Fixed v0.100.4.**
- BRUTE-4 (ssh): legacy KEX with OpenSSH 4.7p1 fails (so does hydra + system ssh) — low priority; re-test vs a modern server.

---

## Follow-up — v0.100.4 (2026-10-24)

- **Promoted to Production:** `--brute-protocol ftp`, `postgres`, `ldap`
  (hydra agreement, single-cred + needle-in-haystack).
- **Fixed:** BRUTE-2 (mysql empty-password → auth-data-length 0) and BRUTE-3
  (vnc RFB 3.3 handshake branch). Both **stay Beta pending a Kali re-test** —
  the adapters touch a live server the dev box can't reach.
- **Fixed:** `--owasp-probes` → `--owasp-scan` naming across the maturity
  registry, the Alpha gate call, and the roadmap docs (the feature existed; the
  matrix/docs named a flag that doesn't).
- **Deferred/filed:** BRUTE-1 (smb SMBv1), BRUTE-4 (ssh legacy KEX), `--ssh-audit`
  non-standard port, `ssl/` service-name prefix.

**NEEDS KALI (v0.100.4):** re-run mysql (`--brute-pair 'root:'` on MSF2) and vnc
(`--brute-passlist` = `password` on MSF2 RFB 3.3) vs hydra → promote on
agreement. Test ssh-brute + `--ssh-audit` against pentest-ground.com:4445.
