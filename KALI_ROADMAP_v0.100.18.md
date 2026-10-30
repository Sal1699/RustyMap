# RustyMap — Roadmap from v0.100.18 (2026-10-30)

Starting point: **v0.100.18**. What's done, what's next, in priority order.
The network brute set + ICS/APK scanning are Production; what remains is
validating the two freshly-shipped code paths and deciding which of the
**9 Alpha** features earn a promotion. **v1.0 is NOT in scope** (your standing
decision — no feature-freeze, no v1.0 tag until you say so).

Companions: `KALI_ALPHA_SWEEP.md` (per-Alpha recipes + sweep results),
`HYDRA_PARITY.md` (brute matrix), `LAB_VALIDATION.md` (dated run log),
`CHANGELOG.md`. This file supersedes `KALI_TEST_ROADMAP.md` as the current plan.

## Progress since v0.100.18 (2026-10-30 Kali report)

- **1A mssql** re-test: TLS handshake completed but the LOGIN7 reply failed
  ("connection error"). Root cause: `ENCRYPTION=OFF` negotiates *login-only*
  encryption, so the reply came back in cleartext and the TLS read rejected it.
  **Fixed in v0.100.19** (advertise `ENCRYPTION=ON` + defensive reply read).
- **1B owasp auth fix** CONFIRMED (cookie reaches crawler + probes, 24pg/35ep).
- **3A owasp** (CMDi probe + GET form-params fix + 9 SQL fingerprints + SSRF FP
  trim) **shipped in v0.101.0** — your R&D showed 6 findings / 0 FP on DVWA.
- **2B `--sI`** scored **9/9 vs nmap** on a real zombie — meets the promote bar;
  promotion pending your OK (you noted "possibile con più target").
- **2A rdp** SKIP (xrdp ≠ Windows CredSSP/NLA — needs a real Windows host);
  **2C misp** SKIP (no instance). **3B/3C** still to implement (you reverted them).

## Where we are (v0.101.0)

- **Production:** all scan types; `-O` / `--sV` / `--tls-grade` / `--cve-for` /
  `--ssh-audit` / `--smb-audit` detection; **7/7 network brute**
  (ftp/ssh/smb/mysql/postgres/ldap/vnc); **`--ics-scan`**, **`--apk-scan`**.
- **0 Beta.**
- **9 Alpha:** brute `rdp`, brute `mssql`, `--ipa-scan`, `--owasp-scan`,
  `--web-crawl`, `--os-fp-v6`, `--sI`, `--threat-intel-misp`, `--osdb-submit`.
- **679/679 tests.**

## Prep (every session)

```sh
cd ~/RustyMap && git fetch origin --tags && git pull origin main   # expect v0.101.0
cargo build --release ; RM=./target/release/rustymap
$RM --version                     # rustymap 0.101.0
cargo test 2>&1 | tail -1         # 683 passed (684 on Linux — one extra platform test)
```
Raw scans / `--fast-engine` / `-O` / `--sI` / `--os-fp-v6` need `sudo`.
**All Alpha features need `--experimental-confirm`.** Record a dated row in
`LAB_VALIDATION.md` and paste me each run's output.

---

## Phase 1 — Validate the fresh code paths (no new code; just run + paste)

Both have code already shipped; they're waiting only on a Kali run.

### 1A 🟢 mssql TDS-over-TLS — the promotion candidate
v0.100.18 added the encrypted login (PRELOGIN `ENCRYPTION=OFF` → TLS handshake
tunneled in TDS `0x12` packets → LOGIN7 as TLS application data). This closes the
v0.100.17 MISS, where the cleartext login was rejected by SQL Server 2022.

```sh
docker run -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=Str0ng!Pass' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022
$RM --brute-protocol mssql --brute-target 127.0.0.1:1433 --brute-pair 'sa:Str0ng!Pass' --experimental-confirm --brute-confirm-authorized
# wrong-cred control + reference:
$RM --brute-protocol mssql --brute-target 127.0.0.1:1433 --brute-pair 'sa:WrongPass!' --experimental-confirm --brute-confirm-authorized
hydra -l sa -p 'Str0ng!Pass' mssql://127.0.0.1
```
**Pass → PROMOTE (8th brute at Production):** correct cred HIT = hydra, wrong cred
rejected. **If it still misses:** re-run with `RUSTYMAP_MSSQL_DEBUG=1` and paste the
trace (it prints the negotiated encryption byte + login-response head) — I decode
and fix. First run of hand-rolled TDS-over-TLS, so the debug trace is there on
purpose (SMB lesson: instrument, don't guess).

### 1B 🔴 owasp-scan re-run on DVWA — confirm the v0.100.17 auth fix
v0.100.17 fixed the probe engine running unauthenticated (it now carries the
session cookie, and a multi-cookie `--web-cookie` keeps `security=low`).

```sh
# DVWA (Metasploitable 2 or a DVWA container), logged in, security=low:
$RM --owasp-scan 'http://<dvwa>/vulnerabilities/' --web-cookie 'PHPSESSID=<id>; security=low' --owasp-checks xss,sqli --experimental-confirm
```
**Pass:** XSS + SQLi findings now appear (0 before the fix). Reference:
`zap-baseline.py`. **Stays Alpha regardless** — no command-injection probe, no JS
rendering (see 3A). This run just confirms the fix landed; report the finding count.

---

## Phase 2 — Validate when you have the target (no new code)

Run these if/when the target exists; all three most likely **stay Alpha**, but a
clean run confirms the mechanics. Full recipes in `KALI_ALPHA_SWEEP.md`.

- **2A — `--brute-protocol rdp`** (needs a Windows RDP host, e.g. a Win Pro `.64`).
  Negatives (NTSTATUS) are reliable; positives are suggestive until pubKeyAuth
  lands (3D). Report a known-good + a known-bad vs `hydra rdp://`.
- **2B — `--sI` idle scan** (needs a predictable-IPID zombie — old printer/IoT).
  `nmap --script ipidseq <cidr>` to find one; then `$RM --sI <zombie> <target>` vs
  `nmap -sI`. Rare on modern OSes; validate only if you find a zombie.
- **2C — `--threat-intel-misp`** (needs a lab MISP instance + API key). Confirm it
  pulls IoCs and flags matches as findings.

---

## Phase 3 — Alpha → Production code work (I build; pick by the capability you want)

Ordered by value/effort. Each is a code change I make, then you validate on Kali.
Say the word (e.g. "vai owasp-cmdi") and I ship it as a `0.100.x` patch.

- **3A — `--owasp-scan`: command-injection probe + FP tuning.** Add a CMDi check
  (time-based `;sleep` / marker echo) so DVWA's third vuln class is covered, and
  tighten XSS/SQLi detection to cut false positives vs ZAP. Biggest usefulness gain.
- **3B — `--os-fp-v6`: expand the IPv6 signature DB.** Today it's thin (the sweep
  host read "legacy/embedded 70%", nmap matched nothing either). Add Windows/Linux/
  BSD v6 signatures so it can match a real OS family. Needs a few known v6 hosts to
  validate.
- **3C — `--ipa-scan`: mach-O + entitlements parsing.** Today only `Info.plist` is
  read. Parse the mach-O header + embedded provisioning profile/entitlements to
  catch get-task-allow, missing hardened-runtime, etc. Then it can promote.
- **3D — `--brute-protocol rdp`: CredSSP pubKeyAuth.** Implement the RC4-of-SPKI
  step under the NTLM session key so a positive is authoritative (not just
  suggestive). Makes rdp promotable.

Likely **stay Alpha by design** (no code will change that): `--web-crawl` (no JS,
inferior to ZAP), `--sI` (zombie scarcity), `--threat-intel-misp` (needs infra),
`--osdb-submit` (privacy-sensitive output — review before sharing).

---

## Phase 4 — Optional new features / hardening (by use case)

Suggest-driven — tell me the use case and I'll scope it:

- **mssql TDS 8.0 strict encryption** — for servers configured `Encrypt=Strict`
  (standard TLS-on-connect, no PRELOGIN-in-cleartext dance). The v0.100.18 path
  covers the default (classic) mode; strict mode is a separate handshake.
- **`--web-crawl` cookie/CSRF robustness** — hold anti-CSRF tokens across POSTs.
- **More `--web-scan` / `--owasp-scan` coverage** — paths, headers, auth flows.
- **caching_sha2_password for mysql brute**, **SCRAM for postgres brute** — the two
  documented "modern-auth" gaps in otherwise-Production adapters.

---

## Not on this roadmap (deferred by your decision)

- **v1.0 cut / feature-freeze / `v1.0.0` tag** — needs your explicit go-ahead.
- **fast engine as default** — stays opt-in (`--fast-engine`); not re-proposed.

## How we work

I ship a release → you run it on Kali against the reference tool
(nmap / hydra / crackmapexec / sslscan / ZAP) → paste the output → I harden and
propose the tier flip per feature. **One real-target agreement with the reference =
promote; divergence = fix or stay Alpha.** Every bug → a `0.100.x` patch, re-run
that row.

## Tracking

| Item | Status | Next action |
|------|--------|-------------|
| 1A mssql TDS-over-TLS | bug found v0.100.18, **fixed v0.100.19** | re-test vs hydra → promote (8th brute) |
| 1B owasp-scan auth fix | **confirmed** (24pg/35ep) | folded into 3A |
| 2A rdp | Alpha — **SKIP** (xrdp ≠ CredSSP) | needs a real Windows RDP host |
| 2B sI | Alpha — **9/9 vs nmap** on a zombie | promote on your OK ("più target"?) |
| 2C threat-intel-misp | Alpha — SKIP | validate with a lab MISP |
| 3A owasp CMDi + params | **shipped v0.101.0** | re-run DVWA → confirm 6 findings / 0 FP |
| 3B os-fp-v6 DB | not started | re-implementing next → v0.102.0 |
| 3C ipa mach-O | not started | re-implementing after 3B |
| 3D rdp pubKeyAuth | not started | say "vai" to build (needs Windows host to test) |
