# RustyMap — Remaining-tests roadmap (from v0.101.3)

The brute set is done (8/8 bar rdp), `--sI`/`--ics-scan`/`--apk-scan` are
Production. What's left is **7 Alpha features**. This file is the plan for
validating/closing each one, grouped by *what you need to run the test*:
nothing, a specific target, or a code change from me first.

Supersedes `KALI_ROADMAP_v0.100.18.md`. Companions: `KALI_ALPHA_SWEEP.md`
(per-feature recipes + sweep history), `HYDRA_PARITY.md`, `LAB_VALIDATION.md`
(dated run log), `CHANGELOG.md`.

## Where we are (v0.101.3)

- **Production:** all scan types incl. `--sI`; `-O` / `--sV` / `--tls-grade` /
  `--cve-for` / `--ssh-audit` / `--smb-audit`; **8 network brute**
  (ftp/ssh/smb/mysql/postgres/ldap/vnc/mssql); `--ics-scan`, `--apk-scan`.
- **0 Beta.**
- **7 Alpha:** brute `rdp`, `--owasp-scan`, `--ipa-scan`, `--os-fp-v6`,
  `--threat-intel-misp`, `--web-crawl`, `--osdb-submit`.
- **684/684 tests** (685 on Linux). **v1.0 NOT in scope** (your standing call).

## Prep (every session)

```sh
cd ~/RustyMap && git fetch origin --tags && git pull origin main   # expect v0.101.3
cargo build --release ; RM=./target/release/rustymap
$RM --version                     # rustymap 0.101.3
cargo test 2>&1 | tail -1         # 684 passed (685 on Linux)
```
**All Alpha features need `--experimental-confirm`.** Raw scans / `-O` /
`--os-fp-v6` need `sudo`. Record a dated row in `LAB_VALIDATION.md` and paste me
each run's output — I harden + flip the tier per feature.

---

## Group 1 — run now (no new code, no special target)

### 1A 🟢 `--owasp-scan` on DVWA — confirm the 3A findings
v0.101.0 added the CMDi probe + the GET form-params fix; your R&D showed 6
findings / 0 FP. This run confirms the shipped code reproduces it.
```sh
# DVWA (Metasploitable 2 or a DVWA container), logged in, security=low:
$RM --owasp-scan 'http://<dvwa>/vulnerabilities/' \
    --web-cookie 'PHPSESSID=<id>; security=low' \
    --owasp-checks xss,sqli,cmdi --experimental-confirm
```
**Expect:** ~6 findings (XSS + SQLi + CMDi), 0 FP. Reference: `zap-baseline.py`.
**Stays Alpha regardless** — no JavaScript rendering, noisier than ZAP/sqlmap.
Report the finding + FP counts; this *closes the 3A validation*, it doesn't promote.

### 1B 🔴 `--osdb-submit` — verify the pack (stays Alpha by design)
```sh
sudo $RM -O --osdb-submit <host>:MyLabel --osdb-submit-out /tmp/pack.txt --experimental-confirm
cat /tmp/pack.txt
```
**Check:** the pack describes the fingerprint correctly (TTL, CPE, confidence).
It does NOT auto-submit anywhere. **Stays Alpha by design** (privacy-sensitive
output — you review before sharing). Just confirming it works.

### 1C 🔴 `--web-crawl` — re-confirm scope + session (stays Alpha by design)
Already validated (24pg/35ep, session held). Optional re-confirm:
```sh
$RM --web-crawl 'http://<dvwa>/' --web-cookie 'PHPSESSID=<id>' --experimental-confirm
```
**Stays Alpha by design** — no JS, slower than ZAP. No promotion path.

---

## Group 2 — run when you have the target (no new code)

### 2A 🟡 `--brute-protocol rdp` — needs a real Windows RDP host
```sh
$RM --brute-protocol rdp --brute-target <win>:3389 --brute-pair 'Administrator:wrongpass' --experimental-confirm --brute-confirm-authorized
$RM --brute-protocol rdp --brute-target <win>:3389 --brute-pair 'Administrator:<known-good>' --experimental-confirm --brute-confirm-authorized
hydra -l Administrator -p wrongpass rdp://<win>    # reference
```
**Known gap:** CredSSP pubKeyAuth NOT implemented → **negatives (NTSTATUS) are
reliable, positives are suggestive**. Report both a known-bad and a known-good vs
hydra. Full promotion waits on **3C below (pubKeyAuth)** — but a clean run now
tells us the NTSTATUS mapping is right. (xrdp on Linux won't work — it doesn't
speak Windows CredSSP/NLA; needs a real Windows box.)

### 2B 🔴 `--threat-intel-misp` — needs a lab MISP instance + API key
```sh
# e.g. coolacid/misp-docker, then an API key from the MISP UI:
$RM --threat-intel-misp https://<misp>/ --misp-api-key <KEY> --threat-intel-match --experimental-confirm <scan args>
```
**Check:** it pulls IoCs and flags matches as findings. Pull-only, no cross-sync
dedup. Promote if it reliably pulls + matches on a real feed; otherwise stays
Alpha (needs infra).

---

## Group 3 — needs a code change from me first (say "vai", I ship it, then you validate)

Each is a `0.10x` release I build on Windows; then you run the Kali step to
promote. Ordered by value.

### 3A ▶ `--os-fp-v6`: expand the IPv6 signature DB  → say **"vai 3B"**
Today the v6 DB is thin (the sweep host read "legacy/embedded", nmap matched
nothing either). I add ~20 Windows/Linux/BSD/network-OS v6 signatures. **Then you
validate:**
```sh
ip -6 neigh                                   # find reachable v6 hosts
sudo $RM --os-fp-v6-multi <ipv6-host> --os-fp-v6-ports 22,80,443 --experimental-confirm
nmap -6 -O <ipv6-host>                         # reference
```
**Promote if** the OS family matches nmap on 1–2 real v6 hosts. *(If you still
have the signature values from your reverted R&D, paste them and I start there.)*

### 3B ▶ `--ipa-scan`: mach-O + entitlements parsing  → say **"vai 3C"**
Today only `Info.plist` is parsed. I add mach-O header (PIE/encryption/arch/
code-sign) + embedded `.mobileprovision` entitlements (get-task-allow, dangerous
capabilities). **Then you validate** on a real IPA with known issues:
```sh
$RM --ipa-scan /path/app.ipa --experimental-confirm
```
**Promote if** findings match the app's known issues with low FP.

### 3C ▶ `--brute-protocol rdp`: CredSSP pubKeyAuth  → say **"vai 3D"**
Implement the RC4-of-SPKI step under the NTLM session key so a **positive** is
authoritative, not just suggestive. Makes rdp promotable. **Then** re-run 2A on a
Windows host: known-good + known-bad both match hydra → promote.

---

## Tracking

| Feature | Needs | Can promote? | Next action |
|---------|-------|--------------|-------------|
| `--owasp-scan` | DVWA (have it) | No (no JS, by design) | **1A** — confirm 6/0, close 3A validation |
| `--osdb-submit` | a host | No (by design) | **1B** — verify pack |
| `--web-crawl` | DVWA | No (no JS, by design) | **1C** — optional re-confirm |
| `--brute-protocol rdp` | Windows RDP host | after 3C + host | **2A** now (mechanics), **3C** for authoritative |
| `--threat-intel-misp` | lab MISP + key | maybe | **2B** when infra exists |
| `--os-fp-v6` | code **3A** + v6 hosts | **yes**, after 3A | say **"vai 3B"** → I build |
| `--ipa-scan` | code **3B** + real IPA | **yes**, after 3B | say **"vai 3C"** → I build |

## Not on this roadmap (your standing decisions)

- **v1.0 cut / feature-freeze / `v1.0.0` tag** — needs your explicit go-ahead.
- **fast engine as default** — stays opt-in (`--fast-engine`); not re-proposed.

## How we work

I ship a release → you run the matching step on Kali against the reference tool
(nmap / hydra / ZAP / sqlmap) → paste the output → I harden + flip the tier.
**One real-target agreement with the reference = promote; divergence = fix or
stay Alpha.** Every bug → a `0.10x` patch, re-run that row.
