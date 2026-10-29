# RustyMap — Alpha feature validation sweep

Exercise all 11 Alpha-tier features on Kali, record results, promote the ones
that match a reference tool. **Every Alpha feature requires `--experimental-confirm`.**

```sh
cd ~/RustyMap && git fetch --tags && git checkout v0.100.16 && cargo build --release
RM=./target/release/rustymap
```

Legend: 🟢 realistic Production candidate · 🟡 harden-then-maybe · 🔴 Alpha by
design (validate it runs; won't promote without new code or is inherently limited).

Promotion rule (as always): one observed agreement with the reference tool on a
real target → tell me and I flip the tier. Record outcomes in `LAB_VALIDATION.md`.

---

## Sweep results — completed 2026-10-29 (outcomes shipped in v0.100.17)

| # | Feature | Ran | RustyMap | Reference | Verdict |
|---|---------|-----|----------|-----------|---------|
| 1 | `--brute-protocol mssql` | ✅ | MISS on correct + wrong cred (cleartext LOGIN7) | hydra HIT `sa:Str0ng!Pass` | **Stay Alpha** — needs TDS-over-TLS login for SQL Server 2022 |
| 2 | `--brute-protocol rdp` | ⊘ skip | — | — | No RDP target (port filtered on Win host) |
| 3 | `--apk-scan` | ✅ | 5 dangerous perms, debuggable, allowBackup, exported, AdMob/Analytics, **0 FP** | InsecureBankv2 known issues — all match | **→ PRODUCTION (v0.100.17)** |
| 4 | `--ipa-scan` | ✅ | ATS disabled, URL schemes, bundle metadata | synthetic IPA (known-insecure plist) | PASS (limited) — stay Alpha (no mach-O/entitlements) |
| 5 | `--ics-scan` | ✅ | Modbus :502 + S7 :102 fingerprinted (raw bytes) | nmap modbus-discover/s7-info both **ERROR** | **→ PRODUCTION (v0.100.17)** — outperforms nmap on Conpot |
| 6 | `--os-fp-v6` | ✅ | "legacy/embedded stack (no WS/TS/SACK) 70%" | nmap -6 -O: "No OS matches" | Stay Alpha — thin v6 DB (both tools miss this host) |
| 7 | `--owasp-scan` | ✅ | crawler 24 pages/35 endpoints ✓; probes **0 findings** | DVWA low: XSS/SQLi/CMDi exploitable | **FAIL → fixed in v0.100.17** (probe ran unauthenticated + dropped `security=low`); re-run to confirm. Stays Alpha |
| 8 | `--web-crawl` | ✅ | 24 pages/35 endpoints, in-scope, session held | DVWA authenticated crawl | PASS — stay Alpha (no JS) |
| 9 | `--sI` | ⊘ skip | — | — | No predictable-IPID zombie available |
| 10 | `--threat-intel-misp` | ⊘ skip | — | — | No MISP instance in lab |
| 11 | `--osdb-submit` | ✅ | pack: Linux, TTL=64, CPE valid, conf 55%, no auto-submit | manual review | PASS — stay Alpha by design |

**Promotions:** `--ics-scan`, `--apk-scan` → Production (9 Alpha remaining).
**Bug found + fixed (v0.100.17):** `--owasp-scan` probed unauthenticated and dropped the `security=low` cookie.
**Confirmed gap:** mssql cleartext LOGIN7 vs SQL Server 2022 TLS → TDS-over-TLS login deferred.

The per-feature recipes below stay for re-running rows as missing targets (RDP host,
IPID zombie, MISP instance, DVWA for the owasp re-test) become available.

---

## 1. 🟢 `--brute-protocol mssql` — SQL Server cred brute
```sh
docker run -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=Str0ng!Pass' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022
$RM --brute-protocol mssql --brute-target 127.0.0.1:1433 --brute-pair 'sa:Str0ng!Pass' --experimental-confirm --brute-confirm-authorized
hydra -l sa -p 'Str0ng!Pass' mssql://127.0.0.1    # reference
```
**Known gap:** the adapter sends a cleartext LOGIN7; SQL Server 2016+ TLS-encrypts
the login packet. If RM fails to authenticate the *correct* cred → that confirms a
TDS-over-TLS login gap → tell me, I'll implement TLS login. If it HITs and matches
hydra → promote (8th brute).

## 2. 🟡 `--brute-protocol rdp` — RDP cred brute
```sh
$RM --brute-protocol rdp --brute-target <win>:3389 --brute-pair 'Administrator:wrongpass' --experimental-confirm --brute-confirm-authorized
$RM --brute-protocol rdp --brute-target <win>:3389 --brute-pair 'Administrator:<known-good>' --experimental-confirm --brute-confirm-authorized
hydra -l Administrator -p wrongpass rdp://<win>    # reference
```
Target: a Windows host with RDP enabled (your Win11 `.64` if Pro — Home has no RDP
server). **Known gap:** CredSSP pubKeyAuth NOT implemented → positive results are
*suggestive*, negatives (NTSTATUS) reliable. Report both the negative and a
known-good positive; I'll harden the NTSTATUS mapping. Likely stays Alpha unless
both match hydra.

## 3. 🟡 `--apk-scan` — Android APK static analysis
```sh
# grab a known-vulnerable APK, e.g. DIVA or InsecureBankv2
$RM --apk-scan /path/diva.apk --experimental-confirm
```
Reference: the app's documented issues, or `mobsf`. Report the findings; I'll tune
the mobile-secret FP patterns and AXML robustness. Promote if findings match the
app's known issues with low FP.

## 4. 🟡 `--ipa-scan` — iOS IPA static analysis
```sh
$RM --ipa-scan /path/app.ipa --experimental-confirm
```
**Known gap:** only `Info.plist` is parsed — no mach-O entitlements / embedded
provisioning profile. Report what it extracts; I'll add mach-O/entitlements
parsing. Stays Alpha until that lands.

## 5. 🟡 `--ics-scan` — ICS/SCADA probes
```sh
docker run --rm -p 502:502 -p 102:102 -p 161:161/udp -p 47808:47808/udp honeynet/conpot
$RM --ics-scan 127.0.0.1 --experimental-confirm
nmap --script modbus-discover,s7-info -p 502,102 127.0.0.1    # reference
```
Report Modbus/S7/DNP3/EnIP/BACnet fingerprints vs nmap. Promote if they agree on a
fresh Conpot (note it stays "Conpot-validated" — real PLCs behave differently).

## 6. 🟡 `--os-fp-v6` — IPv6 OS fingerprint
```sh
ip -6 neigh                                  # find a reachable IPv6 host
$RM --os-fp-v6-multi <ipv6-host> --os-fp-v6-ports 22,80,443 --experimental-confirm
nmap -6 -O <ipv6-host>                        # reference
```
(`--os-fp-v6 <host>` is the single-port form; `--os-fp-v6-port` sets its port.)
Promote if the OS family matches nmap on 1–2 hosts. DB is thinner than the v4 path.

## 7. 🔴 `--owasp-scan` — web vuln probes (XSS/SQLi/redirect/SSRF)
```sh
$RM --owasp-scan 'http://<dvwa>/' --web-crawl-cookie 'PHPSESSID=...; security=low' --experimental-confirm
```
Target: DVWA on Metasploitable 2, or pentest-ground.com. Reference: `zap-baseline.py`
/ sqlmap. **FP-heavy by design** → goal is measuring/reducing false positives, not
Production. Report the FP count vs ZAP and I'll tighten the probes.

## 8. 🔴 `--web-crawl` — BFS crawler
```sh
$RM --web-crawl 'http://<target>/' --web-crawl-cookie 'PHPSESSID=...' --experimental-confirm
```
**Known gap:** slow, no JS rendering, weak cookie/CSRF handling. Report whether it
stays in-scope and holds the DVWA session; I'll fix cookie/CSRF. Stays Alpha
(inferior to ZAP by design).

## 9. 🔴 `--sI` — idle/zombie scan
```sh
nmap --script ipidseq <lan-cidr>              # find a predictable-IPID zombie
$RM --sI <zombie>[:port] -p <ports> <target> --experimental-confirm
nmap -sI <zombie> <target>                    # reference
```
**(v0.100.16 fixes the gate — `--sI` now actually requires `--experimental-confirm`.)**
Likely stays Alpha: predictable-IPID zombies are rare on modern OSes. Validate it
works *if* you can find a zombie (old printer/IoT often works).

## 10. 🔴 `--threat-intel-misp` — MISP IoC pull + match
```sh
# a lab MISP instance + API key (e.g. coolacid/misp-docker)
$RM --threat-intel-misp https://<misp>/ --misp-api-key <KEY> --threat-intel-match --experimental-confirm <scan args>
```
Report whether it pulls IoCs and flags matches as findings. Pull-only, no dedup.
Needs MISP infra. (Flag was mis-advertised as `--threat-intel-sync` before v0.100.16.)

## 11. 🔴 `--osdb-submit` — OS-fp submission pack
```sh
$RM --osdb-submit <host>:MyLabel --osdb-submit-out /tmp/pack.txt --experimental-confirm
```
No external target — it **writes a submission pack** to stdout / the `-out` file,
it does NOT auto-submit anywhere. Verify the pack describes the fingerprint
correctly. Stays Alpha by design (privacy-sensitive output — review before sharing).

---

### Realistic outcome
- **Can promote with validation:** mssql (after TLS-login if needed), ics, os-fp-v6,
  possibly apk.
- **Harden but likely stay Alpha:** rdp (pubKeyAuth gap), ipa (needs mach-O), owasp
  + web-crawl (FP/limited by design), sI (zombie scarcity), threat-intel (infra),
  osdb-submit (privacy by design).

Work them in any order you have a target for; paste results and I'll harden +
promote per feature.
