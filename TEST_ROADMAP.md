# RustyMap — Test Roadmap (v0.69.1)

A phased plan to test RustyMap thoroughly and against nmap. Run the phases
in order: 0 = regression of everything fixed so far, 1 = validate the
raw-socket features that could not be tested on the dev box, then wider.
Log every outcome — especially FAILs — in [`LAB_VALIDATION.md`](LAB_VALIDATION.md).

## Ground rules
- **Authorized targets only.** Public tests use `scanme.nmap.org` (Nmap's
  sanctioned target). Everything intrusive (brute force, aggressive timing,
  UDP, `--owasp-scan`, `--msf-*`) runs **only against your own lab hosts**.
- Run raw-socket scans (`-sS`, `-sU`, `-O`, `--traceroute`, ICMP discovery)
  as **root** on Kali; note in the log whether a test needed root.
- Compare like-for-like: same target, same ports, back-to-back with nmap,
  `time <cmd>` for wall clock.
- PASS = matches nmap within reason **or** the divergence is understood and
  logged. Placeholders: `<LAB_HOST>` (IP on your subnet), `<LAB_SUBNET>`
  (e.g. `192.168.1.0/24`), `<WIN_HOST>`, `<HTTPS_HOST>`, `<DOMAIN>`.
- Build the version under test first:
  `git fetch --tags && git checkout v0.69.1 && cargo build --release`
  then `rustymap --update-cve-db` (needed for the CVE-range test P2.4).

---

## Phase 0 — Regression of all fixes (v0.68.1 → v0.69.1)

| ID | Command | Pass criteria |
|----|---------|---------------|
| R1 | `rustymap scanme.nmap.org` (no `-Pn`) | host up, ports listed — not "0 hosts up" (0.68.1) |
| R2 | `rustymap 127.0.0.1` (no `-Pn`) | completes <1s, no hang (loopback guard) |
| R3 | `rustymap scanme.nmap.org --sV` (no `-Pn`) | runs to end, **no panic**, Script findings printed (0.68.1) |
| R4 | `time rustymap scanme.nmap.org --sV` | "scanned in X" ≈ wall time; "done" line printed **last** (0.68.2) |
| R5 | `rustymap 127.0.0.1 -p 22,80,135,445 --Pn` | closed/filtered ports **shown** (not just open); many→`Not shown: N` (0.68.2/0.A) |
| R6 | `rustymap --top-ports 1000 scanme.nmap.org --sV` | finds 9929 + 31337 (0.68.0) |
| R7 | `rustymap -n scanme.nmap.org -p 80` | resolves + scans, no "DNS disabled" error (0.68.3) |
| R8 | `rustymap <LAB_HOST>` (LAN, no `-Pn`) | found up, **MAC + vendor** line shown; **Network Distance** correct (0.68.2) |
| R9 | `rustymap google.com -p 443 --ssl-enum` | full cipher list, weak suites flagged `⚠` (0.69.0) |
| R10 | `rustymap --cloud-fingerprint google.com` | identifies Google (IP-range); `cloudflare.com`→Cloudflare (0.69.0) |

---

## Phase 1 — Raw-socket features (Kali **root**, pending validation)

These shipped in v0.69.1 but were only fail-closed-tested on Windows.

| ID | RustyMap | nmap check | Pass criteria |
|----|----------|-----------|---------------|
| P1.1 | `sudo rustymap <ICMP-only host>` (a host that answers ping but has no open probe ports) | `nmap -sn <host>` | 0.D: found **up** via ICMP-echo fallback, not "seems down" |
| P1.2 | `sudo rustymap scanme.nmap.org -p 80 --traceroute` | `nmap --traceroute -p 80 scanme.nmap.org` | 1.C: TCP trace shows **real hops**, far fewer `*` than the old ICMP trace |
| P1.3 | `sudo rustymap <LAB_HOST behind FW> --traceroute` | `traceroute -T -p 443 <host>` | hops traverse the firewall (TCP mode) |
| P1.4 | `sudo rustymap -sS --top-ports 1000 scanme.nmap.org` | `sudo nmap -sS --top-ports 1000 …` | same open ports; SYN scan stable |
| P1.5 | `sudo rustymap -sU --top-ports 50 <LAB_HOST>` | `sudo nmap -sU …` | UDP per-port states, `/udp` label, open vs open\|filtered (1.A) |

---

## Phase 2 — New-feature validation

| ID | Command | Pass criteria |
|----|---------|---------------|
| P2.1 | `rustymap <HTTPS_HOST> --ssl-enum` vs `nmap --script ssl-enum-ciphers -p 443 <HTTPS_HOST>` | cipher sets overlap; note any suites nmap finds that we miss |
| P2.2 | `rustymap <legacy-TLS host> --ssl-enum` | 3DES/RC4/CBC surface as `⚠ weak`; SWEET32 flagged |
| P2.3 | `rustymap <HTTPS_HOST> --tls-grade` vs SSL Labs / testssl.sh | grade in the same ballpark |
| P2.4 | `rustymap --cve-for "openssh 6.6.1p1"` (after `--update-cve-db`) | CVE-2024-6387 **absent** (out of range); real 6.6.1 CVEs present (2.B) |
| P2.5 | `rustymap --cve-for "apache 2.4.7"` | KEV-flagged CVEs ordered first |
| P2.6 | `rustymap --cloud-fingerprint <apex on AWS/Fastly/Akamai>` | correct provider via IP-range |

---

## Phase 3 — Core parity vs nmap

| ID | RustyMap | nmap | Pass |
|----|----------|------|------|
| C1 | `rustymap --sn <LAB_SUBNET>` | `nmap -sn <LAB_SUBNET>` | same live-host set (±1, investigate) |
| C2 | `rustymap --sT scanme.nmap.org -p 1-1000 --reason` | `nmap -sT … --reason` | same open/closed/filtered verdicts |
| C3 | `rustymap <WIN_HOST> --sF` | `nmap -sF <WIN_HOST>` | FIN scan: Windows all-closed hint shown |
| C4 | `rustymap scanme.nmap.org -v --reason` | `nmap … --reason` | RTT/REASON columns, realistic latency, Network Distance |

---

## Phase 4 — Service / version + CVE depth

| ID | Command | Pass |
|----|---------|------|
| S1 | `rustymap <LAB_HOST> --sV -p 21,22,25,80,443,3306,3389` vs `nmap -sV …` | product/version per port; log misses |
| S2 | `rustymap <LAB_HOST> --sV --version-intensity 9` | deeper probing improves coverage (note: intensity effect, ex-bug 2.A) |
| S3 | `rustymap <LAB_HOST> --sV --nmap-service-probes /usr/share/nmap/nmap-service-probes` | import widens detection (parser covers ~78% — 5.C) |
| S4 | review the CVE block on S1 | spot-check 10 matches for false pos/neg |

---

## Phase 5 — Feature sweep (confirm each runs, no crash/timeout)

Alpha-tier features may need `--experimental-confirm`. Goal here is
breadth (274 flags exist); deep validation is per-feature later.

| ID | Command | Pass = |
|----|---------|--------|
| F1 | `rustymap <DOMAIN> --dns-security` | DNSSEC/CAA/SPF/DMARC/MX report |
| F2 | `rustymap <DOMAIN> --dns-enum` | wildcard detect + subdomain list |
| F3 | `rustymap <HTTPS_HOST> --csp-cors` | CSP/CORS findings (ex-bug 6) |
| F4 | `rustymap <URL> --http-methods` | PUT/DELETE/TRACE; refused methods **not** flagged critical (4.C) |
| F5 | `rustymap <URL> --http-enum` | completes fast with output (ex-bug 4) |
| F6 | `rustymap <HOST> --ssh-audit` | KEX/cipher/MAC/host-key list (ex-bug 5) |
| F7 | `rustymap <LAB_HOST> --sV --compliance pci-dss` | control mapping + findings |
| F8 | `rustymap <LAB_HOST> --sV --oJ o.json --oH o.html --oMd o.md --oP o.pdf` | all four files valid |
| F9 | `rustymap <LAB_HOST> --sV --siem-format ecs` | valid CEF/ECS |
| F10 | `rustymap <DOMAIN> --takeover-check` / `--origin-discovery` | run; origin-discovery must **not** report 127.0.0.1 (watch ex-bug 0.B/4.D) |
| F11 | `rustymap <LAB_HOST> --sV` ×2 then `--diff-against` | diff vs previous scan |
| F12 | `rustymap --brute-protocol ssh --brute-target <LAB_HOST> --brute-confirm-authorized` | auth gate works — **lab host only** |
| F13 | `rustymap <LAB_HOST> --detect-preview` / `--recommend` / `--serve` | run and produce output |
| F14 | `rustymap <LAB_HOST> --checkpoint s.json` then interrupt + `--resume s.json` | resume works |

---

## Phase 6 — Architectural gap quantification vs nmap

Not pass/fail — **measure the gap** to prioritize the remaining Tier-2 work
(TCP-stack OS fingerprinting is the last big item).

| ID | RustyMap | nmap | Record |
|----|----------|------|--------|
| A1 | `sudo rustymap -O <LAB_HOST>` on 5–10 heterogeneous hosts | `sudo nmap -O <LAB_HOST>` | rustymap guess+confidence vs nmap; hit rate (currently TTL-only) |
| A2 | `rustymap -O <LAB_HOST> --nmap-os-db /usr/share/nmap/nmap-os-db` | — | does the DB change the result? (currently loaded-not-used, 5.B) |
| A3 | `rustymap <HTTPS_HOST> --ssl-enum` cipher count | `nmap --script ssl-enum-ciphers` | how many suites we miss vs nmap |
| A4 | `rustymap <LAB_HOST> --sV` product coverage | `nmap -sV` | # services identified each |

---

## Phase 7 — Non-functional

| ID | What | Pass |
|----|------|------|
| N1 | `time rustymap -sS --top-ports 1000 <LAB_HOST>` vs `time nmap …` | record ratio (feeds the Criterion bench, still TODO) |
| N2 | Ctrl-C mid-scan | clean cancel, partial results, sane exit code |
| N3 | `rustymap <LAB_SUBNET>` (a /24) | completes without hang / runaway memory |
| N4 | invalid inputs (`999.999.999.999`, bad CIDR, unreachable host) | clear error, no panic, correct exit code |
| N5 | `--oX` XML vs `xmllint` / JSON vs `jq` | outputs are well-formed |

---

## Logging
Append each result to `LAB_VALIDATION.md`:
`Date | Feature | Lab target | Reference (nmap …) | Result | Notes | Promoted?`
Prioritize logging **FAILs and divergences** — they drive the next patch.
Current top open item to feed: **Phase 6 / A1–A2 → TCP-stack OS fingerprinting.**
