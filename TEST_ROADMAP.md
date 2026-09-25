# RustyMap — Test Roadmap (v0.68.1)

A phased plan to validate RustyMap against nmap in the lab. Run the phases
in order: Phase 0 confirms the v0.68.1 fixes, then each later phase goes
wider. Log outcomes in [`LAB_VALIDATION.md`](LAB_VALIDATION.md).

## Ground rules
- **Authorized targets only.** Public tests use `scanme.nmap.org` (Nmap's
  sanctioned scan target). Everything intrusive (brute force, aggressive
  timing, UDP floods, `--owasp-scan`) runs **only against your own lab
  hosts**. Never brute-force or aggressively probe a third party.
- Placeholders: `<LAB_HOST>` = an IP on your lab subnet, `<LAB_SUBNET>` =
  e.g. `192.168.1.0/24`, `<WIN_HOST>` = a Windows lab box, `<HTTPS_HOST>`
  = a lab host serving TLS.
- Compare like-for-like: same target, same port set, back-to-back with
  nmap. Note wall time with `time <cmd>`.
- PASS = matches nmap within reason **or** the divergence is understood
  and logged. Record every FAIL/divergence in `LAB_VALIDATION.md`.

---

## Phase 0 — Regression: verify the v0.68.1 fixes (do first, ~10 min)

| ID | Command | Pass criteria |
|----|---------|---------------|
| R1 | `rustymap scanme.nmap.org` | **"host up"**, ports listed — NOT "0 hosts up". (bug #1) |
| R2 | `rustymap 45.33.32.156` (IP direct, no `-Pn`) | host up. (bug #1 via raw IP) |
| R3 | `rustymap <LAB_HOST>` | LAN host still found up, **MAC Address + vendor** line shown (ARP path intact — the fix must not break local discovery) |
| R4 | `rustymap 127.0.0.1` (no `-Pn`) | completes in <1s, no hang (loopback guard) |
| R5 | `rustymap scanme.nmap.org --sV` | runs to the end, **no panic**, `Script findings` printed (async-panic fix) |
| R6 | `time rustymap scanme.nmap.org --sV` | "scanned in X" ≈ real wall time; the **"RustyMap done"** line is the **last** thing printed, after CVE + scripts (bug #2) |
| R7 | `rustymap --top-ports 1000 scanme.nmap.org --sV` | finds ports **9929** and **31337** (bug #3) |

If any R-test fails, stop and report it — those are the fixes we just shipped.

---

## Phase 1 — Core scan parity vs nmap

| ID | RustyMap | nmap equivalent | Pass criteria |
|----|----------|-----------------|---------------|
| C1 | `rustymap --sn <LAB_SUBNET>` | `nmap -sn <LAB_SUBNET>` | same set of live hosts (±1 acceptable, investigate deltas) |
| C2 | `rustymap --sT scanme.nmap.org -p 1-1000 --reason` | `nmap -sT scanme.nmap.org -p 1-1000 --reason` | same open/closed/filtered verdicts per port |
| C3 | `sudo rustymap --sS --top-ports 1000 scanme.nmap.org` | `sudo nmap -sS --top-ports 1000 scanme.nmap.org` | same open ports (now that top-1000 lists match) |
| C4 | `sudo rustymap --sU --top-ports 50 <LAB_HOST>` | `sudo nmap -sU --top-ports 50 <LAB_HOST>` | UDP open/open-filtered agreement |
| C5 | `rustymap --sT <WIN_HOST>` then `--sF <WIN_HOST>` | `nmap -sT` / `-sF` | FIN scan behaves per RFC (Windows → all closed hint shown) |
| C6 | `rustymap scanme.nmap.org -v --reason` | `nmap scanme.nmap.org --reason` | new columns render: **RTT**, REASON; latency realistic; **Network Distance** shown |
| C7 | `time rustymap --sS --top-ports 1000 <LAB_HOST>` | `time nmap -sS --top-ports 1000 <LAB_HOST>` | record wall-time ratio (feeds Fase 27 perf work) |

---

## Phase 2 — Service / version detection + CVE

| ID | RustyMap | nmap equivalent | Pass criteria |
|----|----------|-----------------|---------------|
| S1 | `rustymap scanme.nmap.org --sV` | `nmap -sV scanme.nmap.org` | SSH → OpenSSH+version; HTTP → Apache+version. Compare depth. |
| S2 | `rustymap <LAB_HOST> --sV -p 21,22,25,80,443,3306,3389` | `nmap -sV …` | product/version per port; note misses/false versions |
| S3 | `rustymap <LAB_HOST> --sV --version-intensity 9` | `nmap -sV --version-intensity 9` | deeper probing improves coverage |
| S4 | `rustymap <LAB_HOST> --sV` (review CVE block) | — (nmap has none) | CVE correlation: spot-check 10 matches for false pos/neg |
| S5 | `rustymap <LAB_HOST> --sV --nmap-service-probes /usr/share/nmap/nmap-service-probes` | — | importing nmap's DB widens detection |

---

## Phase 3 — Remaining known bugs (targeted repro)

Reproduce, capture full output + `time`, log in `LAB_VALIDATION.md`.

| ID | Bug | Command | What to capture |
|----|-----|---------|-----------------|
| B4 | `--http-enum` hangs / no output | `time rustymap scanme.nmap.org --http-enum` | wall time vs reported; is any enum output produced? |
| B5 | `--ssh-audit` timeout | `rustymap scanme.nmap.org --ssh-audit` | does it complete on an open, reachable :22? error text? |
| B6 | `--csp-cors` timeout | `rustymap <HTTPS_HOST> --csp-cors` (also try a lab host) | completes vs "deadline elapsed"? |
| B7 | `-n` with hostname | `rustymap -n scanme.nmap.org` | should resolve forward + skip reverse DNS, not error |

---

## Phase 4 — Untested feature smoke sweep

Goal: confirm each **runs and produces sane output** (no crash/timeout).
Deep validation comes later. Alpha-tier features may need
`--experimental-confirm`.

| ID | Command | Pass = |
|----|---------|--------|
| F1 | `rustymap <DOMAIN> --dns-security` | DNSSEC/CAA/SPF/DMARC/MX report |
| F2 | `rustymap <DOMAIN> --cloud-fingerprint` | provider/CDN identified |
| F3 | `rustymap <HTTPS_HOST> --tls-grade --ssl-enum` | grade + cipher list |
| F4 | `rustymap <LAB_HOST> --sV --compliance pci-dss` | control mapping + findings |
| F5 | `rustymap <LAB_HOST> --sV --oJ out.json --oH out.html --oMd out.md --oP out.pdf` | all four files written, valid |
| F6 | `rustymap <LAB_HOST> --sV --siem-format ecs` | CEF/ECS output |
| F7 | `rustymap <DOMAIN> --takeover-check` | 17-provider check runs |
| F8 | `rustymap <DOMAIN> --origin-discovery` | origin-behind-CDN attempt |
| F9 | `rustymap <LAB_HOST> --container-scan` | Docker/K8s/etcd surface check |
| F10 | `rustymap <LAB_HOST> --recommend` | suggests useful flags per open ports |
| F11 | `rustymap <LAB_HOST> --sV` twice, then `rustymap <LAB_HOST> --diff` | diff vs previous scan from history |
| F12 | `rustymap --brute-protocol ssh --brute-target <LAB_HOST> --brute-confirm-authorized` | brute runs only with the auth gate — **lab host only** |
| F13 | `rustymap <LAB_HOST> --detect-preview` | which IDS/WAF/EDR would react |
| F14 | `rustymap <LAB_HOST> --serve` | web dashboard reachable |

*(Add rows as you cover more of the feature list from the comparison report.)*

---

## Phase 5 — Architectural gap quantification vs nmap

These aren't pass/fail — they **measure the gap** so we can prioritize the
big work items (OS stack fingerprinting, full SSL enum).

| ID | RustyMap | nmap | Record |
|----|----------|------|--------|
| A1 | `sudo rustymap -O <LAB_HOST>` on 5–10 heterogeneous hosts (Linux, Windows, router, printer, BSD) | `sudo nmap -O <LAB_HOST>` | per host: rustymap guess+confidence vs nmap guess; how often right? |
| A2 | `rustymap <HTTPS_HOST> --ssl-enum` | `nmap --script ssl-enum-ciphers -p 443 <HTTPS_HOST>` | cipher count: rustymap (1/version?) vs nmap (all) |
| A3 | `rustymap <LAB_HOST> --sV` product coverage across a mixed service host | `nmap -sV` | # services identified each; rustymap's misses |

Feed A1/A2/A3 numbers into the roadmap: A1 → TCP-stack fingerprinting work,
A2 → full cipher enumeration, A3 → service-probe DB expansion.

---

## Logging results
For each test, append a row to `LAB_VALIDATION.md` (Validation log table):
`Date | Feature | Lab target | Reference (nmap …) | Result | Notes | Promoted?`
Prioritize logging **FAILs and divergences** — those drive the next patch.
