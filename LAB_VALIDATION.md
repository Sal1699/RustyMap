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
