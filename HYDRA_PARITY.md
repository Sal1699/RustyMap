# RustyMap bruteforce — hydra parity harness

Turnkey command pairs for validating RustyMap's 13 credential-bruteforce
adapters against **hydra** (and crackmapexec/medusa where noted) in the lab.
RustyMap can't be self-validated for brute here on Windows — this file makes
the Kali second-opinion run ready to execute.

**Prep (once):**
```sh
printf 'root\nadmin\nuser\ntest\n'            > users.txt
printf 'root\nadmin\npassword\ntoor\n123456\n' > pass.txt
printf 'public\nprivate\ncommunity\n'         > communities.txt
TARGET=192.168.1.X      # a lab box running the service
```

**RustyMap base form** (every adapter):
```
rustymap --brute-protocol <PROTO> --brute-target $TARGET \
         --brute-userlist users.txt --brute-passlist pass.txt \
         --brute-rate 4 --brute-confirm-authorized
```

**What to compare per adapter:** (1) same credentials found (or both find
none), (2) attempt count in the same ballpark, (3) no hang / no crash /
clean exit, (4) RustyMap's rate-limit is honored (watch timing).

| # | PROTO | RustyMap `--brute-protocol` | hydra equivalent |
|---|-------|------------------------------|------------------|
| 1 | SSH | `ssh` | `hydra -L users.txt -P pass.txt ssh://$TARGET` |
| 2 | FTP | `ftp` | `hydra -L users.txt -P pass.txt ftp://$TARGET` |
| 3 | Telnet | `telnet` | `hydra -L users.txt -P pass.txt telnet://$TARGET` |
| 4 | SMTP | `smtp` | `hydra -L users.txt -P pass.txt smtp://$TARGET` |
| 5 | SNMP | `snmp` (`--brute-passlist communities.txt`) | `hydra -P communities.txt snmp://$TARGET` |
| 6 | SMB | `smb` | `hydra -L users.txt -P pass.txt smb://$TARGET` · `crackmapexec smb $TARGET -u users.txt -p pass.txt` |
| 7 | MySQL | `mysql` | `hydra -L users.txt -P pass.txt mysql://$TARGET` |
| 8 | PostgreSQL | `postgres` | `hydra -L users.txt -P pass.txt postgres://$TARGET` |
| 9 | LDAP | `ldap` | `hydra -L users.txt -P pass.txt ldap2://$TARGET` |
| 10 | VNC | `vnc` | `hydra -P pass.txt vnc://$TARGET` |
| 11 | MSSQL | `mssql` (Alpha — needs `--experimental-confirm`) | `hydra -L users.txt -P pass.txt mssql://$TARGET` |
| 12 | RDP | `rdp` (Alpha — needs `--experimental-confirm`) | `hydra -L users.txt -P pass.txt rdp://$TARGET` |
| 13 | HTTP-basic | `http-basic --brute-http-url http://$TARGET/protected` | `hydra -L users.txt -P pass.txt $TARGET http-get /protected` |
| 14 | HTTP-form | `http-form --brute-form-spec 'url=http://$TARGET/login,user=username,pass=password,fail=Invalid'` | `hydra -L users.txt -P pass.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid"` |

**Lab results — v0.100.3 (Metasploitable 2 `172.17.0.2`; LDAP via osixia/openldap):**

| PROTO | RustyMap vs hydra | Tier |
|-------|-------------------|------|
| ftp | ✅ same hit `msfadmin:msfadmin` (single + needle), wrong rejected | **Production** (v0.100.4) |
| postgres | ✅ same hit `postgres:postgres` (MD5 auth), wrong rejected | **Production** (v0.100.4) |
| ldap | ✅ same bind `cn=admin,dc=example,dc=org` (hydra **ldap3://**), wrong rejected | **Production** (v0.100.4) |
| ssh | ✅ (v0.100.8) recovered `testbrute:test123` on modern OpenSSH (Docker :2222) in 8 attempts; hydra intermittent under MaxStartups the same run | **Production** (v0.100.9) |
| smb | ⚠️ v0.100.10 fix pending re-test: the SMBv1 AUTHENTICATE now echoes the server-assigned UID (was 0 → Samba 3.0.20 rejected all creds); also ByteCount + CAP_EXTENDED_SECURITY | Beta — re-test vs hydra/CME on Samba 3.0.20 |
| mysql | ✅ (v0.100.5 re-test) empty password `root:` HIT = hydra after the v0.100.4 fix | **Production** (v0.100.5) |
| vnc | ✅ (v0.100.5 re-test) RFB 3.3 `password` HIT = hydra after the v0.100.4 fix | **Production** (v0.100.5) |

> ldap note: hydra `ldap2://` reported 0 on this container; `ldap3://` works and
> RustyMap agrees with it. SSH validated v0.100.8 on a modern OpenSSH (Docker
> linuxserver/openssh-server :2222, password auth) → Production v0.100.9. Only
> SMB remains Beta: the BRUTE-1 root cause (SMBv1 AUTHENTICATE sent UID 0, not
> the server-assigned UID) is fixed in v0.100.10, pending a Samba 3.0.20 re-test
> vs hydra/CME.

**Notes**
- MSSQL + RDP are **Alpha** tier (RDP CredSSP pubKeyAuth is best-effort —
  negative results reliable, positives suggestive). They need
  `--experimental-confirm`; treat positives as hints and confirm manually.
- SNMP is community-string based: pass the community list via
  `--brute-passlist communities.txt` (no usernames).
- Expected safe outcome on a hardened/absent service: both tools report 0
  creds and RustyMap exits cleanly (no hang). That alone validates the
  adapter's transport + error handling even without a crackable account.
- Record results in `LAB_VALIDATION.md` and flip the COMMAND_COVERAGE brute
  row from ⬜ to ✅ per adapter as each passes.

**Safe quick smoke (no target needed)** — confirms the gate + dispatch don't
crash (connection-refused is the expected result):
```
rustymap --brute-protocol ssh --brute-target 127.0.0.1:1 \
         --brute-userlist users.txt --brute-passlist pass.txt --brute-confirm-authorized
```
