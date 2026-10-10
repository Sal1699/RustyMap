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
