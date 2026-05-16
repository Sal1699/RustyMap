use colored::Colorize;

// ── Half-Life palette ────────────────────────────────────────────
//   HL_ORANGE: logo / barre (Freeman orange)
//   HL_AMBER : HUD text
//   HL_YELLOW: HEV suit accents / esempi
//   HL_DIM   : prompt dimmed / tag discreti
//   HL_TEXT  : testo normale, quasi bianco
const HL_ORANGE: (u8, u8, u8) = (247, 129, 0);
const HL_AMBER: (u8, u8, u8) = (255, 176, 0);
const HL_YELLOW: (u8, u8, u8) = (245, 232, 46);
const HL_DIM: (u8, u8, u8) = (140, 90, 20);
const HL_TEXT: (u8, u8, u8) = (220, 220, 210);

pub fn print_guide() {
    banner();
    toc();

    category("ESSENTIALS");
    section("TARGET");
    line("<TARGET>              IP, hostname, CIDR, range o più target separati");
    example("rustymap 192.168.1.1");
    example("rustymap example.com");
    example("rustymap 10.0.0.0/24");
    example("rustymap 10.0.0.1-50 192.168.1.1");

    section("PORTE");
    line("-p, --ports SPEC      Porte da scansionare (default: 1-1000)");
    line("--all-ports           Alias per -p-");
    line("-F, --fast            Top 100 porte (alias --top-ports 100)");
    line("-r                    Non randomizzare l'ordine porte (override)");
    line("--exclude-ports SPEC  Escludi porte (numeri/range/alias: ssh,smb,rdp,web,db…)");
    example("rustymap -p 22 10.0.0.5");
    example("rustymap -p 22,80,443 10.0.0.5");
    example("rustymap -p 1-1000 10.0.0.5");
    example("rustymap -p - 10.0.0.5              # tutte le 65535");

    category("SCAN");
    section("TIPI DI SCAN");
    line("--sT                  TCP connect (3-way handshake, no privilegi)");
    line("--sS                  TCP SYN half-open (admin + Npcap; auto-fallback driver-less)");
    line("--syn-emulated        Forza --sS senza driver (SO_LINGER=0, no admin)");
    line("--ipv4-only           Scarta gli AAAA dopo la risoluzione DNS");
    line("--ipv6-only           Scarta gli A dopo la risoluzione DNS");
    line("--traceroute          Traceroute via tracert/traceroute di sistema");
    line("--trace-hops N        Hop massimi (default 20)");
    line("--topology FILE       Scrive grafo Graphviz DOT della topologia");
    line("--tui                 Apre browser TUI dei risultati (q per uscire)");
    line("--exclude SPEC        Esclude IP/CIDR/range (ripetibile, virgole ok)");
    line("--exclude-file FILE   File con un host/CIDR per riga da escludere");
    line("-A, --aggressive      Combo: -sV -O --traceroute + scripts/ se presente");
    line("--top-ports N         Scansiona le N porte più comuni (override -p)");
    line("--reason              Mostra perché lo stato è quello (syn-ack, rst, …)");
    line("--randomize-hosts     Randomizza l'ordine degli host");
    line("--oA PREFIX           Scrive tutti i formati (txt/gnmap/json/html/md)");
    line("-R                    Forza reverse DNS su ogni IP target");
    line("--host-timeout SEC    Abbandona host dopo N secondi (solo --sT, 0=off)");
    line("--stats-every SEC     Stampa progress ogni N secondi durante lo scan");
    line("--data-string STR     Payload ASCII custom sui pacchetti raw");
    line("--data-hex HEX        Payload hex custom sui pacchetti raw");
    line("--script-arg K=V      Argomento per gli script Rhai (ripetibile)");
    line("--list-scans          Lista le scansioni nel db SQLite e esce");
    line("--open                Mostra solo le porte aperte (anche con -v)");
    line("--iL FILE             Legge target da file (uno per riga, # commenti)");
    line("--oX FILE             Output XML compatibile nmap (zenmap/msf)");
    line("--decoy-random N      Aggiunge N decoy IP casuali ai --decoys");
    line("--max-rate PPS        Cap a PPS pacchetti/sec (per-host, via scan-delay)");
    line("--sF                  TCP FIN scan");
    line("--sN                  TCP NULL scan (nessun flag)");
    line("--sX                  TCP Xmas scan (FIN+PSH+URG)");
    line("--sA                  TCP ACK scan (mapping firewall)");
    line("--sW                  TCP Window scan (RST window field → open/closed)");
    line("--sM                  TCP Maimon scan (FIN+ACK, BSD-derived stacks)");
    line("--sL                  List scan: risolve target con PTR e esce");
    line("--sU                  UDP scan");
    line("--sY                  SCTP INIT scan (raw, root/Npcap)");
    line("--sZ                  SCTP COOKIE-ECHO scan (raw, root/Npcap)");
    line("--PY [PORT]           SCTP INIT ping (host discovery; default port 80)");
    line("--PM                  ICMP Address Mask ping (type 17)");
    line("--PO PROTO            IP-protocol ping (1=ICMP, 17=UDP, 132=SCTP, 47=GRE)");
    line("--ttl N               IP TTL custom (alias di --ip-ttl)");
    line("fe80::1%eth0          IPv6 link-local con zone-ID — supportato come target");
    line("--os-fp-v6 HOST       IPv6 OS fingerprint best-effort (Linux/Windows/BSD/network)");
    line("--os-fp-v6-port N     Probe port per --os-fp-v6 (default 80)");
    line("--checkpoint F.state  Salva progress dello scan in F.state per resume");
    line("--resume-from F.state Riprende uno scan da un checkpoint file");
    line("--stylesheet URL      Embedda XSL nell'XML output (browser-friendly)");
    line("--iR N                N target IPv4 pubblici random (richiede --internet-consent)");
    line("--internet-consent    Conferma autorizzazione per --iR");
    line("--snmp-enum HOST      SNMP v1 enum (community common + MIB-2 system)");
    line("--snmp-community CSV  Community extra per --snmp-enum");
    line("--nbt-enum HOST       NetBIOS NBSTAT (UDP/137): hostname/workgroup/MAC");
    line("--ldap-enum HOST      LDAP anonymous bind + rootDSE");
    line("--ldap-port N         Override porta LDAP (default 389)");
    line("--sR HOST             RPC portmap dump (NFS/mountd/nlockmgr/…)");
    line("--rpc-udp             Usa UDP/111 invece di TCP/111 per --sR");
    line("--smb-deep HOST       SMB pre-auth deep enum (NTLMSSP CHALLENGE)");
    line("--cms-detect URL      Identifica WordPress/Joomla/Drupal + versione");
    line("--http-methods URL    OPTIONS + probe PUT/DELETE/MOVE/TRACE/PATCH");
    line("--shellshock URL      Probe CVE-2014-6271 su path CGI comuni");
    line("--webdav-probe URL    PROPFIND + flag IIS6 CVE-2017-7269 + write-methods");
    line("--csp-cors URL        Deep audit CSP weaknesses + CORS Origin-reflection");
    line("--vuln-ms17-010 HOST  EternalBlue indicator (Trans2 SESSION_SETUP probe)");
    line("--vuln-ssl-ccs HOST   TLS ChangeCipherSpec injection (CVE-2014-0224)");
    line("--vuln-ssl-dh HOST    Logjam: DHE_EXPORT acceptance + DH prime bit-length");
    line("--vuln-ssl-port N     Override porta TLS per --vuln-ssl-* (default 443)");
    line("--vuln-known-key HOST SPKI SHA-256 vs DB chiavi compromesse (Debian PRNG ecc.)");
    line("--cve-for BANNER      Match product/version contro NVD cache (CVE + CVSS + KEV)");
    line("--cve-for-limit N     Tetto risultati --cve-for (default 25)");
    line("--dhcp-discover       Broadcast DHCP DISCOVER → harvest DHCP server offers");
    line("--mdns-discover       Multicast mDNS (224.0.0.251:5353) — Bonjour/Avahi inventory");
    line("--llmnr-probe         LLMNR poisoning surface check (Responder-style)");
    line("--llmnr-probe-name X  Custom name per --llmnr-probe");
    line("--wsdd-probe          WS-Discovery (Windows + printer multicast)");
    line("--nbt-broadcast       NetBIOS broadcast sweep");
    line("--discover-wait SEC   Wait time per i probe multicast/broadcast (default 3)");
    line("--osscan-guess N      Top-N candidati OS con confidence%% (nmap-style)");
    line("--cpe-out             Emette CPE 2.3 string accanto al guess OS");
    line("--osdb-submit H:LABEL Genera submission pack per il community OS-DB");
    line("--osdb-submit-out F   Scrive il pack su file invece di stdout");
    line("--os-fp-v6-multi H    IPv6 OS-fp multi-port (confidence boost se ≥2 agree)");
    line("--os-fp-v6-ports CSV  Porte per --os-fp-v6-multi (default 22,80,443)");
    line("--max-hostgroup N     Cap batch size sotto --max-parallel (nmap-style)");
    line("--scan-stats N        Stats live ogni N secondi (probes/sec, RTT, peak, RSS)");
    line("--msf-url URL         msfrpcd endpoint (https://host:55553/api/1.0)");
    line("--msf-user/pass/token Credenziali msfrpcd (token o user+pass)");
    line("--msf-insecure        Accetta certificati TLS invalidi");
    line("--msf-ping            Test connessione (chiama core.version)");
    line("--msf-import WS       Importa l'ultimo scan in workspace WS");
    line("--msf-suggest-cve C   Cerca moduli MSF che matchano CVE-XXXX-NNNN");
    line("--msf-fire MODULE     Esegui modulo MSF (richiede --msf-fire-confirm + prompt)");
    line("--msf-fire-exploits   Promuove --msf-fire ad esecuzione exploit-class");
    line("--msf-fire-allow-low  Consente moduli rank=manual/low");
    line("--msf-fire-opt K=V    Datastore option per --msf-fire (ripetibile)");
    line("--brute-protocol P    Bruteforce: ftp|http-basic|http-form|telnet|smtp|pop3|imap|snmp|ssh|smb|mysql|postgres|ldap|vnc");
    line("--brute-target H[:P]  Target per --brute-protocol (porta default per protocol)");
    line("--brute-userlist F    File con username (uno per riga)");
    line("--brute-passlist F    File con password (uno per riga)");
    line("--brute-userpass F    File con coppie user:pass (uno per riga)");
    line("--brute-pair U:P      Test pair singolo");
    line("--brute-rate N        Tentativi/sec (default 1)");
    line("--brute-max-tries N   Cap totale (default 1000)");
    line("--brute-default-creds-only  Modalità sicura ~120 vendor defaults (skip consent)");
    line("--brute-confirm-authorized  OBBLIGATORIO oltre la modalità default-creds-only");
    line("--brute-http-url URL  URL per http-basic");
    line("--brute-form-spec S   url=URL,user=FIELD,pass=FIELD,fail=MARKER per http-form");
    line("--sI ZOMBIE[:PORT]    Idle/zombie scan (spoof via host con IPID incrementale)");
    line("--sO                  IP protocol scan (TCP/UDP/ICMP/GRE/OSPF/SCTP…)");
    example("rustymap --sT 10.0.0.5");
    example("rustymap --sS -p 1-65535 10.0.0.5");
    example("rustymap --sU -p 53,123,161 10.0.0.5");
    example("rustymap --sY -p 80,443,2049 10.0.0.5     # SCTP INIT scan");
    example("rustymap --PY 80 --PM 10.0.0.0/24         # SCTP+netmask host discovery");
    example("rustymap --PO 132 10.0.0.5                # IP-proto ping (SCTP)");
    example("rustymap --sS --ttl 200 10.0.0.5          # SYN scan con TTL custom");
    example("rustymap --sT 'fe80::1%eth0' -p 22         # IPv6 link-local con zone");
    example("rustymap --os-fp-v6 2001:db8::42");
    example("rustymap 2001:db8::/120                    # IPv6 CIDR (cap a /112)");
    example("rustymap --checkpoint scan.state 10.0.0.0/24");
    example("rustymap --resume-from scan.state          # ripende dopo CTRL-C");
    example("rustymap --oX scan.xml --stylesheet rustymap.xsl 10.0.0.5");
    example("rustymap --iR 100 --internet-consent --top-ports 10");
    example("rustymap --snmp-enum 10.0.0.5                          # SNMP system MIB");
    example("rustymap --snmp-enum 10.0.0.5 --snmp-community lab,monitor");
    example("rustymap --nbt-enum 10.0.0.5                           # NetBIOS host info");
    example("rustymap --ldap-enum dc01.example.com                  # rootDSE AD");
    example("rustymap --sR 10.0.0.5                                 # RPC portmap dump");
    example("rustymap --smb-deep 10.0.0.5                           # NTLMSSP info");
    example("rustymap --cms-detect https://target.example.com");
    example("rustymap --http-methods https://target/api/");
    example("rustymap --shellshock https://target.example.com");
    example("rustymap --webdav-probe http://target/dav/");
    example("rustymap --csp-cors https://target.example.com");
    example("rustymap --vuln-ms17-010 10.0.0.5");
    example("rustymap --vuln-ssl-ccs 10.0.0.5 --vuln-ssl-port 443");
    example("rustymap --vuln-ssl-dh 10.0.0.5");
    example("rustymap --vuln-known-key 10.0.0.5");
    example("rustymap --cve-for 'openssh 7.4p1'");
    example("rustymap --cve-for nginx:1.18.0");
    example("rustymap --dhcp-discover                  # rogue-DHCP check");
    example("rustymap --mdns-discover --discover-wait 5");
    example("rustymap --llmnr-probe                    # LLMNR poison check");
    example("rustymap --wsdd-probe                     # Windows discovery");
    example("rustymap --nbt-broadcast                  # NBT sweep");
    example("rustymap -O --osscan-guess 5 10.0.0.5      # top-5 OS candidates");
    example("rustymap -O --cpe-out 10.0.0.5             # CPE 2.3 emission");
    example("rustymap --osdb-submit '10.0.0.5:Ubuntu 22.04 server'");
    example("rustymap --os-fp-v6-multi 2001:db8::42 --os-fp-v6-ports 22,80,443,3389");
    example("rustymap --max-hostgroup 64 --max-parallel 500 10.0.0.0/16");
    example("rustymap --scan-stats 5 10.0.0.0/24      # stats line ogni 5s");
    example("cargo bench                              # criterion micro-bench harness");
    example("rustymap --msf-url https://127.0.0.1:55553/api/1.0 --msf-token TOK --msf-ping");
    example("rustymap --msf-suggest-cve CVE-2021-44228 --msf-url ... --msf-token ...");
    example("rustymap --msf-import lab --msf-url ... --msf-token ... 10.0.0.5  # scan + push");
    example("rustymap --msf-fire auxiliary/scanner/smb/smb_version --msf-fire-confirm --msf-fire-opt RHOSTS=10.0.0.5 --msf-url ... --msf-token ...");
    example("rustymap --brute-protocol ftp --brute-target 10.0.0.5 --brute-default-creds-only");
    example("rustymap --brute-protocol smtp --brute-target mail.lab --brute-userlist u.txt --brute-passlist p.txt --brute-confirm-authorized");
    example("rustymap --brute-protocol snmp --brute-target 10.0.0.5 --brute-passlist communities.txt --brute-confirm-authorized");
    example("rustymap --brute-protocol http-basic --brute-http-url https://lab/admin --brute-default-creds-only");
    example("rustymap --brute-protocol http-form --brute-form-spec 'url=https://app/login,user=username,pass=password,fail=Invalid' --brute-default-creds-only");
    example("rustymap --brute-protocol ssh --brute-target 10.0.0.5 --brute-default-creds-only");
    example("rustymap --brute-protocol smb --brute-target 10.0.0.5 --brute-userlist u.txt --brute-passlist p.txt --brute-confirm-authorized");
    example("rustymap --brute-protocol mysql --brute-target db.lab --brute-userpass mysql-defaults.txt --brute-confirm-authorized");
    example("rustymap --brute-protocol postgres --brute-target pg.lab --brute-default-creds-only");
    example("rustymap --brute-protocol ldap --brute-target dc01:389 --brute-pair 'cn=admin,dc=lab:secret' --brute-confirm-authorized");
    example("rustymap --brute-protocol vnc --brute-target 10.0.0.5 --brute-passlist common.txt --brute-confirm-authorized");
    example("rustymap --sI 192.168.1.100:80 10.0.0.5");

    section("HOST DISCOVERY");
    line("-Pn                   Salta discovery (tratta tutti i host come up)");
    line("--sn                  Solo ping, niente port scan");
    line("--PE                  ICMP echo ping (raw, admin)");
    line("--PR                  ARP discovery (LAN only; auto-detect same /24)");
    line("--PS, --PA, --PU      Variant ping types (alias)");
    line("--PP                  ICMP timestamp ping (type 13, fallback per --PE)");
    example("rustymap --sn 10.0.0.0/24           # ping sweep");
    example("rustymap -Pn --sT 10.0.0.5          # scan forzato");
    example("rustymap --PE --sn 10.0.0.0/24      # ICMP ping sweep");

    section("TIMING & PERFORMANCE");
    line("-t, --timing 0-5      Template (0=paranoid ... 3=default ... 5=insane)");
    line("--max-parallel N      Max connessioni parallele (default 500)");
    line("--timeout MS          Timeout per connessione (default 1500)");
    line("--scan-delay MS       Ritardo fra probe per host");
    line("--adaptive            Rate limiting adattivo (auto-tune)");
    example("rustymap -t4 --max-parallel 1000 10.0.0.0/24");
    example("rustymap -t1 --scan-delay 500 10.0.0.5   # low-and-slow");
    example("rustymap --adaptive 10.0.0.0/24");

    section("SERVICE & OS DETECTION");
    line("--sV                  Probe servizi/versione (banner + probe attivi)");
    line("--version-intensity N Aggressività 0-9 (default 5; ≥7 attiva probe TLS)");
    line("--version-light       Alias di --version-intensity 2");
    line("--version-all         Alias di --version-intensity 9");
    line("--osscan-limit        -O solo su host con almeno una porta open/closed");
    line("                      (su porte TLS aggancia anche cert + protocollo;");
    line("                       con HTTP aperto estrae vendor/model/firmware");
    line("                       per Hikvision, Dahua, Axis, Reolink, Foscam,");
    line("                       HP/Brother/Canon/Epson, MikroTik, Ubiquiti,");
    line("                       TP-Link, Netgear, ASUS, Synology, QNAP,");
    line("                       Cisco, Fortinet, pfSense, OPNsense");
    line("                       + web tech Wappalyzer-style: CMS, framework,");
    line("                       JS lib, CDN, cloud, WAF — con versione)");
    line("-O, --os              Fingerprinting OS (TTL + porte/banner)");
    line("                      (device-class auto: router/camera/printer/NAS/IoT…)");
    example("rustymap --sT --sV 10.0.0.5");
    example("rustymap --sS --sV -O 10.0.0.5");

    category("EVASION & STEALTH");
    section("EVASIONE FIREWALL / IDS");
    line("--evasion PRESET          stealth | aggressive | paranoid | ghost");
    line("--stack-profile NOME      windows11 | linux6 | macos | freebsd | android14");
    line("--scanflags FLAGS         Flag TCP custom (es. SYN,ECE oppure 0x42)");
    line("--source-port PORT        Porta sorgente fissa (53, 80, 88...)");
    line("--decoys IP,IP,...        IP sorgente decoy (spoofed)");
    line("--decoy-preping           SYN benigni dai decoy prima del probe reale");
    line("--ip-ttl N                TTL IP custom");
    line("--ttl-jitter N            TTL jitter ±N per probe");
    line("--data-length N           Appende N byte di padding random");
    line("-f, --fragment            Frammenta IP in pezzi piccoli");
    line("--mtu N                   Dim. frammento (multiplo di 8)");
    line("--frag-overlap            Frammenti sovrapposti (avanzato)");
    line("--badsum                  Checksum TCP invalido (rileva stateful FW/IDS)");
    line("--jitter MS               Jitter gaussiano fra probe");
    line("--rotate-evasion          Ruota TTL/src-port/padding per probe");
    line("--randomize-ports         Ordine porte casuale");
    example("rustymap --sS --evasion ghost 10.0.0.5");
    example("rustymap --sS --stack-profile windows11 --source-port 53 10.0.0.5");
    example("rustymap --sS --scanflags SYN,ECE -f --mtu 8 10.0.0.5");
    example("rustymap --sS --decoys 10.0.0.1,10.0.0.2 --decoy-preping 10.0.0.5");
    example("rustymap --sS --ttl-jitter 8 --rotate-evasion 10.0.0.0/24");

    category("OUTPUT & PERSISTENCE");
    section("OUTPUT");
    line("--oN FILE             Output testuale");
    line("--oG FILE             Output grepable");
    line("--oJ FILE             Output JSON (schema v1)");
    line("--oH FILE             Report HTML");
    line("--oMd FILE            Report Markdown");
    line("--template TPL --oT FILE   Template Tera custom");
    line("-v, -vv               Verbose (mostra anche porte chiuse con -vv)");
    line("--no-color            Disabilita colori");
    example("rustymap --sT --oN scan.txt --oJ scan.json 10.0.0.5");
    example("rustymap --sT --oH report.html 10.0.0.0/24");
    example("rustymap --sT --template my.tera --oT out.txt 10.0.0.5");

    section("DATABASE & DIFF");
    line("--db FILE             Path SQLite (default: rustymap.db)");
    line("--no-db               Disabilita persistenza");
    line("--diff                Mostra diff rispetto alla scansione precedente");
    example("rustymap --sT --db lab.db 10.0.0.5");
    example("rustymap --sT --diff 10.0.0.5");

    section("TAG");
    line("--tag IP[:PORT]=NOME  Aggiunge tag a ip/porta (ripetibile)");
    line("--list-tags           Elenca i tag salvati");
    line("--tag-ip IP           Filtra --list-tags per IP");
    example("rustymap --tag 10.0.0.5=dmz");
    example("rustymap --tag 10.0.0.5:22=prod-ssh");
    example("rustymap --list-tags --tag-ip 10.0.0.5");

    category("DNS & NETWORK INSPECTION");
    section("DNS");
    line("--dns-enum DOMINIO    Brute-force sottodomini (+ NS/MX/TXT/SOA + wildcard-filter)");
    line("--dns-wordlist FILE   Wordlist custom per --dns-enum");
    line("--dns-reverse CIDR    Reverse-DNS sweep (PTR) su un range");
    line("--dns-ct APEX         Subdomain via Certificate Transparency (crt.sh, passivo)");
    line("--takeover-check D    CNAME → 17 dangling-provider fingerprints (S3/Heroku/Azure…)");
    line("--origin-discovery D  Origin-IP dietro CDN: MX + SPF ip4: + sottodomini comuni");
    line("--dns-security D      Audit DNSSEC + CAA + DANE/TLSA + SPF/DMARC qualifiers + MX");
    line("--http-enum           Path enumeration su porte HTTP open dopo lo scan");
    line("--ssl-enum            Enumera TLS 1.0/1.1/1.2/1.3 + cipher su porte TLS open");
    line("--tls-grade           Grade A+/F + DROWN/POODLE/Heartbleed PoC (read-only)");
    line("--ssh-audit           SSH KEX/cipher/host-key/MAC enum (RFC 4253 KEXINIT)");
    line("--smb-audit           SMB dialect + signing (flag SMBv1 + signing-not-required)");
    line("--rdp-audit           RDP X.224 negotiation (flag legacy RDP + missing NLA)");
    line("--smtp-audit          STARTTLS + AUTH mechanisms su 25/465/587");
    line("--auth-audit          Shortcut: ssh + smb + rdp + smtp insieme");
    line("--web-crawl URL       BFS crawler (forms + params + links, robots.txt aware)");
    line("--crawl-depth N       Profondità max del crawl (default 3)");
    line("--crawl-max-urls N    Tetto numero URL (default 200)");
    line("--web-cookie HEADER   Cookie da iniettare (es. \"session=abc; csrf=…\")");
    line("--no-robots           Ignora robots.txt durante --web-crawl");
    line("--owasp-scan URL      Crawl + probe XSS/SQLi/open-redirect/SSRF");
    line("--owasp-checks LIST   Subset: xss,sqli,redirect,ssrf");
    line("--cloud-buckets SEED  Enum public S3/GCS/Azure (~30 permutazioni dal seed)");
    line("--cloud-buckets-limit N  Tetto permutazioni provate (default 30)");
    line("--cloud-metadata      Probe IMDS 169.254.169.254 (AWS/GCP/Azure/OpenStack)");
    line("--cloud-metadata-via URL  Probe IMDS via SSRF prefix sul target");
    line("--cloud-fingerprint D Identifica AWS/GCP/Azure/Cloudflare/Akamai/Fastly da DNS");
    line("--apk-scan FILE       Static APK: manifest perms+components, dex secrets+pinning");
    line("--ipa-scan FILE       Static IPA: Info.plist (ATS, URL schemes), binary secrets");
    line("--compliance FW       Eval findings vs framework: pci-dss|hipaa|nist-800-53|iso-27001|cis");
    line("--compliance-report F Scrive un report Markdown del risultato compliance");
    line("--executive-summary   Stampa narrativa + top services + esposizioni sensibili");
    line("--oP FILE.pdf         Scrive report PDF (printpdf, no system deps)");
    line("--oSvg FILE.svg       Scrive topology SVG self-contained (no Graphviz)");
    line("--diff-against F.json Diff vs un --oJ precedente (no --db needed)");
    line("--wizard              Wizard interattivo che assembla un comando rustymap");
    line("--recommend HOST      Probe rapido + suggerisce i flag più utili");
    line("--save-profile F.toml Salva l'invocation corrente come profilo TOML");
    line("--history [N]         Mostra le ultime N scan (default 20)");
    line("--history-clear       Tronca lo storico delle scansioni");
    line("--siem-format FMT     Output SIEM: cef|leef|ecs|syslog");
    line("--siem-out FILE       File destinazione SIEM events (richiede --siem-format)");
    line("--threat-intel-misp U Sync IoC MISP nel cache locale");
    line("--misp-api-key KEY    API key MISP");
    line("--misp-days N         Giorni di lookback MISP (default 30)");
    line("--threat-intel-match  Confronta target con IoC cached → flag matches");
    line("--ics-scan HOST       ICS/SCADA: Modbus 502, S7 102, DNP3 20000, EnIP 44818, BACnet 47808");
    line("--iot-discover HOST   IoT unicast: mDNS 5353, SSDP 1900, CoAP 5683");
    line("--container-scan HOST Docker (2375/6) + K8s API (6443/8443) + Kubelet (10250/55) + etcd + Consul");
    line("--detect-preview      Anteprima statica: cosa vedrebbe un defender della tua scan");
    line("--delay-jitter PCT    Randomizza ±N% lo --scan-delay (anti-pattern semplici)");
    line("--explain ARGS        Spiega ogni flag dell'invocation in linguaggio piano");
    line("--explain last        Spiega l'ultima scan recorded in --history");
    line("--script-list         Catalogo plugin Rhai (built-in + user) con metadati");
    line("--script-info NAME    Dettaglio metadati di un singolo plugin");
    line("--script-category CAT Filtra per categoria (web|db|ssh|tls|container|smb…)");
    line("--script-tag TAG      Filtra per tag (jwt, no-auth, owasp-aXX…)");
    line("--script-severity SEV Filtra per severity (info|low|medium|high|critical)");
    line("--script-cve CVE-ID   Trova plugin che verificano un CVE specifico");
    line("--script-catalog FILE Esporta tutto il catalogo (.json o .md)");
    line("--notify URL          Webhook su completion (ntfy://topic, slack://hook, https://)");
    line("--progress            Spinner indicatif durante lo scan (elapsed + tipo + N target)");
    line("--dns-sniff           Sniff DNS sulla rete (admin + Npcap)");
    line("--dns-spoof D=IP      Spoof risposte DNS (ripetibile)");
    line("--iface NOME          Interfaccia per sniff/spoof");
    line("-n, --no-dns          Niente risoluzione DNS sui target");
    example("rustymap --dns-enum example.com");
    example("rustymap --dns-reverse 10.0.0.0/24");
    example("rustymap --dns-sniff --iface Ethernet");
    example("rustymap --dns-spoof example.com=10.0.0.5 --iface Ethernet");
    example("rustymap --takeover-check abandoned.example.com");
    example("rustymap --origin-discovery example.com");
    example("rustymap --dns-security example.com");
    example("rustymap --tls-grade --ssl-enum -p 443 example.com");
    example("rustymap --auth-audit -p 22,445,3389,587 10.0.0.5");
    example("rustymap --web-crawl https://target/ --crawl-depth 4");
    example("rustymap --owasp-scan https://target/ --owasp-checks xss,sqli");
    example("rustymap --owasp-scan https://target/ --web-cookie \"session=abc\"");
    example("rustymap --cloud-buckets acme.com");
    example("rustymap --cloud-metadata             # da dentro una VM");
    example("rustymap --cloud-metadata-via 'https://target/?u='");
    example("rustymap --cloud-fingerprint cdn.example.com");
    example("rustymap --apk-scan app-release.apk");
    example("rustymap --ipa-scan MyApp.ipa");
    example("rustymap --auth-audit --tls-grade --compliance pci-dss 10.0.0.5");
    example("rustymap --auth-audit --compliance cis --compliance-report cis.md target");
    example("rustymap --executive-summary --oP report.pdf --oSvg map.svg 10.0.0.0/24");
    example("rustymap --diff-against baseline.json --oJ now.json 10.0.0.0/24");
    example("rustymap --wizard");
    example("rustymap --recommend example.com");
    example("rustymap -sV --auth-audit --save-profile lab.toml 10.0.0.5");
    example("rustymap --history 50");
    example("rustymap --siem-format ecs --siem-out events.jsonl 10.0.0.0/24");
    example("rustymap --siem-format cef --siem-out events.cef --auth-audit 10.0.0.5");
    example("rustymap --threat-intel-misp https://misp.lab.example --misp-api-key XXX");
    example("rustymap --threat-intel-match --auth-audit 10.0.0.0/24");
    example("rustymap --notify discord://discord.com/api/webhooks/...");
    example("rustymap --notify teams://outlook.office.com/webhook/...");
    example("rustymap --notify 'jira://alice:tok@jira.example.com/SEC?type=Bug'");
    example("rustymap --ics-scan 10.0.0.50          # PLC enumeration");
    example("rustymap --iot-discover 192.168.1.42   # camera / hub probe");
    example("rustymap --container-scan node.k8s.lab # Docker/K8s/etcd/Consul");
    example("rustymap --detect-preview --sS -T 5 10.0.0.5  # mostra impatto IDS");
    example("rustymap --scan-delay 500 --delay-jitter 30 10.0.0.0/24");
    example("rustymap --explain '--auth-audit --tls-grade --compliance pci-dss'");
    example("rustymap --explain last        # spiega l'ultima scan dello storico");
    example("rustymap --script-list --script-severity critical");
    example("rustymap --script-cve CVE-2021-44228     # quali plugin verificano Log4Shell?");
    example("rustymap --script-info redis-no-auth");
    example("rustymap --script-catalog catalog.md");

    category("AUTOMATION & TOOLING");
    section("VAULT (credenziali cifrate)");
    line("--vault FILE          Path vault (default rustymap-vault.json)");
    line("--vault-add SPEC      Aggiungi: name=user:secret:kind[:note]");
    line("--vault-list          Elenca entry (chiede password)");
    line("--vault-remove NAME   Rimuovi entry");
    example("rustymap --vault-add ssh=root:pa55w0rd:ssh:lab");
    example("rustymap --vault-list");

    section("PROFILI & SCHEDULAZIONE");
    line("--profile FILE.toml   Carica profilo scan (es. profiles/pci-lite.toml)");
    line("--every SPEC          Ripeti ogni N[s|m|h|d]");
    example("rustymap --profile profiles/pci-lite.toml 10.0.0.0/24");
    example("rustymap --sT --every 1h 10.0.0.5");

    section("WEB UI");
    line("--serve               Avvia dashboard web (legge da --db)");
    line("--serve-addr ADDR     Bind (default 127.0.0.1:8088)");
    example("rustymap --serve");
    example("rustymap --serve --serve-addr 0.0.0.0:9090 --db lab.db");

    category("EXTENSIONS");
    section("SCRIPTING & CVE");
    line("--script PATH         Esegui script Rhai (file o directory *.rhai)");
    line("--cve-db FILE         Correla servizi a CVE (usa con --sV)");
    line("--no-builtin-scripts  Disabilita gli script Rhai baked nel binario");
    line("--no-builtin-cves     Disabilita il DB CVE baked nel binario");
    line("--nmap-os-db FILE     Carica nmap-os-db (GPLv2, parsing runtime, no contamin.)");
    line("--nmap-service-probes FILE  Carica nmap-service-probes (parse `match` lines)");
    line("--examples            Stampa 16 ricette pronte per casi comuni");
    line("--completions SHELL   Genera completion script (bash|zsh|fish|powershell)");
    line("--trace-raw           Logga ogni tx/rx pacchetto raw (debug --sS)");
    line("-d, --debug           Debug log (-d, -dd, -ddd) con tag [net]/[probe]/…");
    line("--script-trace        Trace script Rhai come JSON Lines (pipe in jq)");
    line("--script-args-file F  Carica --script-arg da file (key=val per riga)");
    line("--append-output       Appendi ai file output invece di sovrascrivere");
    line("--max-retries N       Riprova porte filtered fino a N volte (connect)");
    line("-S IP                 Spoof source IP per raw scans (warn se non routable)");
    line("--ip-options SPEC     IPv4 options: record-route|timestamp|lsrr IP,IP|ssrr|hex");
    line("-e, --iface-scan IF   Bind scan a interfaccia (anche per --PR e --spoof-mac)");
    line("--spoof-mac MAC|VEND  Spoofing MAC: indirizzo o vendor (vmware|apple|cisco|random)");
    line("--proxies URLS        Tunnel TCP-connect via SOCKS5/HTTP chain (DNS via proxy)");
    line("--max-scan-delay MS   Cap massimo per --scan-delay");
    line("--ble-scan SECONDI    Scan Bluetooth LE per N secondi (phone/wearable/IoT)");
    line("--iflist [TARGET]     Lista interfacce (con hint route-to-target)");
    line("--script-help         Catalogo script Rhai (built-in + utente)");
    line("                      Script API (active probes):");
    line("                       tcp_send(host, port, payload, timeout_ms) -> str");
    line("                       http_get(url, timeout_ms) -> {status, body, headers}");
    line("--confirm-large       Permette target list > 4096 host");
    example("rustymap --sT --sV --cve-db cves.json 10.0.0.5");
    example("rustymap --sT --script rules/ 10.0.0.5");

    category("MAINTENANCE");
    section("AUDIT & INSTALL");
    line("--audit-log FILE      JSONL con tutte le azioni (timestamped)");
    line("--install-npcap       Installa runtime Npcap (Windows admin)");
    line("--check-update        Controlla se esiste una release più recente");
    line("--update              Scarica e installa l'ultima release da GitHub");
    line("--update-cve-db       Sync NVD JSON 2.0 (last 5y) → ~/.cache/rustymap/nvd.sqlite");
    line("--update-exploit-refs Sync KEV + ExploitDB + Nuclei → exploit_refs.json");
    example("rustymap --sS --audit-log audit.jsonl 10.0.0.5");
    example("rustymap --install-npcap");
    example("rustymap --check-update");
    example("rustymap --update");
    example("rustymap --update-cve-db");
    example("rustymap --update-exploit-refs");

    section("ALTRO");
    line("--help                Help breve (clap)");
    line("--guide               Questa guida estesa");
    line("--version             Versione");

    combined_examples();

    footer();
}

fn banner() {
    let bar = "═══════════════════════════════════════════════════════════════";
    let o = |s: &str| s.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2).bold();
    let a = |s: &str| s.truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2).bold();
    let d = |s: &str| s.truecolor(HL_DIM.0, HL_DIM.1, HL_DIM.2);

    println!("{}", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));
    println!();
    println!("         {}          {}", o("╱╲"), a("R U S T Y M A P"));
    println!("        {}         {}", o("╱  ╲"), d("─ ─ ─ ─ ─ ─ ─ ─"));
    println!("       {}         {}", o("╱ ╱╲ ╲"), a("Guida ai Comandi"));
    println!("      {}", o("╱ ╱  ╲ ╲"));
    println!("     {}", o("╱_╱    ╲_╲"));
    println!();
    println!("{}", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));
    println!(
        "  Uso: {} {}\n",
        "rustymap"
            .truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2)
            .bold(),
        "[OPZIONI] [TARGET...]".truecolor(HL_TEXT.0, HL_TEXT.1, HL_TEXT.2),
    );
}

fn combined_examples() {
    let bar = "───────────────────────────────────────────────────────────────";
    println!("\n{}", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));
    println!(
        "  {}  {}",
        "λ".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2).bold(),
        "ESEMPI COMBINATI"
            .truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2)
            .bold(),
    );
    println!("{}\n", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));

    combo("# Scan discreto Windows-style su subnet",
          "rustymap --sS --stack-profile windows11 --jitter 300 --randomize-ports -t2 10.0.0.0/24");
    combo("# Audit completo con report HTML + CVE",
          "rustymap --sS --sV -O --oH report.html --cve-db cves.json --audit-log audit.jsonl 10.0.0.0/24");
    combo("# Idle scan attraverso uno zombie",
          "rustymap --sI 192.168.1.250:80 -p 1-1000 10.0.0.5");
    combo("# Enumerazione sottodomini con wordlist",
          "rustymap --dns-enum example.com --dns-wordlist big.txt");
    combo("# Scan pianificato con persistenza e diff",
          "rustymap --sT --sV --db lab.db --diff --every 6h 10.0.0.0/24");
}

fn footer() {
    let bar = "═══════════════════════════════════════════════════════════════";
    println!("{}", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));
    println!(
        "  {}  {}",
        "λ".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2).bold(),
        "Rise and shine, Mr. Freeman..."
            .truecolor(HL_DIM.0, HL_DIM.1, HL_DIM.2)
            .italic(),
    );
    println!("{}", bar.truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2));
}

fn toc() {
    println!();
    println!(
        "  {}",
        "INDICE".truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2).bold()
    );
    let entries: &[(&str, &[&str])] = &[
        ("ESSENTIALS", &["TARGET", "PORTE"]),
        ("SCAN", &["TIPI DI SCAN", "HOST DISCOVERY", "TIMING & PERFORMANCE", "SERVICE & OS DETECTION"]),
        ("EVASION & STEALTH", &["EVASIONE FIREWALL / IDS"]),
        ("OUTPUT & PERSISTENCE", &["OUTPUT", "DATABASE & DIFF", "TAG"]),
        ("DNS & NETWORK INSPECTION", &["DNS"]),
        ("AUTOMATION & TOOLING", &["VAULT", "PROFILI & SCHEDULAZIONE", "WEB UI"]),
        ("EXTENSIONS", &["SCRIPTING & CVE"]),
        ("MAINTENANCE", &["AUDIT & INSTALL", "ALTRO"]),
    ];
    for (cat, sects) in entries {
        println!(
            "    {} {}  {}",
            "■".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2),
            cat.truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2).bold(),
            sects.join(" · ").truecolor(HL_DIM.0, HL_DIM.1, HL_DIM.2),
        );
    }
    println!(
        "\n  {}",
        "Tip: rustymap --examples per ricette pronte all'uso"
            .truecolor(HL_DIM.0, HL_DIM.1, HL_DIM.2),
    );
}

fn category(name: &str) {
    println!();
    println!();
    println!(
        "  {}",
        format!("══ {} ══", name)
            .truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2)
            .bold(),
    );
}

fn section(name: &str) {
    println!(
        "\n {} {}",
        "▸".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2).bold(),
        name.truecolor(HL_AMBER.0, HL_AMBER.1, HL_AMBER.2).bold(),
    );
}

fn line(s: &str) {
    println!("   {}", s.truecolor(HL_TEXT.0, HL_TEXT.1, HL_TEXT.2));
}

fn example(cmd: &str) {
    println!(
        "     {} {}",
        "λ".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2),
        cmd.truecolor(HL_YELLOW.0, HL_YELLOW.1, HL_YELLOW.2),
    );
}

fn combo(comment: &str, cmd: &str) {
    println!("  {}", comment.truecolor(HL_DIM.0, HL_DIM.1, HL_DIM.2));
    println!(
        "    {} {}\n",
        "λ".truecolor(HL_ORANGE.0, HL_ORANGE.1, HL_ORANGE.2).bold(),
        cmd.truecolor(HL_YELLOW.0, HL_YELLOW.1, HL_YELLOW.2),
    );
}
