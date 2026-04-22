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

    section("TARGET");
    line("<TARGET>              IP, hostname, CIDR, range o più target separati");
    example("rustymap 192.168.1.1");
    example("rustymap example.com");
    example("rustymap 10.0.0.0/24");
    example("rustymap 10.0.0.1-50 192.168.1.1");

    section("PORTE");
    line("-p, --ports SPEC      Porte da scansionare (default: 1-1000)");
    line("--all-ports           Alias per -p-");
    example("rustymap -p 22 10.0.0.5");
    example("rustymap -p 22,80,443 10.0.0.5");
    example("rustymap -p 1-1000 10.0.0.5");
    example("rustymap -p - 10.0.0.5              # tutte le 65535");

    section("TIPI DI SCAN");
    line("--sT                  TCP connect (3-way handshake, no privilegi)");
    line("--sS                  TCP SYN half-open (admin + Npcap; auto-fallback driver-less)");
    line("--syn-emulated        Forza --sS senza driver (SO_LINGER=0, no admin)");
    line("--sF                  TCP FIN scan");
    line("--sN                  TCP NULL scan (nessun flag)");
    line("--sX                  TCP Xmas scan (FIN+PSH+URG)");
    line("--sA                  TCP ACK scan (mapping firewall)");
    line("--sU                  UDP scan");
    line("--sI ZOMBIE[:PORT]    Idle/zombie scan (spoof via host con IPID incrementale)");
    example("rustymap --sT 10.0.0.5");
    example("rustymap --sS -p 1-65535 10.0.0.5");
    example("rustymap --sU -p 53,123,161 10.0.0.5");
    example("rustymap --sI 192.168.1.100:80 10.0.0.5");

    section("HOST DISCOVERY");
    line("-Pn                   Salta discovery (tratta tutti i host come up)");
    line("--sn                  Solo ping, niente port scan");
    line("--PE                  ICMP echo ping (raw, admin)");
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
    line("-O, --os              Fingerprinting OS (TTL + porte/banner)");
    line("                      (device-class auto: router/camera/printer/NAS/IoT…)");
    example("rustymap --sT --sV 10.0.0.5");
    example("rustymap --sS --sV -O 10.0.0.5");

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

    section("DNS");
    line("--dns-enum DOMINIO    Brute-force sottodomini (+ NS/MX/TXT/SOA + wildcard-filter)");
    line("--dns-wordlist FILE   Wordlist custom per --dns-enum");
    line("--dns-reverse CIDR    Reverse-DNS sweep (PTR) su un range");
    line("--dns-sniff           Sniff DNS sulla rete (admin + Npcap)");
    line("--dns-spoof D=IP      Spoof risposte DNS (ripetibile)");
    line("--iface NOME          Interfaccia per sniff/spoof");
    line("-n, --no-dns          Niente risoluzione DNS sui target");
    example("rustymap --dns-enum example.com");
    example("rustymap --dns-reverse 10.0.0.0/24");
    example("rustymap --dns-sniff --iface Ethernet");
    example("rustymap --dns-spoof example.com=10.0.0.5 --iface Ethernet");

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

    section("SCRIPTING & CVE");
    line("--script PATH         Esegui script Rhai (file o directory *.rhai)");
    line("--cve-db FILE         Correla servizi a CVE (usa con --sV)");
    example("rustymap --sT --sV --cve-db cves.json 10.0.0.5");
    example("rustymap --sT --script rules/ 10.0.0.5");

    section("AUDIT & INSTALL");
    line("--audit-log FILE      JSONL con tutte le azioni (timestamped)");
    line("--install-npcap       Installa runtime Npcap (Windows admin)");
    line("--check-update        Controlla se esiste una release più recente");
    line("--update              Scarica e installa l'ultima release da GitHub");
    example("rustymap --sS --audit-log audit.jsonl 10.0.0.5");
    example("rustymap --install-npcap");
    example("rustymap --check-update");
    example("rustymap --update");

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
