//! Curated recipes printed by `--examples`.
//!
//! Copy-paste starting points for common pentest/recon tasks. Chosen to
//! showcase the flag combinations that are worth remembering, not every
//! flag — the full reference lives in --guide.

use colored::*;

struct Recipe {
    title: &'static str,
    why: &'static str,
    cmd: &'static str,
}

const RECIPES: &[Recipe] = &[
    Recipe {
        title: "Quick recon of a host",
        why: "Top 100 ports, service versioning, TLS, device class — a 3s overview.",
        cmd: "rustymap --top-ports 100 --sV target.example.com",
    },
    Recipe {
        title: "Aggressive audit with everything on",
        why: "-A = -sV -O --traceroute, auto-runs built-in scripts, CVE correlation.",
        cmd: "rustymap -A --oA audit-$(date +%F) target.example.com",
    },
    Recipe {
        title: "Stealth SYN scan with ghost evasion",
        why: "Real SYN half-open, bad-checksum + fragmentation + TTL jitter + decoys.",
        cmd: "rustymap --sS --evasion ghost --decoy-random 5 target.example.com",
    },
    Recipe {
        title: "Internal /24 with fast timing and device classification",
        why: "8s total on a home LAN, flags routers/cameras/printers automatically.",
        cmd: "rustymap -T4 --sT --top-ports 200 -O 10.0.0.0/24",
    },
    Recipe {
        title: "Diff against last scan (drift detection)",
        why: "Persists to SQLite, prints + embeds delta in the HTML report.",
        cmd: "rustymap --sT -p 1-1024 --diff --oH report.html 10.0.0.0/24",
    },
    Recipe {
        title: "Resume an interrupted big scan",
        why: "Skips hosts already in the db, continues under the same scan id.",
        cmd: "rustymap --resume last",
    },
    Recipe {
        title: "UDP scan of top DNS/NTP/SNMP ports",
        why: "Admin/root required for ICMP unreach parsing.",
        cmd: "rustymap --sU -p 53,67,123,161,500,514,5353 10.0.0.0/24",
    },
    Recipe {
        title: "DNS enumeration with wildcard detection",
        why: "Base A/AAAA/MX/NS/TXT/SOA + brute-force subdomains.",
        cmd: "rustymap --dns-enum example.com",
    },
    Recipe {
        title: "Reverse-DNS sweep of a subnet",
        why: "Finds named assets without touching the hosts themselves.",
        cmd: "rustymap --dns-reverse 10.0.0.0/24",
    },
    Recipe {
        title: "Nmap-compatible XML export for msf/zenmap",
        why: "Subset of xmloutputversion=1.05 the common tools parse.",
        cmd: "rustymap --sV -p 22,80,443 --oX scan.xml target.example.com",
    },
    Recipe {
        title: "Read targets from a file",
        why: "One per line, # comments ok — pairs well with a cron job.",
        cmd: "rustymap --iL hosts.txt --sT --top-ports 50",
    },
    Recipe {
        title: "Launch the web dashboard on the persisted db",
        why: "Browse scans history, search by id/type/target from the browser.",
        cmd: "rustymap --serve --serve-addr 127.0.0.1:8088 --db lab.db",
    },
    Recipe {
        title: "Post-scan TUI browser",
        why: "Two-pane ratatui UI for walking through large host sets.",
        cmd: "rustymap --sT --sV -p- --tui 10.0.0.0/24",
    },
    Recipe {
        title: "Traceroute + Graphviz topology",
        why: "Renderable with `dot -Tpng topo.dot -o topo.png`.",
        cmd: "rustymap --sT --traceroute --topology topo.dot 10.0.0.0/24",
    },
    Recipe {
        title: "Idle (zombie) scan via a third-party host",
        why: "Spoofs the probe source. Needs a host with predictable IP IDs.",
        cmd: "rustymap --sI 192.168.1.250:80 -p 1-1024 10.0.0.5",
    },
    Recipe {
        title: "One-shot self-update",
        why: "Pulls the latest GitHub release and replaces the current binary.",
        cmd: "rustymap --update",
    },
];

pub fn print() {
    println!("{}", "RustyMap — recipe book".bold().cyan());
    println!();
    for (i, r) in RECIPES.iter().enumerate() {
        println!("{} {}", format!("{}.", i + 1).dimmed(), r.title.bold());
        println!("   {}", r.why);
        println!("   $ {}", r.cmd.green());
        println!();
    }
    println!(
        "{}",
        "More flags: rustymap --guide  ·  full help: rustymap --help".dimmed()
    );
}
