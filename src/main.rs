mod audit;
mod cli;
mod cve;
mod db;
mod device_fp;
mod dns;
mod discovery;
mod evasion;
mod examples;
mod guide;
mod icmp_ping;
mod idle_scan;
mod json_out;
mod net_util;
mod npcap;
mod os_fp;
mod output;
mod ports;
mod profile;
mod privilege;
mod rate;
mod raw_scan;
mod report;
mod scanner;
mod scripting;
mod service_probe;
mod shutdown;
mod syn_emu;
mod target;
mod tls_probe;
mod top_ports;
mod traceroute;
mod tui;
mod udp_scan;
mod updater;
mod vendor_probe;
mod xml_out;
mod vault;
mod webui;
mod win_console;

use anyhow::{anyhow, Result};
use audit::Audit;
use clap::Parser;
use cli::{Cli, ScanType};
use colored::control;
use db::Db;
use futures::stream::{self, StreamExt};
use rate::AdaptiveLimiter;
use raw_scan::{RawTcpKind, RawTcpScanner};
use scanner::{HostResult, PortState};
use serde_json::json;
use shutdown::Cancel;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use udp_scan::UdpScanner;

#[tokio::main]
async fn main() -> Result<()> {
    win_console::init();

    let mut args = Cli::parse();

    // Apply profile overrides BEFORE any command dispatch
    if let Some(profile_path) = args.profile.clone() {
        let p = profile::load(&profile_path)?;
        if let Some(name) = &p.name { eprintln!("[profile] loaded: {}", name); }
        profile::apply(&mut args, &p);
    }

    // -A: nmap-style aggressive shortcut. Implies -sV -O --traceroute, and
    // auto-runs scripts/ if it exists in the cwd or alongside the binary.
    if args.aggressive {
        args.service_version = true;
        args.os_fingerprint = true;
        args.traceroute = true;
        if args.script_path.is_none() {
            for candidate in ["scripts", "/usr/share/rustymap/scripts"] {
                if std::path::Path::new(candidate).is_dir() {
                    args.script_path = Some(candidate.to_string());
                    break;
                }
            }
            if args.script_path.is_none() {
                if let Ok(exe) = std::env::current_exe() {
                    if let Some(dir) = exe.parent() {
                        let p = dir.join("scripts");
                        if p.is_dir() {
                            args.script_path = Some(p.to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    }

    // --max-rate: approximate cap via per-host scan_delay (1000/rate ms).
    if args.max_rate > 0 && args.scan_delay_ms == 0 {
        args.scan_delay_ms = (1000 / args.max_rate).max(1) as u64;
    }

    // -oA: expand into individual output paths if not already set.
    if let Some(prefix) = args.output_all.clone() {
        if args.output_normal.is_none() {
            args.output_normal = Some(format!("{}.txt", prefix));
        }
        if args.output_grepable.is_none() {
            args.output_grepable = Some(format!("{}.gnmap", prefix));
        }
        if args.output_json.is_none() {
            args.output_json = Some(format!("{}.json", prefix));
        }
        if args.output_html.is_none() {
            args.output_html = Some(format!("{}.html", prefix));
        }
        if args.output_markdown.is_none() {
            args.output_markdown = Some(format!("{}.md", prefix));
        }
        if args.output_xml.is_none() {
            args.output_xml = Some(format!("{}.xml", prefix));
        }
    }

    if args.no_color {
        control::set_override(false);
    }

    if args.guide {
        guide::print_guide();
        return Ok(());
    }
    if args.examples {
        examples::print();
        return Ok(());
    }
    if let Some(shell) = args.completions {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    if args.check_update {
        return tokio::task::spawn_blocking(updater::check).await?;
    }
    if args.self_update {
        return tokio::task::spawn_blocking(updater::update).await?;
    }

    let cancel = shutdown::install_handler();
    let audit = Arc::new(Audit::open(args.audit_log.as_deref())?);

    // ----- DNS commands (no scan) -----
    if args.dns_sniff {
        #[cfg(windows)]
        npcap::ensure_available()?;
        let cancel_dns = Arc::clone(&cancel);
        return tokio::task::spawn_blocking(move || {
            dns::dns_sniff(args.iface.as_deref(), cancel_dns)
        }).await?;
    }
    if !args.dns_spoof.is_empty() {
        #[cfg(windows)]
        npcap::ensure_available()?;
        let mut rules = std::collections::HashMap::new();
        for spec in &args.dns_spoof {
            let (domain, ip_s) = spec.split_once('=')
                .ok_or_else(|| anyhow!("--dns-spoof format: domain=ip, got '{}'", spec))?;
            let ip: std::net::Ipv4Addr = ip_s.parse()
                .map_err(|_| anyhow!("invalid IP in --dns-spoof: {}", ip_s))?;
            rules.insert(domain.to_lowercase(), ip);
        }
        let cancel_dns = Arc::clone(&cancel);
        let iface = args.iface.clone();
        return tokio::task::spawn_blocking(move || {
            dns::dns_spoof(iface.as_deref(), &rules, 300, cancel_dns)
        }).await?;
    }
    if let Some(domain) = &args.dns_enum {
        let domain = domain.clone();
        let wordlist = args.dns_wordlist.clone();
        let parallel = args.parallel().min(100);
        let cancel_dns = Arc::clone(&cancel);
        let rep = dns::dns_enum(&domain, wordlist.as_deref(), parallel, cancel_dns).await?;

        println!("\n== DNS enumeration for {} ==", domain);
        if !rep.base_a.is_empty() {
            let ips: Vec<String> = rep.base_a.iter().map(|i| i.to_string()).collect();
            println!("A     : {}", ips.join(", "));
        }
        if !rep.base_aaaa.is_empty() {
            let ips: Vec<String> = rep.base_aaaa.iter().map(|i| i.to_string()).collect();
            println!("AAAA  : {}", ips.join(", "));
        }
        if !rep.ns.is_empty() {
            println!("NS    : {}", rep.ns.join(", "));
        }
        if !rep.mx.is_empty() {
            println!("MX    : {}", rep.mx.join(", "));
        }
        if let Some(soa) = &rep.soa {
            println!("SOA   : {}", soa);
        }
        if !rep.txt.is_empty() {
            for t in &rep.txt {
                println!("TXT   : {}", t);
            }
        }
        if !rep.wildcard_ips.is_empty() {
            let ips: Vec<String> = rep.wildcard_ips.iter().map(|i| i.to_string()).collect();
            println!("WILDCARD filtered: {}", ips.join(", "));
        }

        if rep.subdomains.is_empty() {
            println!("\nNo subdomains found for {}", domain);
        } else {
            println!("\n{:<40} IPs", "SUBDOMAIN");
            for (sub, ips) in &rep.subdomains {
                let ips_s: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
                println!("{:<40} {}", sub, ips_s.join(", "));
            }
            println!("\nFound {} subdomain(s)", rep.subdomains.len());
        }
        return Ok(());
    }
    if let Some(cidr) = &args.dns_reverse {
        let cidr = cidr.clone();
        let parallel = args.parallel().min(100);
        let cancel_dns = Arc::clone(&cancel);
        let found = dns::dns_reverse(&cidr, parallel, cancel_dns).await?;
        if found.is_empty() {
            println!("No PTR records found in {}", cidr);
        } else {
            println!("{:<20} PTR", "IP");
            for (ip, name) in &found {
                println!("{:<20} {}", ip.to_string(), name);
            }
            println!("\nFound {} PTR record(s)", found.len());
        }
        return Ok(());
    }

    // ----- Install Npcap on demand -----
    #[cfg(windows)]
    if args.install_npcap {
        if npcap::is_installed() {
            println!("Npcap is already installed.");
            return Ok(());
        }
        npcap::auto_install(false)?;
        return Ok(());
    }

    // ----- Web UI (no scan) -----
    if args.serve {
        let db_path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
        return tokio::task::spawn_blocking(move || webui::serve(&args.serve_addr, &db_path)).await?;
    }

    // ----- Vault commands (no scan) -----
    if args.vault_list || args.vault_add.is_some() || args.vault_remove.is_some() {
        return run_vault(&args);
    }

    // ----- Pure-DB commands (no scan) -----
    if args.list_tags {
        return run_list_tags(&args);
    }
    if args.list_scans {
        let path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
        let db = Db::open(&path)?;
        let rows = db.list_scans()?;
        if rows.is_empty() {
            println!("No scans recorded in {}", path);
        } else {
            println!(
                "{:<5} {:<25} {:<10} {:<10} {:>10}  TARGET / PORTS",
                "ID", "STARTED", "TYPE", "STATUS", "ELAPSED"
            );
            for (id, started, stype, targets, ports, elapsed, status) in rows {
                println!(
                    "{:<5} {:<25} {:<10} {:<10} {:>9.2}s  {} [{}]",
                    id, started, stype, status, elapsed, targets, ports
                );
            }
        }
        return Ok(());
    }

    if !args.add_tags.is_empty() && args.targets.is_empty() {
        return run_add_tags(&args);
    }

    // -iL: append targets from a file (one per line, # comments allowed).
    if let Some(path) = args.input_list.clone() {
        let body = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("read {}: {}", path, e))?;
        for line in body.lines() {
            let s = line.trim();
            if !s.is_empty() && !s.starts_with('#') {
                args.targets.push(s.to_string());
            }
        }
    }

    // ----- Resume an interrupted scan -----
    let mut resumed_scan_id: Option<i64> = None;
    if let Some(spec) = args.resume.clone() {
        if args.no_db {
            return Err(anyhow!("--resume requires the SQLite db; remove --no-db"));
        }
        let path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
        let db = Db::open(&path)?;
        let sid = if spec == "last" {
            db.latest_incomplete()?
                .ok_or_else(|| anyhow!("no in-progress scan to resume"))?
        } else {
            spec.parse::<i64>()
                .map_err(|_| anyhow!("--resume expects integer or 'last', got '{}'", spec))?
        };
        let (_started, saved_type, target_spec, port_spec, status) = db
            .scan_meta(sid)?
            .ok_or_else(|| anyhow!("scan id {} not found in db", sid))?;
        if status == "complete" {
            return Err(anyhow!("scan #{} is already complete", sid));
        }
        eprintln!(
            "[resume] scan #{} ({}, target={}, ports={})",
            sid, saved_type, target_spec, port_spec
        );
        args.targets = target_spec.split(',').map(|s| s.to_string()).collect();
        args.ports = port_spec;
        apply_scan_type_str(&mut args, &saved_type)?;
        resumed_scan_id = Some(sid);
    }

    if args.targets.is_empty() {
        return Err(anyhow!("no targets specified. Use --help for usage."));
    }

    // ----- Scan pipeline -----
    output::print_banner();

    let scan_type = args.scan_type();
    let needs_privilege = !matches!(scan_type, ScanType::Connect);
    // --sS can degrade to a driver-less SO_LINGER=0 emulation when raw
    // sockets aren't available; explicit opt-in via --syn-emulated bypasses
    // privilege/Npcap checks entirely.
    let syn_emulated_active =
        matches!(scan_type, ScanType::Syn) && (args.syn_emulated || !npcap::is_installed());
    if needs_privilege && !syn_emulated_active {
        if !privilege::is_privileged() {
            return Err(anyhow!(
                "scan type requires elevated privileges. {}",
                privilege::raw_privilege_hint()
            ));
        }
        #[cfg(windows)]
        npcap::ensure_available()?;
    }
    if syn_emulated_active && args.verbose > 0 {
        eprintln!("[sS] using SYN-emulated path (no driver, full handshake + RST close)");
    }

    let scan_type_str = format!("{:?}", scan_type);

    audit.event(
        "scan_start",
        json!({
            "scan_type": &scan_type_str,
            "targets": args.targets,
            "ports": args.effective_ports(),
            "timing": args.timing,
        }),
    );

    let started_at = chrono::Local::now();
    let t_start = Instant::now();

    let mut db_handle = if args.no_db {
        None
    } else {
        let path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
        Some(Db::open(&path)?)
    };

    // 1) Expand targets
    let mut targets = target::expand_targets(&args.targets, !args.no_dns).await?;
    if args.ipv4_only {
        targets.retain(|t| t.ip.is_ipv4());
    } else if args.ipv6_only {
        targets.retain(|t| t.ip.is_ipv6());
    }

    // Exclusions: --exclude (comma-list ok, repeatable) + --exclude-file
    let mut exclude_specs: Vec<String> = Vec::new();
    for spec in &args.exclude {
        for piece in spec.split(',') {
            let s = piece.trim();
            if !s.is_empty() {
                exclude_specs.push(s.to_string());
            }
        }
    }
    if let Some(path) = &args.exclude_file {
        let body = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("read {}: {}", path, e))?;
        for line in body.lines() {
            let s = line.trim();
            if !s.is_empty() && !s.starts_with('#') {
                exclude_specs.push(s.to_string());
            }
        }
    }
    if !exclude_specs.is_empty() {
        let excluded = target::expand_targets(&exclude_specs, false).await?;
        let excluded_ips: std::collections::HashSet<_> =
            excluded.iter().map(|t| t.ip).collect();
        let before = targets.len();
        targets.retain(|t| !excluded_ips.contains(&t.ip));
        if args.verbose > 0 {
            println!("Excluded {} target(s)", before - targets.len());
        }
    }

    // -R: force reverse DNS for each target so output shows hostnames.
    if args.force_reverse_dns && !args.no_dns {
        if let Ok(resolver) =
            hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
        {
            for t in targets.iter_mut() {
                if t.hostname.is_none() {
                    if let Ok(rev) = resolver.reverse_lookup(t.ip).await {
                        if let Some(name) = rev.iter().next() {
                            t.hostname =
                                Some(name.to_string().trim_end_matches('.').to_string());
                        }
                    }
                }
            }
        }
    }

    // --randomize-hosts: shuffle target order
    if args.randomize_hosts {
        use rand::seq::SliceRandom;
        targets.shuffle(&mut rand::thread_rng());
    }

    // Safety rail: require --confirm-large for multi-thousand-host scans.
    // Accidental /16 or hostname-that-returns-many-IPs are the usual cause.
    const LARGE_SCAN_THRESHOLD: usize = 4096;
    if targets.len() > LARGE_SCAN_THRESHOLD && !args.confirm_large {
        return Err(anyhow!(
            "target list has {} hosts — pass --confirm-large to proceed, \
             or narrow the scope with --exclude / --top-ports / smaller CIDR.",
            targets.len()
        ));
    }

    if args.verbose > 0 {
        println!("Expanded {} target(s)", targets.len());
    }

    // Resume: drop targets already persisted under the original scan id.
    if let (Some(sid), Some(db)) = (resumed_scan_id, db_handle.as_ref()) {
        let done = db.completed_hosts(sid)?;
        let before = targets.len();
        targets.retain(|t| !done.contains(&t.ip.to_string()));
        eprintln!(
            "[resume] {}/{} hosts already in db, {} remaining",
            before - targets.len(),
            before,
            targets.len()
        );
    }

    // 2) Host discovery
    if !args.skip_discovery {
        let before = targets.len();
        targets = if args.ping_icmp {
            #[cfg(windows)]
            npcap::ensure_available()?;
            icmp_ping::icmp_discover(targets, args.timeout())?
        } else {
            discovery::discover_hosts(targets, args.timeout(), args.parallel()).await
        };
        if args.verbose > 0 {
            println!("{}/{} hosts responded to ping", targets.len(), before);
        }
    }

    if args.ping_only {
        for t in &targets {
            println!("RustyMap scan report for {}", t.display());
            println!("Host is up.");
        }
        let elapsed = t_start.elapsed().as_secs_f64();
        println!(
            "\nRustyMap done: {} host{} up, scanned in {:.2}s",
            targets.len(),
            if targets.len() == 1 { "" } else { "s" },
            elapsed
        );
        audit.event("scan_end", json!({ "mode": "ping_only", "up": targets.len() }));
        return Ok(());
    }

    // 3) Port scan
    let mut port_vec = if let Some(n) = args.top_ports {
        if n == 0 {
            return Err(anyhow!("--top-ports must be > 0"));
        }
        top_ports::top(n)
    } else {
        ports::parse_ports(&args.effective_ports())?
    };
    if args.randomize_ports {
        use rand::seq::SliceRandom;
        port_vec.shuffle(&mut rand::thread_rng());
        if args.verbose > 0 { println!("Port order randomized"); }
    }
    let port_list = Arc::new(port_vec);
    if args.verbose > 0 {
        println!(
            "Scanning {} port(s) per host using {:?} scan",
            port_list.len(),
            scan_type
        );
    }

    // 4) Begin DB scan record (or reuse the one we are resuming)
    let scan_id: Option<i64> = if let Some(sid) = resumed_scan_id {
        Some(sid)
    } else if let Some(ref mut db) = db_handle {
        Some(db.begin_scan(
            &started_at.to_rfc3339(),
            &scan_type_str,
            &args.targets.join(","),
            &args.effective_ports(),
        )?)
    } else {
        None
    };

    let timeout_dur = args.timeout();
    let parallel = args.parallel();
    let show_closed = args.verbose >= 2 && !args.only_open;

    // --stats-every: spawn a tick that prints elapsed time periodically.
    let stats_handle: Option<(tokio::task::JoinHandle<()>, Arc<std::sync::atomic::AtomicBool>)> =
        if args.stats_every_secs > 0 {
            let interval = std::time::Duration::from_secs(args.stats_every_secs);
            let stop: Arc<std::sync::atomic::AtomicBool> =
                Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_c = Arc::clone(&stop);
            let scan_t = scan_type_str.clone();
            let nhosts = targets.len();
            let scan_started = std::time::Instant::now();
            let h = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if stop_c.load(Ordering::Relaxed) {
                        break;
                    }
                    eprintln!(
                        "[stats] elapsed {:.1}s scanning {} ({} target(s))",
                        scan_started.elapsed().as_secs_f64(),
                        scan_t,
                        nhosts
                    );
                }
            });
            Some((h, stop))
        } else {
            None
        };

    let limiter: Option<Arc<AdaptiveLimiter>> = if args.adaptive {
        let min_p = (parallel / 10).max(4);
        let max_p = parallel * 4;
        let init = parallel.max(min_p).min(max_p);
        let lim = AdaptiveLimiter::new(init, min_p, max_p, args.verbose > 0);
        lim.spawn_adjuster(500);
        if args.verbose > 0 {
            println!("Adaptive rate limiter: start={} min={} max={}", init, min_p, max_p);
        }
        Some(lim)
    } else {
        None
    };

    let results: Vec<HostResult> = match scan_type {
        ScanType::Connect => {
            run_connect(
                targets,
                port_list.clone(),
                timeout_dur,
                parallel,
                show_closed,
                Arc::clone(&cancel),
                limiter.clone(),
                std::time::Duration::from_millis(args.scan_delay_ms),
                std::time::Duration::from_secs(args.host_timeout_secs),
            )
            .await
        }
        ScanType::Syn if syn_emulated_active => {
            run_syn_emu(
                targets,
                port_list.clone(),
                timeout_dur,
                parallel,
                show_closed,
                Arc::clone(&cancel),
                limiter.clone(),
                std::time::Duration::from_millis(args.scan_delay_ms),
            )
            .await
        }
        ScanType::Syn | ScanType::Fin | ScanType::Null | ScanType::Xmas | ScanType::Ack => {
            let kind = match scan_type {
                ScanType::Syn => RawTcpKind::Syn,
                ScanType::Fin => RawTcpKind::Fin,
                ScanType::Null => RawTcpKind::Null,
                ScanType::Xmas => RawTcpKind::Xmas,
                ScanType::Ack => RawTcpKind::Ack,
                _ => unreachable!(),
            };
            let evasion_cfg = build_evasion_config(&args)?;
            if evasion_cfg.is_active() {
                eprintln!("[evasion] {}", evasion_cfg.summary());
            }
            if args.trace_raw {
                raw_scan::set_trace(true);
                eprintln!("[trace-raw] enabled — every tx/rx packet will be logged to stderr");
            }
            let scanner = Arc::new(RawTcpScanner::new(evasion_cfg)?);
            let result = run_raw_tcp(targets, port_list.clone(), kind, scanner, timeout_dur, parallel).await;
            // Post-scan sanity check: if we sent packets but rx_count is 0,
            // the kernel (or a firewall) is silently swallowing responses
            // before they reach our raw socket.
            if cfg!(target_os = "linux") && raw_scan::rx_count() == 0 && !result.is_empty() {
                eprintln!(
                    "[!] raw TCP scanner received zero packets. Common causes on Linux:\n    \
                     - iptables/nftables dropping unsolicited SYN-ACK as INVALID\n    \
                     - conntrack deciding the flow is unknown and dropping replies\n    \
                     - interface has no routable path to the target\n    \
                     Try `sudo iptables -I INPUT -p tcp --tcp-flags ALL SYN,ACK -j ACCEPT`\n    \
                     or fall back to --sT (connect scan)."
                );
            }
            result
        }
        ScanType::Udp => {
            let scanner = Arc::new(UdpScanner::new()?);
            run_udp(targets, port_list.clone(), scanner, timeout_dur, parallel).await
        }
        ScanType::Idle => {
            let spec = args.scan_idle.as_ref().unwrap();
            let (zombie_str, zombie_port) = match spec.rsplit_once(':') {
                Some((ip, port)) => (
                    ip,
                    port.parse::<u16>()
                        .map_err(|_| anyhow!("invalid zombie port in --sI '{}'", spec))?,
                ),
                None => (spec.as_str(), 80u16),
            };
            let zombie_ip: std::net::Ipv4Addr = zombie_str
                .parse()
                .map_err(|_| anyhow!("invalid zombie IP in --sI: {}", zombie_str))?;

            let scanner = Arc::new(idle_scan::IdleScanner::new(zombie_ip)?);

            let src = net_util::source_ipv4_for(zombie_ip)
                .map_err(|e| anyhow!("cannot determine source IP for zombie: {}", e))?;
            if args.verbose > 0 {
                println!("[idle] qualifying zombie {}:{}...", zombie_ip, zombie_port);
            }
            scanner
                .qualify(src, zombie_port, timeout_dur)
                .map_err(|e| anyhow!("zombie unusable: {}", e))?;
            if args.verbose > 0 {
                println!("[idle] zombie OK — starting scan");
            }

            run_idle(targets, port_list.clone(), scanner, zombie_port, timeout_dur).await
        }
    };

    let was_cancelled = cancel.load(Ordering::Relaxed);

    // 4.5) Service/version probing on open ports
    let mut results = results;
    if args.service_version && !was_cancelled {
        if args.verbose > 0 { println!("Probing services on open ports..."); }
        probe_services(&mut results, timeout_dur).await;
    }

    // 4.6) OS fingerprinting
    if args.os_fingerprint && !was_cancelled {
        if args.verbose > 0 { println!("Fingerprinting OS..."); }
        for h in results.iter_mut() {
            if h.up {
                h.os = Some(os_fp::fingerprint(h, timeout_dur));
            }
        }
    }

    // 4.7) Device classification (free — uses existing ports/banners/OS hint)
    if !was_cancelled {
        for h in results.iter_mut() {
            if h.up {
                let guess = device_fp::classify(h, h.mac.as_ref());
                if guess.class != device_fp::DeviceClass::Unknown || guess.vendor.is_some() {
                    h.device = Some(guess);
                }
            }
        }
    }

    // 4.8) Deep vendor probe: HTTP GET on any open HTTP-ish port, extract
    // title/Server header and match against per-vendor model/firmware
    // patterns. Active (one TCP connect + GET per host), so gated by
    // --sV to keep the default scan fast.
    if !was_cancelled && args.service_version {
        let probe_t = timeout_dur.min(std::time::Duration::from_secs(3));
        for h in results.iter_mut() {
            if !h.up { continue; }
            let open_ports: Vec<u16> = h
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| p.port)
                .collect();
            if open_ports.is_empty() { continue; }
            if let Some(hint) = vendor_probe::probe(h.target.ip, &open_ports, probe_t).await {
                let dev = h.device.get_or_insert(device_fp::DeviceGuess {
                    class: device_fp::DeviceClass::Unknown,
                    confidence: 0,
                    vendor: None,
                    model: None,
                    firmware: None,
                    hints: Vec::new(),
                });
                if let Some(v) = hint.vendor { dev.vendor.get_or_insert(v); }
                if let Some(m) = hint.model { dev.model.get_or_insert(m); }
                if let Some(f) = hint.firmware { dev.firmware.get_or_insert(f); }
                if let Some(t) = hint.title { dev.hints.push(format!("title: {}", t)); }
                if let Some(s) = hint.server { dev.hints.push(format!("Server: {}", s)); }
            }
        }
    }

    // 5) Output
    let mut sorted = results;
    sorted.sort_by_key(|h| h.target.ip);
    for h in &sorted {
        let mut h_view = h.clone();
        if args.only_open {
            h_view.ports.retain(|p| p.state == PortState::Open);
        }
        output::print_host_with_reason(&h_view, args.verbose, &scan_type_str, args.reason);
    }

    let elapsed = t_start.elapsed().as_secs_f64();
    if let Some((handle, stop)) = stats_handle {
        stop.store(true, Ordering::Relaxed);
        handle.abort();
        let _ = handle.await;
    }
    output::print_summary(&sorted, elapsed);

    // CVE correlation (requires -sV to have populated service info).
    // Use --cve-db when given, otherwise fall back to the built-in DB
    // unless the user opts out with --no-builtin-cves.
    {
        let db = if let Some(path) = &args.cve_db {
            match cve::load_db(path) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("[!] CVE DB error: {}", e);
                    None
                }
            }
        } else if !args.no_builtin_cves {
            Some(cve::builtin_db())
        } else {
            None
        };
        if let Some(d) = db {
            let hits = cve::correlate(&d, &sorted);
            cve::print_hits(&hits);
            audit.event("cve_correlated", json!({ "hits": hits.len() }));
        }
    }

    // Traceroute + topology
    if args.traceroute {
        let mut traces = Vec::new();
        println!("\n-- Traceroute --");
        for h in sorted.iter().filter(|h| h.up) {
            match traceroute::trace(&h.target, args.trace_hops).await {
                Ok(tr) => {
                    println!("{}:", h.target.display());
                    for hop in &tr.hops {
                        match hop.ip {
                            Some(ip) => println!("  {:>2}  {}", hop.ttl, ip),
                            None => println!("  {:>2}  *", hop.ttl),
                        }
                    }
                    traces.push(tr);
                }
                Err(e) => eprintln!("[!] traceroute {}: {}", h.target.display(), e),
            }
        }
        if let Some(path) = &args.topology {
            let dot = traceroute::render_dot(&traces);
            if let Err(e) = std::fs::write(path, dot) {
                eprintln!("[!] failed to write topology to {}: {}", path, e);
            } else {
                println!("[topology] wrote {} (render with: dot -Tpng {} -o topology.png)", path, path);
            }
        }
        audit.event("traceroute", json!({ "hosts": traces.len() }));
    }

    // Run Rhai scripts: explicit --script first, then built-in scripts
    // (unless the user passed --no-builtin-scripts).
    let parsed_args: Vec<(String, String)> = args
        .script_args
        .iter()
        .filter_map(|spec| {
            spec.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    if !args.no_builtin_scripts && args.script_path.is_none() {
        let scripts = scripting::builtin_scripts();
        let f = scripting::run_inline(&scripts, &sorted, &parsed_args);
        scripting::print_findings(&f);
        if !f.is_empty() {
            audit.event("scripts_builtin_run", json!({ "count": f.len() }));
        }
    }
    if let Some(sp) = &args.script_path {
        match scripting::run_scripts(sp, &sorted, &parsed_args) {
            Ok(f) => {
                scripting::print_findings(&f);
                audit.event("scripts_run", json!({ "count": f.len() }));
            }
            Err(e) => {
                eprintln!("[!] script error: {}", e);
            }
        }
    }

    // 6) Persist to DB and run diff
    let mut diffs: std::collections::HashMap<String, db::PortDiff> = std::collections::HashMap::new();
    if let (Some(ref mut db), Some(sid)) = (db_handle.as_mut(), scan_id) {
        for h in &sorted {
            db.insert_host(sid, h)?;
        }
        let status = if was_cancelled { "aborted" } else { "complete" };
        db.finalize_scan(sid, elapsed, status)?;
        audit.event("db_persisted", json!({ "scan_id": sid, "status": status }));

        // Always compute diffs when a previous scan exists — reports use them
        // regardless of whether --diff was passed for stdout printing.
        for h in &sorted {
            let state: Vec<(u16, PortState)> =
                h.ports.iter().map(|p| (p.port, p.state)).collect();
            if let Some(d) = db::diff_host_vs_previous(db, sid, &h.target.ip.to_string(), &state)? {
                diffs.insert(h.target.ip.to_string(), d);
            }
        }
        if args.show_diff && !diffs.is_empty() {
            println!("\n-- Diff vs previous scan --");
            for h in &sorted {
                if let Some(d) = diffs.get(&h.target.ip.to_string()) {
                    print_diff(&h.target.display(), d);
                }
            }
        }
    }

    // 7) Files out
    if let Some(p) = &args.output_normal {
        output::write_normal(p, &sorted, elapsed)?;
    }
    if let Some(p) = &args.output_grepable {
        output::write_grepable(p, &sorted)?;
    }
    if let Some(p) = &args.output_json {
        let json = json_out::to_json_string(&sorted, &scan_type_str, started_at, elapsed)?;
        json_out::write_json(p, &json)?;
    }
    if let Some(p) = &args.output_html {
        report::write_html(p, &sorted, &scan_type_str, started_at, elapsed, &diffs)?;
    }
    if let Some(p) = &args.output_xml {
        let args_line: String = std::env::args().collect::<Vec<_>>().join(" ");
        xml_out::write_xml(p, &sorted, &scan_type_str, started_at, elapsed, &args_line)?;
    }
    if let Some(p) = &args.output_markdown {
        report::write_markdown(p, &sorted, &scan_type_str, started_at, elapsed, &diffs)?;
    }
    if let (Some(tpl), Some(out)) = (&args.template_path, &args.output_template) {
        report::write_custom(tpl, out, &sorted, &scan_type_str, started_at, elapsed, &diffs)?;
    } else if args.template_path.is_some() ^ args.output_template.is_some() {
        return Err(anyhow!("--template and --oT must be used together"));
    }

    audit.event(
        "scan_end",
        json!({
            "hosts_total": sorted.len(),
            "hosts_up": sorted.iter().filter(|h| h.up).count(),
            "elapsed_secs": elapsed,
            "cancelled": was_cancelled,
        }),
    );

    if args.tui {
        if let Err(e) = tui::run(&sorted) {
            eprintln!("[!] TUI error: {}", e);
        }
    }

    if was_cancelled {
        eprintln!("[!] Scan aborted; partial results saved.");
        std::process::exit(130);
    }

    // Scheduling mode: re-exec self with same args after the configured interval.
    if let Some(spec) = &args.every {
        let dur = profile::parse_duration(spec)
            .ok_or_else(|| anyhow!("invalid --every spec '{}' (use e.g. 30s, 5m, 1h)", spec))?;
        eprintln!("[schedule] next run in {:?}", dur);
        tokio::time::sleep(dur).await;
        let exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(exe);
        cmd.args(std::env::args().skip(1));
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(0));
    }

    Ok(())
}

fn print_diff(host_disp: &str, d: &db::PortDiff) {
    if d.new_open.is_empty() && d.closed_now.is_empty() && d.state_changes.is_empty() {
        return;
    }
    println!("{}", host_disp);
    for p in &d.new_open {
        println!("  + {}/tcp now open", p);
    }
    for p in &d.closed_now {
        println!("  - {}/tcp no longer open", p);
    }
    for (p, old, new) in &d.state_changes {
        println!("  ~ {}/tcp {} -> {}", p, old, new);
    }
}

fn run_vault(args: &Cli) -> Result<()> {
    let path = std::path::PathBuf::from(&args.vault_path);
    let pw = if let Ok(p) = std::env::var("RUSTYMAP_VAULT_PW") {
        p
    } else {
        rpassword::prompt_password("Vault password: ")
            .map_err(|e| anyhow!("password: {}", e))?
    };

    if let Some(spec) = &args.vault_add {
        let (name, rest) = spec.split_once('=').ok_or_else(|| anyhow!("format: name=user:secret:kind[:note]"))?;
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 3 { return Err(anyhow!("need user:secret:kind[:note]")); }
        let entry = vault::VaultEntry {
            username: parts[0].to_string(),
            secret: parts[1].to_string(),
            kind: parts[2].to_string(),
            note: parts.get(3).map(|s| s.to_string()),
        };
        vault::add(&path, &pw, name, entry)?;
        println!("+ added credential '{}'", name);
        return Ok(());
    }
    if let Some(name) = &args.vault_remove {
        let was = vault::remove(&path, &pw, name)?;
        println!("{}removed '{}'", if was { "" } else { "(not found) " }, name);
        return Ok(());
    }
    if args.vault_list {
        let rows = vault::list(&path, &pw)?;
        if rows.is_empty() { println!("(vault empty)"); return Ok(()); }
        println!("{:<20} {:<18} {:<10} NOTE", "NAME", "USERNAME", "KIND");
        for (n, e) in rows {
            println!("{:<20} {:<18} {:<10} {}", n, e.username, e.kind, e.note.unwrap_or_default());
        }
        return Ok(());
    }
    Ok(())
}

fn run_add_tags(args: &Cli) -> Result<()> {
    let path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
    let mut db = Db::open(&path)?;
    for spec in &args.add_tags {
        let (loc, tag) = spec.split_once('=').ok_or_else(|| anyhow!("--tag format: ip[:port]=tagname, got '{}'", spec))?;
        let (ip, port) = if let Some((ip, port)) = loc.rsplit_once(':') {
            (ip.to_string(), Some(port.parse::<u16>()?))
        } else {
            (loc.to_string(), None)
        };
        db.add_tag(&ip, port, tag, None)?;
        println!("+ tag {} = {} on {}{}", tag, loc, ip, port.map(|p| format!(":{}", p)).unwrap_or_default());
    }
    Ok(())
}

fn run_list_tags(args: &Cli) -> Result<()> {
    let path = args.db_path.clone().unwrap_or_else(|| "rustymap.db".to_string());
    let db = Db::open(&path)?;
    let rows = db.list_tags(args.tag_ip.as_deref())?;
    if rows.is_empty() {
        println!("(no tags)");
        return Ok(());
    }
    println!("{:<18} {:<8} {:<20} {:<25} NOTE", "IP", "PORT", "TAG", "CREATED");
    for (ip, port, tag, note, created) in rows {
        let port_s = port.map(|p| p.to_string()).unwrap_or_default();
        println!(
            "{:<18} {:<8} {:<20} {:<25} {}",
            ip,
            port_s,
            tag,
            created,
            note.unwrap_or_default()
        );
    }
    Ok(())
}

async fn probe_services(hosts: &mut [HostResult], timeout_dur: std::time::Duration) {
    use futures::stream::{self, StreamExt};
    // Use a shorter timeout for banner probing (at most 3s, or scan timeout if lower)
    let probe_timeout = timeout_dur.min(std::time::Duration::from_secs(3));
    for h in hosts.iter_mut() {
        if !h.up { continue; }
        let ip = h.target.ip;
        let hostname = h.target.hostname.clone();
        let open_idx: Vec<usize> = h.ports.iter().enumerate()
            .filter(|(_, p)| p.state == PortState::Open)
            .map(|(i, _)| i).collect();
        let concurrency = open_idx.len().clamp(4, 32);
        let infos: Vec<(usize, Option<service_probe::ServiceInfo>)> = stream::iter(open_idx.into_iter())
            .map(|i| {
                let port = h.ports[i].port;
                let host = hostname.clone();
                async move { (i, service_probe::probe(ip, port, probe_timeout, host.as_deref()).await) }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        for (i, info) in infos {
            h.ports[i].service = info;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_connect(
    targets: Vec<target::Target>,
    ports: Arc<Vec<u16>>,
    timeout_dur: std::time::Duration,
    parallel: usize,
    show_closed: bool,
    cancel: Cancel,
    limiter: Option<Arc<AdaptiveLimiter>>,
    scan_delay: std::time::Duration,
    host_timeout: std::time::Duration,
) -> Vec<HostResult> {
    let host_concurrency = match targets.len() {
        0..=1 => 1,
        2..=10 => 4,
        11..=50 => 8,
        _ => 16,
    };
    stream::iter(targets.into_iter())
        .map(|t| {
            let ports = Arc::clone(&ports);
            let cancel = Arc::clone(&cancel);
            let limiter = limiter.clone();
            async move {
                let target_clone = t.clone();
                let fut = scanner::tcp_connect_scan(t, ports, timeout_dur, parallel, show_closed, cancel, limiter, scan_delay);
                if host_timeout.is_zero() {
                    fut.await
                } else {
                    match tokio::time::timeout(host_timeout, fut).await {
                        Ok(r) => r,
                        Err(_) => HostResult {
                            target: target_clone,
                            up: false,
                            ports: vec![],
                            elapsed: host_timeout,
                            os: None,
                            device: None,
                            mac: None,
                        },
                    }
                }
            }
        })
        .buffer_unordered(host_concurrency)
        .collect()
        .await
}

#[allow(clippy::too_many_arguments)]
async fn run_syn_emu(
    targets: Vec<target::Target>,
    ports: Arc<Vec<u16>>,
    timeout_dur: std::time::Duration,
    parallel: usize,
    show_closed: bool,
    cancel: Cancel,
    limiter: Option<Arc<AdaptiveLimiter>>,
    scan_delay: std::time::Duration,
) -> Vec<HostResult> {
    let host_concurrency = match targets.len() {
        0..=1 => 1,
        2..=10 => 4,
        11..=50 => 8,
        _ => 16,
    };
    stream::iter(targets.into_iter())
        .map(|t| {
            let ports = Arc::clone(&ports);
            let cancel = Arc::clone(&cancel);
            let limiter = limiter.clone();
            async move {
                syn_emu::run_syn_emulated(
                    t,
                    ports,
                    timeout_dur,
                    parallel,
                    show_closed,
                    cancel,
                    limiter,
                    scan_delay,
                )
                .await
            }
        })
        .buffer_unordered(host_concurrency)
        .collect()
        .await
}

async fn run_raw_tcp(
    targets: Vec<target::Target>,
    ports: Arc<Vec<u16>>,
    kind: RawTcpKind,
    scanner_arc: Arc<RawTcpScanner>,
    timeout_dur: std::time::Duration,
    parallel: usize,
) -> Vec<HostResult> {
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let ports = Arc::clone(&ports);
        let scanner_arc = Arc::clone(&scanner_arc);
        let r = tokio::task::spawn_blocking(move || {
            raw_scan::run_raw_tcp_scan(t, ports, kind, scanner_arc, timeout_dur, parallel)
        })
        .await
        .expect("scan thread panicked");
        out.push(r);
    }
    out
}

async fn run_idle(
    targets: Vec<target::Target>,
    ports: Arc<Vec<u16>>,
    scanner_arc: Arc<idle_scan::IdleScanner>,
    zombie_port: u16,
    timeout_dur: std::time::Duration,
) -> Vec<HostResult> {
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let ports = Arc::clone(&ports);
        let scanner_arc = Arc::clone(&scanner_arc);
        let r = tokio::task::spawn_blocking(move || {
            idle_scan::run_idle_scan(t, ports, scanner_arc, zombie_port, timeout_dur)
        })
        .await
        .expect("scan thread panicked");
        out.push(r);
    }
    out
}

async fn run_udp(
    targets: Vec<target::Target>,
    ports: Arc<Vec<u16>>,
    scanner_arc: Arc<UdpScanner>,
    timeout_dur: std::time::Duration,
    parallel: usize,
) -> Vec<HostResult> {
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let ports = Arc::clone(&ports);
        let scanner_arc = Arc::clone(&scanner_arc);
        let r = tokio::task::spawn_blocking(move || {
            udp_scan::run_udp_scan(t, ports, scanner_arc, timeout_dur, parallel)
        })
        .await
        .expect("scan thread panicked");
        out.push(r);
    }
    out
}

fn apply_scan_type_str(args: &mut Cli, s: &str) -> Result<()> {
    args.scan_connect = false;
    args.scan_syn = false;
    args.scan_fin = false;
    args.scan_null = false;
    args.scan_xmas = false;
    args.scan_ack = false;
    args.scan_udp = false;
    match s {
        "Connect" => args.scan_connect = true,
        "Syn" => args.scan_syn = true,
        "Fin" => args.scan_fin = true,
        "Null" => args.scan_null = true,
        "Xmas" => args.scan_xmas = true,
        "Ack" => args.scan_ack = true,
        "Udp" => args.scan_udp = true,
        "Idle" => return Err(anyhow!("--resume not supported for Idle scans")),
        other => return Err(anyhow!("unknown saved scan_type '{}'", other)),
    }
    Ok(())
}

fn build_evasion_config(args: &Cli) -> Result<evasion::EvasionConfig> {
    // Start from preset if provided, else default.
    let mut cfg = if let Some(name) = &args.evasion_preset {
        let preset = evasion::EvasionPreset::from_name(name)
            .ok_or_else(|| anyhow!("unknown --evasion preset '{}' (stealth|aggressive|paranoid|ghost)", name))?;
        preset.to_config()
    } else {
        evasion::EvasionConfig::default()
    };

    // Explicit CLI flags override preset fields.
    if args.source_port.is_some() {
        cfg.source_port = args.source_port;
    }
    if let Some(ref d) = args.decoys {
        cfg.decoys = d
            .split(',')
            .map(|s| s.trim().parse::<std::net::Ipv4Addr>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("invalid decoy IP: {}", e))?;
    }
    if let Some(ttl) = args.ip_ttl {
        cfg.ip_ttl = ttl;
    }
    if args.data_length > 0 {
        cfg.data_length = args.data_length;
    }
    if args.decoy_random > 0 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..args.decoy_random {
            // Random non-private RFC 6890 unicast IP, avoiding 10/8, 172.16/12,
            // 192.168/16, 127/8, 0/8, 224/4, 240/4 to look like an external decoy.
            loop {
                let a: u8 = rng.gen_range(1..=223);
                if matches!(a, 0 | 10 | 127 | 169 | 172 | 192 | 224..=255) {
                    continue;
                }
                let b: u8 = rng.gen();
                let c: u8 = rng.gen();
                let d: u8 = rng.gen_range(1..=254);
                cfg.decoys.push(std::net::Ipv4Addr::new(a, b, c, d));
                break;
            }
        }
    }
    if let Some(s) = &args.data_string {
        cfg.data_payload = s.as_bytes().to_vec();
    }
    if let Some(h) = &args.data_hex {
        let cleaned: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        if !cleaned.len().is_multiple_of(2) {
            return Err(anyhow!("--data-hex needs an even number of hex digits"));
        }
        let mut bytes = Vec::with_capacity(cleaned.len() / 2);
        for i in (0..cleaned.len()).step_by(2) {
            bytes.push(
                u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .map_err(|_| anyhow!("invalid hex byte at {}", i))?,
            );
        }
        cfg.data_payload = bytes;
    }
    if args.fragment {
        cfg.fragment = true;
    }
    if let Some(mtu) = args.mtu {
        cfg.frag_mtu = mtu;
    }
    if args.bad_checksum {
        cfg.bad_checksum = true;
    }
    if let Some(ref name) = args.stack_profile {
        let sp = evasion::StackProfile::from_name(name).ok_or_else(|| {
            anyhow!("unknown --stack-profile '{}' (windows11|linux6|macos|freebsd|android14)", name)
        })?;
        cfg.stack_profile = sp;
        // Inherit stack's TTL if user didn't explicitly override --ip-ttl
        if args.ip_ttl.is_none() {
            cfg.ip_ttl = sp.ttl();
        }
    }
    if args.jitter_ms > 0 {
        cfg.jitter = evasion::JitterMode::Gaussian(args.jitter_ms);
    }
    if args.rotate_evasion {
        cfg.rotate = true;
    }
    if args.frag_overlap {
        cfg.frag_overlap = true;
        cfg.fragment = true; // overlap implies fragmentation
    }
    if let Some(ref s) = args.scanflags {
        let flags = evasion::parse_scanflags(s).map_err(|e| anyhow!("--scanflags: {}", e))?;
        cfg.custom_flags = Some(flags);
    }
    if args.ttl_jitter > 0 {
        cfg.ttl_jitter = args.ttl_jitter;
    }
    if args.decoy_preping {
        cfg.decoy_preping = true;
    }

    Ok(cfg)
}
