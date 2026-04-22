mod audit;
mod cli;
mod cve;
mod db;
mod device_fp;
mod dns;
mod discovery;
mod evasion;
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
mod udp_scan;
mod updater;
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

    if args.no_color {
        control::set_override(false);
    }

    if args.guide {
        guide::print_guide();
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

    if !args.add_tags.is_empty() && args.targets.is_empty() {
        return run_add_tags(&args);
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
    if args.verbose > 0 {
        println!("Expanded {} target(s)", targets.len());
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
    let mut port_vec = ports::parse_ports(&args.effective_ports())?;
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

    // 4) Begin DB scan record
    let scan_id: Option<i64> = if let Some(ref mut db) = db_handle {
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
    let show_closed = args.verbose >= 2;

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
            let scanner = Arc::new(RawTcpScanner::new(evasion_cfg)?);
            run_raw_tcp(targets, port_list.clone(), kind, scanner, timeout_dur, parallel).await
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

    // 5) Output
    let mut sorted = results;
    sorted.sort_by_key(|h| h.target.ip);
    for h in &sorted {
        output::print_host(h, args.verbose);
    }

    let elapsed = t_start.elapsed().as_secs_f64();
    output::print_summary(&sorted, elapsed);

    // CVE correlation (requires -sV to have populated service info)
    if let Some(path) = &args.cve_db {
        match cve::load_db(path) {
            Ok(db) => {
                let hits = cve::correlate(&db, &sorted);
                cve::print_hits(&hits);
                audit.event("cve_correlated", json!({ "hits": hits.len() }));
            }
            Err(e) => eprintln!("[!] CVE DB error: {}", e),
        }
    }

    // Run Rhai scripts if requested
    if let Some(sp) = &args.script_path {
        match scripting::run_scripts(sp, &sorted) {
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
    if let (Some(ref mut db), Some(sid)) = (db_handle.as_mut(), scan_id) {
        for h in &sorted {
            db.insert_host(sid, h)?;
        }
        let status = if was_cancelled { "aborted" } else { "complete" };
        db.finalize_scan(sid, elapsed, status)?;
        audit.event("db_persisted", json!({ "scan_id": sid, "status": status }));

        if args.show_diff {
            println!("\n-- Diff vs previous scan --");
            for h in &sorted {
                let state: Vec<(u16, PortState)> =
                    h.ports.iter().map(|p| (p.port, p.state)).collect();
                if let Some(d) = db::diff_host_vs_previous(db, sid, &h.target.ip.to_string(), &state)? {
                    print_diff(&h.target.display(), &d);
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
        report::write_html(p, &sorted, &scan_type_str, started_at, elapsed)?;
    }
    if let Some(p) = &args.output_markdown {
        report::write_markdown(p, &sorted, &scan_type_str, started_at, elapsed)?;
    }
    if let (Some(tpl), Some(out)) = (&args.template_path, &args.output_template) {
        report::write_custom(tpl, out, &sorted, &scan_type_str, started_at, elapsed)?;
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
        let open_idx: Vec<usize> = h.ports.iter().enumerate()
            .filter(|(_, p)| p.state == PortState::Open)
            .map(|(i, _)| i).collect();
        let concurrency = open_idx.len().clamp(4, 32);
        let infos: Vec<(usize, Option<service_probe::ServiceInfo>)> = stream::iter(open_idx.into_iter())
            .map(|i| {
                let port = h.ports[i].port;
                async move { (i, service_probe::probe(ip, port, probe_timeout).await) }
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
                scanner::tcp_connect_scan(t, ports, timeout_dur, parallel, show_closed, cancel, limiter, scan_delay).await
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
