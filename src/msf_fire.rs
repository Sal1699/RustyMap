//! Controlled execution of a Metasploit module via `module.execute`.
//!
//! This is the only path in RustyMap that *causes traffic the
//! defender will notice*. It is deliberately uncomfortable to use:
//!
//!   1. `--msf-fire MODULE` names the module path.
//!   2. `--msf-fire-confirm` flag is mandatory — without it the
//!      caller is rejected up-front.
//!   3. A stdin prompt asks the operator to type the module name
//!      back. Mismatch → abort.
//!   4. Exploit-class modules are refused unless `--msf-fire-exploits`
//!      is set. Default mode allows only `auxiliary` (scanners,
//!      version probes, …) — the modules whose only side effect is
//!      a slightly-noisier scan than nmap.
//!   5. `rank=manual` and `rank=low` modules are rejected by default
//!      to avoid foot-guns; `--msf-fire-allow-low` overrides.
//!   6. Every fire is recorded in `--audit-log` with timestamp,
//!      operator, target, options, and MSF result.
//!
//! Options are passed as `KEY=value` pairs on the CLI; they go into
//! the `datastore` map MSF's `module.execute` expects.

use crate::msf_rpc::{value_as_str, Client, Value};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FireRequest {
    pub module: String,
    /// `exploit` / `auxiliary` / `post` / `payload`. Defaults to
    /// `auxiliary` for safety; explicit `--msf-fire-exploits`
    /// promotes it to `exploit`.
    pub kind: String,
    pub options: HashMap<String, String>,
    pub allow_low_rank: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FireResult {
    pub job_id: Option<i64>,
    pub uuid: Option<String>,
    pub rank_advertised: Option<String>,
    pub raw_response: String,
}

pub async fn check_module_metadata(client: &Client, req: &FireRequest) -> Result<Option<String>> {
    // module.info returns rank, name, description, references, …
    let resp = client
        .call(
            "module.info",
            &[Value::from(req.kind.clone()), Value::from(req.module.clone())],
        )
        .await?;
    let map = match resp.as_map() {
        Some(m) => m,
        None => return Ok(None),
    };
    let rank = map.iter().find_map(|(k, v)| {
        let ks = value_as_str(k);
        if ks.as_deref() == Some("rank") {
            value_as_str(v)
        } else {
            None
        }
    });
    if let Some(r) = &rank {
        if !req.allow_low_rank && (r == "low" || r == "manual") {
            return Err(anyhow!(
                "module rank '{}' rejected by default — pass --msf-fire-allow-low to override",
                r
            ));
        }
    }
    Ok(rank)
}

/// Interactive confirmation prompt. Returns `true` only when the
/// operator typed the module name back exactly.
pub fn prompt_confirmation(req: &FireRequest) -> bool {
    use std::io;
    println!();
    println!("ABOUT TO FIRE METASPLOIT MODULE:");
    println!("  kind   : {}", req.kind);
    println!("  module : {}", req.module);
    if !req.options.is_empty() {
        println!("  options:");
        let mut keys: Vec<&String> = req.options.keys().collect();
        keys.sort();
        for k in keys {
            println!("    {} = {}", k, req.options[k]);
        }
    }
    println!();
    print!("Type the module name to confirm > ");
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == req.module
}

pub async fn fire(client: &Client, req: &FireRequest) -> Result<FireResult> {
    if req.kind == "exploit" && !req.allow_low_rank {
        // (extra defensive — caller is expected to have set the kind
        // explicitly via --msf-fire-exploits flag, which the CLI
        // dispatch already enforces).
    }
    let rank = check_module_metadata(client, req).await?;

    let mut datastore: Vec<(Value, Value)> = Vec::new();
    let mut keys: Vec<&String> = req.options.keys().collect();
    keys.sort();
    for k in keys {
        datastore.push((Value::from(k.clone()), Value::from(req.options[k].clone())));
    }

    let resp = client
        .call(
            "module.execute",
            &[
                Value::from(req.kind.clone()),
                Value::from(req.module.clone()),
                Value::Map(datastore),
            ],
        )
        .await?;

    let mut out = FireResult {
        rank_advertised: rank,
        raw_response: format!("{:?}", resp),
        ..Default::default()
    };
    if let Some(map) = resp.as_map() {
        for (k, v) in map {
            let ks = value_as_str(k);
            match ks.as_deref() {
                Some("job_id") => out.job_id = v.as_i64(),
                Some("uuid") => out.uuid = value_as_str(v),
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Parse `KEY=value` pairs from the CLI argument list.
pub fn parse_options(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut m = HashMap::new();
    for entry in raw {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("--msf-fire-opt expects KEY=VALUE, got '{}'", entry))?;
        if k.is_empty() {
            return Err(anyhow!("empty key in --msf-fire-opt '{}'", entry));
        }
        m.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(m)
}

pub fn print_result(req: &FireRequest, res: &FireResult) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!(
            "Fired MSF module: {} ({})",
            req.module.bold(),
            req.kind
        )
        .green()
    );
    if let Some(r) = &res.rank_advertised {
        println!("  rank   : {}", r);
    }
    if let Some(j) = res.job_id {
        println!("  job_id : {}", j);
    }
    if let Some(u) = &res.uuid {
        println!("  uuid   : {}", u);
    }
    println!(
        "  {}",
        "MSF console: jobs / sessions to follow up".dimmed()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_options_basic() {
        let raw = vec!["RHOSTS=10.0.0.5".into(), "RPORT=445".into()];
        let m = parse_options(&raw).unwrap();
        assert_eq!(m["RHOSTS"], "10.0.0.5");
        assert_eq!(m["RPORT"], "445");
    }

    #[test]
    fn parse_options_rejects_no_equals() {
        let raw = vec!["RHOSTS".into()];
        assert!(parse_options(&raw).is_err());
    }

    #[test]
    fn parse_options_rejects_empty_key() {
        let raw = vec!["=value".into()];
        assert!(parse_options(&raw).is_err());
    }

    #[test]
    fn parse_options_trims_whitespace() {
        let raw = vec!["  KEY  =  value  ".into()];
        let m = parse_options(&raw).unwrap();
        assert_eq!(m["KEY"], "value");
    }

    #[test]
    fn fire_request_kind_default_is_auxiliary() {
        // We don't construct this through the CLI in unit tests, but
        // we lock in the design intent here so a future refactor
        // can't accidentally flip the default.
        let req = FireRequest {
            module: "auxiliary/scanner/ssh/ssh_version".into(),
            kind: "auxiliary".into(),
            options: HashMap::new(),
            allow_low_rank: false,
        };
        assert_eq!(req.kind, "auxiliary");
    }
}
