//! Structured metadata for Rhai plugin scripts.
//!
//! Each script may declare a header block of `// @key: value` lines.
//! Recognised keys:
//!
//!   `@name`         display name (defaults to file stem)
//!   `@description`  one-line summary
//!   `@category`     coarse bucket (web, dns, tls, db, mobile, cloud, …)
//!   `@severity`     info | low | medium | high | critical
//!   `@tags`         comma-separated taxonomy
//!   `@cve`          comma-separated CVE IDs the script verifies
//!   `@references`   comma-separated URLs
//!   `@author`       free-text
//!
//! Scripts with no metadata block still load — they just get default
//! values. The catalog lists every script (built-in + user) with
//! whatever metadata each declared. Filters compose: `--script-tag X
//! --script-severity high` returns the intersection.
//!
//! `--script-cve CVE-XXXX-NNNN` is the killer feature: given a CVE
//! you found in the NVD lookup, instantly see which scripts can
//! verify it on the wire.

use serde::{Deserialize, Serialize};
use std::path::Path;

// Bug-20 (v0.66.4): serialize variants in lowercase so JSON output
// matches the `label()` used by the table display (was PascalCase
// "Critical" in JSON but "crit" in --script-list — inconsistent for
// downstream parsers).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginMeta {
    pub name: String,
    pub source: String, // "builtin" | "user:<path>"
    pub description: String,
    pub category: Option<String>,
    pub severity: Option<Severity>,
    pub tags: Vec<String>,
    pub cves: Vec<String>,
    pub references: Vec<String>,
    pub author: Option<String>,
}

/// Parse the leading comment block of a Rhai script and pull out
/// `// @key: value` annotations. Stops at the first non-comment,
/// non-blank line — metadata must be in the header.
pub fn parse(name: &str, source_label: &str, src: &str) -> PluginMeta {
    let mut meta = PluginMeta {
        name: name.to_string(),
        source: source_label.to_string(),
        ..Default::default()
    };
    for line in src.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if !l.starts_with("//") {
            // Header ends at the first executable line.
            break;
        }
        let body = l.trim_start_matches("//").trim();
        let Some(rest) = body.strip_prefix('@') else {
            // Plain `// description text` line — keep the first such
            // line as the description if no `@description` shows up.
            if meta.description.is_empty() {
                meta.description = body.trim_end_matches('.').to_string();
            }
            continue;
        };
        let Some((key, val)) = rest.split_once(':') else { continue };
        let key = key.trim().to_lowercase();
        let val = val.trim();
        match key.as_str() {
            "name" => meta.name = val.to_string(),
            "description" | "desc" => meta.description = val.to_string(),
            "category" | "cat" => meta.category = Some(val.to_lowercase()),
            "severity" | "sev" => meta.severity = Severity::parse(val),
            "tags" => meta.tags = split_csv(val),
            "cve" | "cves" => meta.cves = split_csv(val).into_iter().map(|s| s.to_uppercase()).collect(),
            "references" | "refs" | "ref" => meta.references = split_csv(val),
            "author" => meta.author = Some(val.to_string()),
            _ => {} // unknown key — ignore so scripts don't break on schema additions
        }
    }
    if meta.description.is_empty() {
        meta.description = "(no description)".into();
    }
    meta
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Build the full catalog from built-in scripts + a user directory.
pub fn build_catalog(
    builtins: &[(&str, &str)],
    user_dir: Option<&Path>,
) -> Vec<PluginMeta> {
    let mut out: Vec<PluginMeta> =
        builtins.iter().map(|(n, src)| parse(n, "builtin", src)).collect();

    if let Some(dir) = user_dir {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("rhai") {
                    continue;
                }
                let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("script").to_string();
                let label = format!("user:{}", path.display());
                if let Ok(src) = std::fs::read_to_string(&path) {
                    out.push(parse(&name, &label, &src));
                }
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[derive(Debug, Clone, Default)]
pub struct CatalogFilter {
    pub category: Option<String>,
    pub tag: Option<String>,
    pub severity: Option<Severity>,
    pub cve: Option<String>,
}

impl CatalogFilter {
    pub fn matches(&self, m: &PluginMeta) -> bool {
        if let Some(cat) = &self.category {
            if m.category.as_deref().map(str::to_lowercase) != Some(cat.to_lowercase()) {
                return false;
            }
        }
        if let Some(tag) = &self.tag {
            let tl = tag.to_lowercase();
            if !m.tags.iter().any(|t| t.to_lowercase() == tl) {
                return false;
            }
        }
        if let Some(sev) = self.severity {
            if m.severity != Some(sev) {
                return false;
            }
        }
        if let Some(cve) = &self.cve {
            let cu = cve.to_uppercase();
            if !m.cves.iter().any(|c| c.to_uppercase() == cu) {
                return false;
            }
        }
        true
    }
}

pub fn print_catalog(catalog: &[PluginMeta], filter: &CatalogFilter) {
    use colored::*;
    let filtered: Vec<&PluginMeta> = catalog.iter().filter(|m| filter.matches(m)).collect();
    println!();
    println!(
        "{}",
        format!("Plugin catalog — {} script(s) shown of {}", filtered.len(), catalog.len())
            .bold()
    );
    if filtered.is_empty() {
        println!("  {}", "no script matches the filter".dimmed());
        return;
    }
    println!(
        "  {:<28} {:<10} {:<10} {:<10} TAGS",
        "NAME".bold(), "SOURCE".bold(), "CATEGORY".bold(), "SEVERITY".bold()
    );
    for m in filtered {
        // Bug-20 (v0.66.4): use full lowercase labels matching JSON
        // output (`Severity::label()`). Previous "crit"/"med" 4-char
        // shorthand split parsers between the display and the export.
        let sev_color = match m.severity {
            Some(Severity::Critical) => "critical".red().bold().to_string(),
            Some(Severity::High) => "high".red().to_string(),
            Some(Severity::Medium) => "medium".yellow().to_string(),
            Some(Severity::Low) => "low".dimmed().to_string(),
            Some(Severity::Info) => "info".dimmed().to_string(),
            None => "-".dimmed().to_string(),
        };
        let source_short = if m.source == "builtin" { "builtin".green().to_string() } else { "user".cyan().to_string() };
        println!(
            "  {:<28} {:<10} {:<10} {:<10} {}",
            m.name,
            source_short,
            m.category.as_deref().unwrap_or("-"),
            sev_color,
            m.tags.join(",")
        );
    }
}

pub fn print_info(meta: &PluginMeta) {
    use colored::*;
    println!();
    println!("{}", format!("Plugin: {}", meta.name).bold().underline());
    println!("  source     : {}", meta.source);
    println!("  description: {}", meta.description);
    if let Some(c) = &meta.category {
        println!("  category   : {}", c);
    }
    if let Some(s) = meta.severity {
        println!("  severity   : {}", s.label());
    }
    if !meta.tags.is_empty() {
        println!("  tags       : {}", meta.tags.join(", "));
    }
    if !meta.cves.is_empty() {
        println!("  CVEs       : {}", meta.cves.join(", ").yellow());
    }
    if !meta.references.is_empty() {
        println!("  references :");
        for r in &meta.references {
            println!("    · {}", r);
        }
    }
    if let Some(a) = &meta.author {
        println!("  author     : {}", a);
    }
}

pub fn export_markdown(catalog: &[PluginMeta]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(&mut s, "# RustyMap plugin catalog\n");
    let _ = writeln!(&mut s, "{} scripts.\n", catalog.len());
    let _ = writeln!(&mut s, "| Name | Source | Category | Severity | Tags | CVEs |");
    let _ = writeln!(&mut s, "|------|--------|----------|----------|------|------|");
    for m in catalog {
        let _ = writeln!(
            &mut s,
            "| `{}` | {} | {} | {} | {} | {} |",
            m.name,
            m.source,
            m.category.as_deref().unwrap_or("-"),
            m.severity.map(|s| s.label()).unwrap_or("-"),
            m.tags.join(", "),
            m.cves.join(", ")
        );
    }
    s
}

pub fn export_json(catalog: &[PluginMeta]) -> String {
    serde_json::to_string_pretty(catalog).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_metadata_block() {
        let src = "// @name: log4shell-probe\n\
                   // @description: Detect Log4Shell on HTTP services\n\
                   // @category: web\n\
                   // @severity: critical\n\
                   // @tags: log4j, jndi, owasp-a06\n\
                   // @cve: CVE-2021-44228, CVE-2021-45046\n\
                   // @references: https://example/log4shell\n\
                   // @author: alice\n\
                   \n\
                   // body…\n\
                   fn run() { 0 }";
        let m = parse("log4shell-probe", "builtin", src);
        assert_eq!(m.name, "log4shell-probe");
        assert_eq!(m.category.as_deref(), Some("web"));
        assert_eq!(m.severity, Some(Severity::Critical));
        assert!(m.tags.contains(&"jndi".to_string()));
        assert!(m.cves.contains(&"CVE-2021-44228".to_string()));
        assert_eq!(m.author.as_deref(), Some("alice"));
    }

    #[test]
    fn falls_back_to_first_comment_line_for_description() {
        let src = "// Probes anonymous FTP login\nfn run() { 0 }";
        let m = parse("anon-ftp", "builtin", src);
        assert_eq!(m.description, "Probes anonymous FTP login");
    }

    #[test]
    fn missing_metadata_keeps_defaults() {
        let m = parse("noop", "builtin", "fn run() { 0 }");
        assert_eq!(m.description, "(no description)");
        assert!(m.tags.is_empty());
        assert!(m.severity.is_none());
    }

    #[test]
    fn unknown_keys_ignored_silently() {
        let src = "// @name: x\n// @future_field: someday\nfn r() { 0 }";
        let m = parse("x", "builtin", src);
        assert_eq!(m.name, "x");
    }

    #[test]
    fn filter_by_severity() {
        let metas = vec![
            PluginMeta { name: "a".into(), severity: Some(Severity::High), ..Default::default() },
            PluginMeta { name: "b".into(), severity: Some(Severity::Low), ..Default::default() },
        ];
        let f = CatalogFilter { severity: Some(Severity::High), ..Default::default() };
        let kept: Vec<_> = metas.iter().filter(|m| f.matches(m)).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "a");
    }

    #[test]
    fn filter_by_cve_case_insensitive() {
        let metas = vec![
            PluginMeta {
                name: "log4j".into(),
                cves: vec!["CVE-2021-44228".into()],
                ..Default::default()
            },
        ];
        let f = CatalogFilter { cve: Some("cve-2021-44228".into()), ..Default::default() };
        assert_eq!(metas.iter().filter(|m| f.matches(m)).count(), 1);
    }

    #[test]
    fn filter_by_tag_intersect_severity() {
        let metas = vec![
            PluginMeta {
                name: "a".into(),
                tags: vec!["jwt".into()],
                severity: Some(Severity::High),
                ..Default::default()
            },
            PluginMeta {
                name: "b".into(),
                tags: vec!["jwt".into()],
                severity: Some(Severity::Low),
                ..Default::default()
            },
        ];
        let f = CatalogFilter { tag: Some("jwt".into()), severity: Some(Severity::High), ..Default::default() };
        let kept: Vec<_> = metas.iter().filter(|m| f.matches(m)).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "a");
    }

    #[test]
    fn export_markdown_has_header_and_one_row_per_script() {
        let metas = vec![
            PluginMeta { name: "a".into(), source: "builtin".into(), ..Default::default() },
            PluginMeta { name: "b".into(), source: "builtin".into(), ..Default::default() },
        ];
        let md = export_markdown(&metas);
        assert!(md.contains("| Name |"));
        assert!(md.contains("| `a` |"));
        assert!(md.contains("| `b` |"));
    }

    #[test]
    fn severity_parse_aliases() {
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("med"), Some(Severity::Medium));
        assert!(Severity::parse("nope").is_none());
    }
}
