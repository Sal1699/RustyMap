//! Web crawler — BFS link/form discovery for the OWASP probes.
//!
//! Stays inside the seed's host (no off-site hops), respects
//! robots.txt by default (override with `respect_robots = false`),
//! caps both depth and total URL count to keep scans bounded.
//! Persists cookies across requests via reqwest's cookie store so
//! the post-login surface gets crawled when a `--web-cookie` is
//! supplied at the CLI layer.
//!
//! Output is a flat inventory of `Endpoint`s — each carries the URL,
//! method, parameter names, and a flag for whether the endpoint came
//! from a discovered HTML form. The OWASP probe layer iterates this
//! inventory deciding which checks fit which endpoint.

use anyhow::Result;
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub url: String,
    pub method: String,
    pub params: Vec<String>,
    pub from_form: bool,
}

#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub max_depth: usize,
    pub max_urls: usize,
    pub respect_robots: bool,
    pub cookie: Option<String>,
    pub timeout: Duration,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_urls: 200,
            respect_robots: true,
            cookie: None,
            timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    pub seed: String,
    pub pages_visited: usize,
    pub endpoints: Vec<Endpoint>,
}

pub async fn crawl(seed: &str, cfg: &CrawlConfig) -> Result<CrawlResult> {
    let seed_url = Url::parse(seed)?;
    let host = seed_url.host_str().unwrap_or("").to_string();

    let jar = Arc::new(reqwest::cookie::Jar::default());
    if let Some(cookie) = &cfg.cookie {
        jar.add_cookie_str(cookie, &seed_url);
    }
    let client = reqwest::Client::builder()
        .cookie_provider(Arc::clone(&jar))
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .user_agent("rustymap/web-crawler")
        .build()?;

    // robots.txt
    let disallow: Vec<String> = if cfg.respect_robots {
        fetch_robots_disallow(&client, &seed_url).await
    } else {
        Vec::new()
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut endpoints_seen: HashSet<Endpoint> = HashSet::new();
    let mut q: VecDeque<(Url, usize)> = VecDeque::new();
    q.push_back((seed_url.clone(), 0));
    seen.insert(seed_url.to_string());

    let mut pages = 0usize;

    while let Some((url, depth)) = q.pop_front() {
        if pages >= cfg.max_urls {
            break;
        }
        if disallowed(&disallow, &url) {
            continue;
        }
        let body = match fetch_html(&client, &url).await {
            Some(b) => b,
            None => continue,
        };
        pages += 1;

        // Record this URL itself as an endpoint (GET, query params if any).
        let params: Vec<String> = url
            .query_pairs()
            .map(|(k, _)| k.into_owned())
            .collect();
        let ep = Endpoint {
            url: url.to_string(),
            method: "GET".into(),
            params,
            from_form: false,
        };
        if endpoints_seen.insert(ep.clone()) {
            endpoints.push(ep);
        }

        // Forms.
        for form in extract_forms(&body, &url) {
            if endpoints_seen.insert(form.clone()) {
                endpoints.push(form);
            }
        }

        if depth >= cfg.max_depth {
            continue;
        }
        // Links.
        for link in extract_links(&body, &url) {
            if link.host_str().unwrap_or("") != host {
                continue;
            }
            let s = link.to_string();
            if !seen.insert(s.clone()) {
                continue;
            }
            if seen.len() >= cfg.max_urls * 4 {
                break;
            }
            q.push_back((link, depth + 1));
        }
    }

    Ok(CrawlResult {
        seed: seed.to_string(),
        pages_visited: pages,
        endpoints,
    })
}

async fn fetch_robots_disallow(client: &reqwest::Client, seed: &Url) -> Vec<String> {
    let mut robots = seed.clone();
    robots.set_path("/robots.txt");
    let body = match client.get(robots).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return Vec::new(),
    };
    // Honor only the User-agent: * stanza — anything more granular is
    // overkill for a single-tool audit.
    let mut applies = false;
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(ua) = line.strip_prefix("User-agent:") {
            applies = ua.trim() == "*";
        } else if applies {
            if let Some(p) = line.strip_prefix("Disallow:") {
                let p = p.trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

fn disallowed(rules: &[String], url: &Url) -> bool {
    let path = url.path();
    rules.iter().any(|r| path.starts_with(r.as_str()))
}

async fn fetch_html(client: &reqwest::Client, url: &Url) -> Option<String> {
    let resp = client.get(url.clone()).send().await.ok()?;
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    // Skip non-HTML so we don't waste budget on assets — but still
    // allow text/* in case a server mis-tags.
    if !ctype.starts_with("text/") && !ctype.contains("html") && !ctype.is_empty() {
        return None;
    }
    resp.text().await.ok()
}

fn extract_links(body: &str, base: &Url) -> Vec<Url> {
    // Conservative regex; we don't care about every link, only those
    // that contribute new attack surface.
    let re = Regex::new(r#"(?i)<a[^>]+href\s*=\s*["']([^"'#]+)["']"#).unwrap();
    let mut out = Vec::new();
    for cap in re.captures_iter(body) {
        if let Ok(u) = base.join(&cap[1]) {
            if u.scheme() == "http" || u.scheme() == "https" {
                out.push(u);
            }
        }
    }
    out
}

fn extract_forms(body: &str, base: &Url) -> Vec<Endpoint> {
    let form_re =
        Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let attr_re = Regex::new(r#"(?i)(action|method)\s*=\s*["']?([^"'\s>]+)"#).unwrap();
    let input_re =
        Regex::new(r#"(?i)<(input|select|textarea)[^>]*\bname\s*=\s*["']?([^"'\s>]+)"#).unwrap();
    let mut out = Vec::new();
    for cap in form_re.captures_iter(body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let inner = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let mut action = base.clone();
        let mut method = "GET".to_string();
        for a in attr_re.captures_iter(attrs) {
            let key = a[1].to_lowercase();
            let val = a[2].to_string();
            match key.as_str() {
                "action" => {
                    if let Ok(u) = base.join(&val) {
                        action = u;
                    }
                }
                "method" => method = val.to_uppercase(),
                _ => {}
            }
        }
        let params: Vec<String> = input_re
            .captures_iter(inner)
            .map(|m| m[2].to_string())
            .collect();
        out.push(Endpoint {
            url: action.to_string(),
            method,
            params,
            from_form: true,
        });
    }
    out
}

pub fn print_summary(result: &CrawlResult) {
    use colored::*;
    println!();
    println!(
        "{}",
        format!("Crawl of {} — {} pages, {} endpoints", result.seed, result.pages_visited, result.endpoints.len()).bold()
    );
    for ep in &result.endpoints {
        let tag = if ep.from_form { "FORM".cyan() } else { "GET ".dimmed() };
        let params = if ep.params.is_empty() {
            String::new()
        } else {
            format!(" [{}]", ep.params.join(", "))
        };
        println!("  {} {} {}{}", tag, ep.method, ep.url, params);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_links_finds_internal() {
        let base = Url::parse("https://x.test/").unwrap();
        let html = r#"<a href="/a">a</a> <a href='b/c?x=1'>b</a> <a href="https://other/">o</a>"#;
        let links: Vec<String> = extract_links(html, &base).iter().map(|u| u.to_string()).collect();
        assert!(links.contains(&"https://x.test/a".to_string()));
        assert!(links.iter().any(|u| u.contains("b/c?x=1")));
    }

    #[test]
    fn extract_forms_captures_action_method_inputs() {
        let base = Url::parse("https://x.test/login").unwrap();
        let html = r#"<form action="/auth" method="POST"><input name="u"><input name="p"></form>"#;
        let forms = extract_forms(html, &base);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].url, "https://x.test/auth");
        assert_eq!(forms[0].params, vec!["u", "p"]);
    }

    #[test]
    fn disallowed_matches_path_prefix() {
        let url = Url::parse("https://x.test/admin/dash").unwrap();
        assert!(disallowed(&["/admin".to_string()], &url));
        assert!(!disallowed(&["/api".to_string()], &url));
    }
}
