//! Wappalyzer-style web technology fingerprinting on HTTP responses.
//!
//! Runs alongside `vendor_probe`: re-examines the same HTTP body/headers
//! looking for CMS, JavaScript framework, CDN, and cloud signatures.
//! The matched technologies are surfaced as `device.hints` entries
//! (and end up in the JSON/HTML reports) so a `--sV` scan of a web
//! host gets a one-line "tech: WordPress 6.4 · jQuery 3.7 · Cloudflare"
//! readout next to the cert info.

use once_cell::sync::Lazy;
use regex::Regex;

/// One technology detection rule.
struct WebRule {
    name: &'static str,
    /// Regex matched against the response body+headers (case-insensitive).
    marker: Regex,
    /// Optional version-extracting regex (capture group 1).
    version: Option<Regex>,
    /// Category for grouping in output.
    category: Category,
}

#[derive(Debug, Clone, Copy)]
pub enum Category {
    Cms,
    Framework,
    JsLibrary,
    Cdn,
    Cloud,
    WebServer,
    Analytics,
    Other,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Category::Cms => "CMS",
            Category::Framework => "framework",
            Category::JsLibrary => "js",
            Category::Cdn => "CDN",
            Category::Cloud => "cloud",
            Category::WebServer => "server",
            Category::Analytics => "analytics",
            Category::Other => "tech",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebHit {
    pub name: String,
    pub version: Option<String>,
    pub category: &'static str,
}

impl WebHit {
    pub fn label(&self) -> String {
        match &self.version {
            Some(v) => format!("[{}] {} {}", self.category, self.name, v),
            None => format!("[{}] {}", self.category, self.name),
        }
    }
}

static RULES: Lazy<Vec<WebRule>> = Lazy::new(|| {
    use Category::*;
    vec![
        // ── CMS ──
        WebRule {
            name: "WordPress",
            marker: Regex::new(r"(?i)/wp-content/|/wp-includes/|wp-emoji-release|<meta name=.generator. content=.WordPress").unwrap(),
            version: Some(Regex::new(r#"(?i)<meta name="generator" content="WordPress\s+([\d.]+)"#).unwrap()),
            category: Cms,
        },
        WebRule {
            name: "Drupal",
            marker: Regex::new(r"(?i)x-generator:\s*drupal|/sites/default/files/|/sites/default/modules/|drupal-settings-json").unwrap(),
            version: Some(Regex::new(r"(?i)x-generator:\s*drupal\s+([\d.]+)").unwrap()),
            category: Cms,
        },
        WebRule {
            name: "Joomla",
            marker: Regex::new(r"(?i)/administrator/templates/|<meta name=.generator. content=.Joomla|/media/jui/").unwrap(),
            version: Some(Regex::new(r#"(?i)<meta name="generator" content="Joomla[!]?\s*-?\s*([\d.]+)"#).unwrap()),
            category: Cms,
        },
        WebRule {
            name: "Magento",
            marker: Regex::new(r"(?i)mage/cookies\.js|skin/frontend/|/static/version\d+/frontend/").unwrap(),
            version: None,
            category: Cms,
        },
        WebRule {
            name: "Shopify",
            marker: Regex::new(r"(?i)cdn\.shopify\.com|x-shopify-stage|shopify-features").unwrap(),
            version: None,
            category: Cms,
        },
        WebRule {
            name: "Ghost",
            marker: Regex::new(r"(?i)<meta name=.generator. content=.Ghost").unwrap(),
            version: Some(Regex::new(r#"(?i)Ghost\s+([\d.]+)"#).unwrap()),
            category: Cms,
        },
        // ── Frameworks ──
        WebRule {
            name: "Next.js",
            marker: Regex::new(r"(?i)/_next/static/|x-powered-by:\s*next\.js|__NEXT_DATA__").unwrap(),
            version: Some(Regex::new(r"(?i)x-powered-by:\s*next\.js\s+([\d.]+)").unwrap()),
            category: Framework,
        },
        WebRule {
            name: "Express",
            marker: Regex::new(r"(?i)x-powered-by:\s*express").unwrap(),
            version: None,
            category: Framework,
        },
        WebRule {
            name: "Django",
            marker: Regex::new(r"(?i)csrftoken|__admin/|x-frame-options:\s*deny.*django").unwrap(),
            version: None,
            category: Framework,
        },
        WebRule {
            name: "Laravel",
            marker: Regex::new(r"(?i)laravel_session|set-cookie:\s*xsrf-token=.*laravel").unwrap(),
            version: None,
            category: Framework,
        },
        WebRule {
            name: "Rails",
            marker: Regex::new(r"(?i)x-powered-by:\s*phusion passenger|set-cookie:\s*_[a-z]+_session=.*--").unwrap(),
            version: None,
            category: Framework,
        },
        WebRule {
            name: "Spring",
            marker: Regex::new(r"(?i)x-application-context:|jsessionid=").unwrap(),
            version: None,
            category: Framework,
        },
        // ── JS libraries ──
        WebRule {
            name: "jQuery",
            // Common forms: /jquery.js, /jquery-3.7.1.min.js, jquery.com, "jquery":
            marker: Regex::new(r"(?i)/?jquery(?:[-.][\d.]+)?(?:\.min)?\.js|jquery\.com").unwrap(),
            version: Some(Regex::new(r"(?i)jquery[-.]([\d.]+)(?:\.min)?\.js").unwrap()),
            category: JsLibrary,
        },
        WebRule {
            name: "React",
            marker: Regex::new(r"(?i)data-reactroot|react(-dom)?[.-]?(?:[\d.]+)?\.(?:min\.)?js|react-dom\.production").unwrap(),
            version: Some(Regex::new(r"(?i)react(?:-dom)?[.-]([\d.]+)\.(?:production\.min\.)?js").unwrap()),
            category: JsLibrary,
        },
        WebRule {
            name: "Vue.js",
            marker: Regex::new(r"(?i)vue\.(?:min\.)?(?:runtime\.)?js|data-v-[a-f0-9]{6,8}|<div\s+id=.app").unwrap(),
            version: Some(Regex::new(r"(?i)vue(?:js)?[/.-]([\d.]+)").unwrap()),
            category: JsLibrary,
        },
        WebRule {
            name: "Angular",
            marker: Regex::new(r"(?i)ng-version=|angular(?:\.min)?\.js|@angular/").unwrap(),
            version: Some(Regex::new(r#"(?i)ng-version="([\d.]+)""#).unwrap()),
            category: JsLibrary,
        },
        WebRule {
            name: "Bootstrap",
            marker: Regex::new(r#"(?i)bootstrap[.-](?:min\.)?(?:[\d.]+)?\.(?:css|js)|class="[^"]*\b(?:btn-primary|navbar-toggler)"#).unwrap(),
            version: Some(Regex::new(r"(?i)bootstrap[.-]([\d.]+)").unwrap()),
            category: JsLibrary,
        },
        // ── CDN ──
        WebRule {
            name: "Cloudflare",
            marker: Regex::new(r"(?i)server:\s*cloudflare|cf-ray:|__cfduid|cf-cache-status:").unwrap(),
            version: None,
            category: Cdn,
        },
        WebRule {
            name: "Akamai",
            marker: Regex::new(r"(?i)server:\s*akamai|x-akamai-|akamaighost").unwrap(),
            version: None,
            category: Cdn,
        },
        WebRule {
            name: "Fastly",
            marker: Regex::new(r"(?i)x-served-by:\s*cache-|x-cache:.*fastly|x-fastly-").unwrap(),
            version: None,
            category: Cdn,
        },
        WebRule {
            name: "AWS CloudFront",
            marker: Regex::new(r"(?i)x-amz-cf-id|via:\s*[\d.]+\s*\(cloudfront\)").unwrap(),
            version: None,
            category: Cdn,
        },
        // ── Cloud / hosting ──
        WebRule {
            name: "AWS",
            marker: Regex::new(r"(?i)x-amz-(?:request-id|id-2)|server:\s*amazons3").unwrap(),
            version: None,
            category: Cloud,
        },
        WebRule {
            name: "Azure",
            marker: Regex::new(r"(?i)x-azure-ref|x-msedge-ref").unwrap(),
            version: None,
            category: Cloud,
        },
        WebRule {
            name: "Google Cloud",
            marker: Regex::new(r"(?i)server:\s*gws|x-goog-").unwrap(),
            version: None,
            category: Cloud,
        },
        // ── Web servers (extra detail beyond the existing Server-header heuristic) ──
        WebRule {
            name: "Apache Tomcat",
            marker: Regex::new(r"(?i)server:\s*apache[/-]coyote|jsessionid=").unwrap(),
            version: Some(Regex::new(r"(?i)apache[/-]coyote/([\d.]+)").unwrap()),
            category: WebServer,
        },
        WebRule {
            name: "OpenResty",
            marker: Regex::new(r"(?i)server:\s*openresty").unwrap(),
            version: Some(Regex::new(r"(?i)openresty/([\d.]+)").unwrap()),
            category: WebServer,
        },
        WebRule {
            name: "Caddy",
            marker: Regex::new(r"(?i)server:\s*caddy").unwrap(),
            version: Some(Regex::new(r"(?i)caddy/([\d.]+)").unwrap()),
            category: WebServer,
        },
        WebRule {
            name: "Lighttpd",
            marker: Regex::new(r"(?i)server:\s*lighttpd").unwrap(),
            version: Some(Regex::new(r"(?i)lighttpd/([\d.]+)").unwrap()),
            category: WebServer,
        },
        // ── Analytics ──
        WebRule {
            name: "Google Analytics",
            marker: Regex::new(r"(?i)googletagmanager\.com/gtag|google-analytics\.com/analytics\.js|UA-\d+-\d+|G-[A-Z0-9]{8,}").unwrap(),
            version: None,
            category: Analytics,
        },
        WebRule {
            name: "Matomo",
            marker: Regex::new(r"(?i)matomo\.(?:js|php)|piwik\.js").unwrap(),
            version: None,
            category: Analytics,
        },
        // ── Misc ──
        WebRule {
            name: "WAF: ModSecurity",
            marker: Regex::new(r"(?i)mod_security|modsecurity").unwrap(),
            version: None,
            category: Other,
        },
        WebRule {
            name: "WAF: Sucuri",
            marker: Regex::new(r"(?i)server:\s*sucuri/cloudproxy|x-sucuri-").unwrap(),
            version: None,
            category: Other,
        },
    ]
});

pub fn detect(body_and_headers: &str) -> Vec<WebHit> {
    let mut out = Vec::new();
    for rule in RULES.iter() {
        if rule.marker.is_match(body_and_headers) {
            let version = rule
                .version
                .as_ref()
                .and_then(|v| v.captures(body_and_headers))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());
            out.push(WebHit {
                name: rule.name.to_string(),
                version,
                category: rule.category.label(),
            });
        }
    }
    // Stable order: keep CMS/framework hits first, then libs, then infra
    out.sort_by_key(|h| match h.category {
        "CMS" => 0,
        "framework" => 1,
        "js" => 2,
        "server" => 3,
        "CDN" => 4,
        "cloud" => 5,
        "analytics" => 6,
        _ => 7,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wordpress_with_version() {
        let body = r#"<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel='stylesheet' href='/wp-content/themes/foo/style.css'>
</head></html>"#;
        let hits = detect(body);
        let wp = hits.iter().find(|h| h.name == "WordPress").unwrap();
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
        assert_eq!(wp.category, "CMS");
    }

    #[test]
    fn detects_cloudflare() {
        let body = "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 8a1b2c-FRA\r\n\r\n";
        let hits = detect(body);
        assert!(hits.iter().any(|h| h.name == "Cloudflare" && h.category == "CDN"));
    }

    #[test]
    fn detects_jquery_and_version() {
        let body = r#"<script src="/static/jquery-3.7.1.min.js"></script>"#;
        let hits = detect(body);
        let j = hits.iter().find(|h| h.name == "jQuery").unwrap();
        assert_eq!(j.version.as_deref(), Some("3.7.1"));
    }

    #[test]
    fn detects_multiple_categories() {
        let body = r#"HTTP/1.1 200 OK
Server: cloudflare
CF-RAY: x

<html><head>
<meta name="generator" content="WordPress 6.4.2">
<script src="/jquery-3.7.1.min.js"></script>
</head></html>"#;
        let hits = detect(body);
        // Stable order: CMS first, then js, then CDN
        let names: Vec<&str> = hits.iter().map(|h| h.name.as_str()).collect();
        assert!(names.contains(&"WordPress"));
        assert!(names.contains(&"jQuery"));
        assert!(names.contains(&"Cloudflare"));
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(pos("WordPress") < pos("jQuery"));
        assert!(pos("jQuery") < pos("Cloudflare"));
    }

    #[test]
    fn empty_returns_nothing() {
        assert!(detect("").is_empty());
        assert!(detect("HTTP/1.0 404 Not Found\r\n\r\n").is_empty());
    }
}
