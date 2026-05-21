// Active probe: GET / on each open HTTP port and extract <title>.
// Surfaces "what does this site claim to be?" — quick recon win.
// Bug-08 (v0.66.5): the v0.66.3 hardening used `lo.len` (Rhai
// property access) which fails on this build's string type, causing
// extract_title to silently return () and the subsequent `title.len`
// check to crash with "Unknown property 'len' on type ()". Switched
// every length access to the `len()` global function which is always
// available in Rhai 1.x. Also kept the og:title fallback but made it
// guard-rail-safe.
// @name: active-http-title
// @description: Extract HTTP <title> (or og:title) per open web port
// @category: info
// @severity: info
// @tags: http recon
// @author: rustymap
fn extract_title(html) {
    if type_of(html) != "string" { return ""; }
    let lo = html.to_lower();
    // Primary: <title …>…</title>
    let i = lo.index_of("<title");
    if i >= 0 {
        let close = lo.index_of(">", i);
        if close >= 0 {
            let end = lo.index_of("</title>", close);
            if end > close {
                let t = html.sub_string(close + 1, end - close - 1).trim();
                if t != "" { return t; }
            }
        }
    }
    // Fallback: <meta property="og:title" content="…"> for SPA pages.
    let og = lo.index_of("og:title");
    if og >= 0 {
        let content_pos = lo.index_of("content=", og);
        if content_pos >= 0 {
            let quote_at = content_pos + 8;
            if quote_at < len(lo) {
                let q = lo.sub_string(quote_at, 1);
                if q == "\"" || q == "'" {
                    let stop = lo.index_of(q, quote_at + 1);
                    if stop > quote_at {
                        let t = html.sub_string(quote_at + 1, stop - quote_at - 1).trim();
                        if t != "" { return t; }
                    }
                }
            }
        }
    }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 81 && p.port != 443 && p.port != 591
        && p.port != 2480 && p.port != 3000 && p.port != 5000
        && p.port != 8000 && p.port != 8008 && p.port != 8080 && p.port != 8081
        && p.port != 8443 && p.port != 8888 && p.port != 9000 && p.port != 9090
        && p.port != 9200 && p.port != 9443 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 || p.port == 9443 { "https" } else { "http" };
    let url = `${scheme}://${host.ip}:${p.port}/`;
    let resp = http_get(url, 3000);
    if resp.status == 0 { continue; }
    if resp.status >= 400 { continue; }
    let title = extract_title(resp.body);
    if type_of(title) != "string" { continue; }   // defensive
    if title == "" { continue; }                  // strict — empty titles never reported
    if len(title) > 200 { title = title.sub_string(0, 200) + "…"; }
    findings.push(#{
        severity: "info",
        port: p.port,
        message: `HTTP title: "${title}" (status ${resp.status})`
    });
}
