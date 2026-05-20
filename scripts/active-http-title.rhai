// Active probe: GET / on each open HTTP port and extract <title>.
// Surfaces "what does this site claim to be?" — quick recon win.
// Bug-08 (v0.66.3): hardened parser, skips empty titles outright,
// handles attrs on the <title> tag, BOM, and falls back to
// <meta property="og:title"> when the page is JS-rendered.
// @name: active-http-title
// @description: Extract HTTP <title> (or og:title) per open web port
// @category: info
// @severity: info
// @tags: http recon
// @author: rustymap
fn extract_title(html) {
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
        let content = lo.index_of("content=", og);
        if content >= 0 {
            let quote_at = content + 8;
            if quote_at < lo.len {
                let q = lo.sub_string(quote_at, 1);
                if q == `"` || q == `'` {
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
    if title == "" { continue; }   // strict — empty titles never reported
    if title.len > 200 { title = title.sub_string(0, 200) + "…"; }
    findings.push(#{
        severity: "info",
        port: p.port,
        message: `HTTP title: "${title}" (status ${resp.status})`
    });
}
