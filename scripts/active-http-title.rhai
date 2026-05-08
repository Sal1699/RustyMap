// Active probe: GET / on each open HTTP port and extract <title>.
// Surfaces "what does this site claim to be?" — quick recon win.
fn extract_title(html) {
    let lo = html.to_lower();
    let i = lo.index_of("<title");
    if i < 0 { return ""; }
    let close = lo.index_of(">", i);
    if close < 0 { return ""; }
    let end = lo.index_of("</title>", close);
    if end < 0 { return ""; }
    return html.sub_string(close + 1, end - close - 1).trim();
}
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 81 && p.port != 8000 && p.port != 8080 && p.port != 8443 && p.port != 443 && p.port != 8888 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let url = `${scheme}://${host.ip}:${p.port}/`;
    let resp = http_get(url, 3000);
    if resp.status > 0 && resp.status < 400 {
        let title = extract_title(resp.body);
        if title != "" {
            findings.push(#{
                severity: "info",
                port: p.port,
                message: `HTTP title: "${title}" (status ${resp.status})`
            });
        }
    }
}
