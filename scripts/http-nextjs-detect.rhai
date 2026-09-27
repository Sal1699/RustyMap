// @name: http-nextjs-detect
// @description: Detect a Next.js app (and version when advertised)
// @category: http
// @severity: info
// @tags: http, nextjs, framework, fingerprint
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 3000 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let hdr = if type_of(resp.headers) == "string" { resp.headers } else { "" };
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    let ver = regex_capture("(?i)x-powered-by:\\s*Next\\.js\\s*([\\d.]+)?", hdr);
    if hdr.to_lower().index_of("next.js") >= 0 || body.index_of("/_next/static") >= 0 {
        let msg = if ver != "" { `Next.js ${ver}` } else { "Next.js app detected" };
        findings.push(#{ severity: "info", port: p.port, message: msg });
    }
}
