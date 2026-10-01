// @name: http-xmlrpc-exposed
// @description: Detect an exposed WordPress xmlrpc.php endpoint
// @category: http
// @severity: low
// @tags: http, wordpress, xmlrpc, ddos, brute-force
// @author: rustymap
// WordPress xmlrpc.php enables pingback-based DDoS reflection and amplified
// credential brute-force (system.multicall). A GET returns the tell-tale
// "XML-RPC server accepts POST requests only" message when it is live.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/xmlrpc.php`, 3000);
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("XML-RPC server accepts POST") >= 0 {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: "WordPress xmlrpc.php exposed — pingback DDoS and multicall brute-force vector; block or disable it"
        });
    }
}
