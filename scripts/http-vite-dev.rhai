// @name: http-vite-dev
// @description: Detect a Vite dev server exposed to the network
// @category: http
// @severity: medium
// @tags: http, vite, dev-server, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5173 && p.port != 3000 && p.port != 80 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/@vite/client`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("createHotContext") >= 0 || body.index_of("vite") >= 0 {
        findings.push(#{ severity: "medium", port: p.port, message: "Vite dev server exposed — HMR/source is reachable; never run dev servers on public interfaces" });
    }
}
