// @name: vnc-http-exposed
// @description: VNC-over-HTTP (5800) open
// @category: vnc
// @severity: low
// @tags: vnc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5800 { continue; }
    findings.push(#{ severity: "low", port: 5800, message: "VNC-over-HTTP (5800) open" });
}
