// @name: portmap-service
// @description: RPC portmapper open (enumerate with --sR)
// @category: misc
// @severity: medium
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 111 { continue; }
    findings.push(#{ severity: "medium", port: 111, message: "RPC portmapper open (enumerate with --sR)" });
}
