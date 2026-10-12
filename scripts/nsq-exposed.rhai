// @name: nsq-exposed
// @description: NSQ message queue open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 4150 { continue; }
    findings.push(#{ severity: "low", port: 4150, message: "NSQ message queue open" });
}
