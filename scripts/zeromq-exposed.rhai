// @name: zeromq-exposed
// @description: ADB/ZeroMQ-class port 5555 open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5555 { continue; }
    findings.push(#{ severity: "low", port: 5555, message: "ADB/ZeroMQ-class port 5555 open" });
}
