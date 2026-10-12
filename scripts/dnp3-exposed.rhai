// @name: dnp3-exposed
// @description: DNP3 open (SCADA — must be isolated)
// @category: ics
// @severity: high
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 20000 { continue; }
    findings.push(#{ severity: "high", port: 20000, message: "DNP3 open (SCADA — must be isolated)" });
}
