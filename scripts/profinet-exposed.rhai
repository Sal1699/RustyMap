// @name: profinet-exposed
// @description: PROFINET open (ICS)
// @category: ics
// @severity: medium
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 34962 { continue; }
    findings.push(#{ severity: "medium", port: 34962, message: "PROFINET open (ICS)" });
}
