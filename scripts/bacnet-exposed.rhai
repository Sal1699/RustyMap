// @name: bacnet-exposed
// @description: BACnet open (building automation)
// @category: ics
// @severity: medium
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 47808 { continue; }
    findings.push(#{ severity: "medium", port: 47808, message: "BACnet open (building automation)" });
}
