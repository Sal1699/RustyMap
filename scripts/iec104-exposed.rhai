// @name: iec104-exposed
// @description: IEC 60870-5-104 open (power SCADA)
// @category: ics
// @severity: high
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 2404 { continue; }
    findings.push(#{ severity: "high", port: 2404, message: "IEC 60870-5-104 open (power SCADA)" });
}
