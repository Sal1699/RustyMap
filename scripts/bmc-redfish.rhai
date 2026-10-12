// @name: bmc-redfish
// @description: IPMI/BMC open (out-of-band mgmt)
// @category: mgmt
// @severity: high
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 623 { continue; }
    findings.push(#{ severity: "high", port: 623, message: "IPMI/BMC open (out-of-band mgmt)" });
}
