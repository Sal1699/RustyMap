// @name: vmware-authd
// @description: VMware authd/ESXi mgmt port open
// @category: mgmt
// @severity: low
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 902 { continue; }
    findings.push(#{ severity: "low", port: 902, message: "VMware authd/ESXi mgmt port open" });
}
