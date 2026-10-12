// @name: vmware-vsphere-8443
// @description: VMware vSphere/mgmt on 8443
// @category: mgmt
// @severity: low
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8443 { continue; }
    findings.push(#{ severity: "low", port: 8443, message: "VMware vSphere/mgmt on 8443" });
}
