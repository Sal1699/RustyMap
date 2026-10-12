// @name: netbios-name-svc
// @description: NetBIOS name service open (host/domain leak)
// @category: smb
// @severity: medium
// @tags: smb, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 137 { continue; }
    findings.push(#{ severity: "medium", port: 137, message: "NetBIOS name service open (host/domain leak)" });
}
