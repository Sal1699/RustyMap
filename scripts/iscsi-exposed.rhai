// @name: iscsi-exposed
// @description: iSCSI target (3260) open (storage exposure)
// @category: misc
// @severity: medium
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3260 { continue; }
    findings.push(#{ severity: "medium", port: 3260, message: "iSCSI target (3260) open (storage exposure)" });
}
