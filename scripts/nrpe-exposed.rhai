// @name: nrpe-exposed
// @description: Nagios NRPE (5666) open (check CVE-2014-2913)
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5666 { continue; }
    findings.push(#{ severity: "low", port: 5666, message: "Nagios NRPE (5666) open (check CVE-2014-2913)" });
}
