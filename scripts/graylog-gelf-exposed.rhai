// @name: graylog-gelf-exposed
// @description: Graylog GELF input open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 12201 { continue; }
    findings.push(#{ severity: "low", port: 12201, message: "Graylog GELF input open" });
}
