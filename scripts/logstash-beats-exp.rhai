// @name: logstash-beats-exp
// @description: Logstash Beats input open
// @category: misc
// @severity: low
// @tags: misc, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5044 { continue; }
    findings.push(#{ severity: "low", port: 5044, message: "Logstash Beats input open" });
}
