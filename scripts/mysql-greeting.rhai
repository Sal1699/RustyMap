// @name: mysql-greeting
// @description: Read the MySQL/MariaDB server greeting and extract version
// @category: database
// @severity: info
// @tags: mysql, mariadb, fingerprint
// @author: rustymap
// NSE-equivalent of mysql-info: MySQL speaks first, embedding its version
// as ASCII in the handshake packet (e.g. "5.7.42" / "10.11.6-MariaDB").
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 3306 && p.port != 3307 { continue; }
    let resp = tcp_send(host.ip, p.port, "", 2500);
    if resp == "" { continue; }
    let ver = regex_capture("([0-9]+\\.[0-9]+\\.[0-9]+[0-9A-Za-z._-]*)", resp);
    if ver == "" { continue; }
    let flavour = if resp.to_lower().index_of("mariadb") >= 0 { "MariaDB" } else { "MySQL" };
    findings.push(#{
        severity: "info",
        port: p.port,
        message: `${flavour} handshake version ${ver}`
    });
}
