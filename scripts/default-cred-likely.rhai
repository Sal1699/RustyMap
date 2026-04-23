// Flag services historically deployed with vendor default credentials.
fn hint_for(p) {
    if p == 23    { return "Telnet (admin/admin, root/root)"; }
    if p == 1433  { return "MSSQL (sa/blank or weak)"; }
    if p == 3306  { return "MySQL/MariaDB (root/blank, root/root)"; }
    if p == 3389  { return "RDP (Administrator/blank or weak)"; }
    if p == 5432  { return "PostgreSQL (postgres/postgres)"; }
    if p == 5900  { return "VNC (no auth or 'password')"; }
    if p == 6379  { return "Redis (no auth by default in old versions)"; }
    if p == 8080  { return "Tomcat manager (tomcat/tomcat, admin/admin)"; }
    if p == 9200  { return "Elasticsearch (no auth in old versions)"; }
    if p == 11211 { return "memcached (no auth)"; }
    if p == 27017 { return "MongoDB (no auth in old versions)"; }
    return "";
}
for p in host.ports {
    if p.state != "open" { continue; }
    let h = hint_for(p.port);
    if h != "" {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: `Default-cred-prone service: ${h}`
        });
    }
}
