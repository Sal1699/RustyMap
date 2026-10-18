// Flag services historically deployed with vendor default credentials.
// Bug-01 (v0.66.3): port 8080 was firing for any HTTP server (incl.
// lighttpd / nginx). Now: when --sV info is available, only fire the
// 8080 hint if the banner actually looks like Tomcat / JBoss. Other
// hint ports either are protocol-unambiguous (3306 → MySQL family
// regardless of banner) or stay as-is.
// @name: default-cred-likely
// @description: Port-based hint for services historically shipped with vendor defaults
// @category: vuln
// @severity: high
// @tags: creds default
// @author: rustymap
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

// Ambiguous ports (used by many HTTP servers) must NOT fire on a bare open
// state — they require a POSITIVE -sV product marker, else we skip (v0.99.1
// FP-2: lighttpd:8080 was wrongly flagged "Tomcat manager" when -sV had no/
// non-Tomcat product). Protocol-unambiguous ports (23/3306/…) fire as before.
fn needs_positive_marker(port) {
    return port == 8080;
}

fn product_confirms(port, product) {
    if product == () { return false; }
    let p = product.to_string().to_lower();
    if port == 8080 {
        return p.contains("tomcat") || p.contains("coyote")
            || p.contains("jboss") || p.contains("wildfly");
    }
    return false;
}

for p in host.ports {
    if p.state != "open" { continue; }
    let h = hint_for(p.port);
    if h == "" { continue; }
    let product = if p.service != () { p.service.product } else { () };
    // On ambiguous ports, require a positive product match before asserting.
    if needs_positive_marker(p.port) && !product_confirms(p.port, product) { continue; }
    findings.push(#{
        severity: "high",
        port: p.port,
        message: `Default-cred-prone service: ${h}`
    });
}
