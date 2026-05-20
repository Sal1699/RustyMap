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

// Return true when the banner contradicts the port-based hint, so we
// should NOT fire the finding. Currently only port 8080 is ambiguous
// enough to need a banner check (it's used by everything HTTP).
fn banner_contradicts_hint(port, product) {
    if product == () { return false; }
    let p = product.to_string().to_lower();
    if port == 8080 {
        // Tomcat / JBoss / WildFly / Coyote banners → genuine candidate
        if p.contains("tomcat") || p.contains("coyote") || p.contains("jboss") || p.contains("wildfly") {
            return false;
        }
        // Any other identified HTTP server (nginx, lighttpd, Apache,
        // IIS, Caddy, OpenResty, …) means it's NOT a Tomcat manager.
        if p.contains("nginx") || p.contains("lighttpd") || p.contains("apache")
            || p.contains("iis") || p.contains("caddy") || p.contains("openresty")
            || p.contains("traefik") || p.contains("haproxy") {
            return true;
        }
    }
    return false;
}

for p in host.ports {
    if p.state != "open" { continue; }
    let h = hint_for(p.port);
    if h == "" { continue; }
    let product = if p.service != () { p.service.product } else { () };
    if banner_contradicts_hint(p.port, product) { continue; }
    findings.push(#{
        severity: "high",
        port: p.port,
        message: `Default-cred-prone service: ${h}`
    });
}
