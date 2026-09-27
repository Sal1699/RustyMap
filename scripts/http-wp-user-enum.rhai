// @name: http-wp-user-enum
// @description: Enumerate WordPress users via the REST API
// @category: http
// @severity: medium
// @tags: http, wordpress, user-enum
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/wp-json/wp/v2/users`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    let slugs = regex_find_all("(?i)\"slug\"\\s*:\\s*\"([^\"]+)\"", body);
    if len(slugs) > 0 {
        findings.push(#{ severity: "medium", port: p.port, message: `WordPress REST API leaks ${len(slugs)} usernames (/wp-json/wp/v2/users) — aids credential attacks` });
    }
}
