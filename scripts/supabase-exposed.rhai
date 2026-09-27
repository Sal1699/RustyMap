// @name: supabase-exposed
// @description: Detect a Supabase REST/Studio surface
// @category: backend
// @severity: medium
// @tags: supabase, baas, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8000 && p.port != 3000 && p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/rest/v1/`, 3000);
    if resp.status == 0 { continue; }
    let hdr = if type_of(resp.headers) == "string" { resp.headers.to_lower() } else { "" };
    let body = if type_of(resp.body) == "string" { resp.body.to_lower() } else { "" };
    if hdr.index_of("supabase") >= 0 || body.index_of("supabase") >= 0 || hdr.index_of("postgrest") >= 0 {
        findings.push(#{ severity: "medium", port: p.port, message: "Supabase/PostgREST surface reachable — verify Row-Level Security and that the service_role key isn't client-exposed" });
    }
}
