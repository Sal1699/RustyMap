use crate::scanner::HostResult;
use anyhow::{Context, Result};
use rhai::{Array, Dynamic, Engine, Map, Scope};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub script: String,
    pub host: String,
    pub port: Option<u16>,
    pub severity: String,
    pub message: String,
}

fn host_to_map(h: &HostResult) -> Map {
    let mut m = Map::new();
    m.insert("ip".into(), Dynamic::from(h.target.ip.to_string()));
    m.insert(
        "hostname".into(),
        match &h.target.hostname {
            Some(n) => Dynamic::from(n.clone()),
            None => Dynamic::UNIT,
        },
    );
    m.insert("up".into(), Dynamic::from(h.up));

    let ports: Array = h
        .ports
        .iter()
        .map(|p| {
            let mut pm = Map::new();
            pm.insert("port".into(), Dynamic::from(p.port as i64));
            pm.insert("state".into(), Dynamic::from(p.state.as_str().to_string()));
            if let Some(svc) = &p.service {
                let mut sm = Map::new();
                sm.insert(
                    "product".into(),
                    svc.product.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                sm.insert(
                    "version".into(),
                    svc.version.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                sm.insert(
                    "banner".into(),
                    svc.banner.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                );
                if let Some(tls) = &svc.tls {
                    let mut tm = Map::new();
                    tm.insert(
                        "negotiated".into(),
                        tls.negotiated.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "subject".into(),
                        tls.subject.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "issuer".into(),
                        tls.issuer.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert(
                        "not_after".into(),
                        tls.not_after.clone().map(Dynamic::from).unwrap_or(Dynamic::UNIT),
                    );
                    tm.insert("self_signed".into(), Dynamic::from(tls.self_signed));
                    tm.insert("expired".into(), Dynamic::from(tls.expired));
                    if let Some(b) = tls.key_bits {
                        tm.insert("key_bits".into(), Dynamic::from(b as i64));
                    }
                    let sans: Array = tls.san.iter().cloned().map(Dynamic::from).collect();
                    tm.insert("san".into(), Dynamic::from(sans));
                    sm.insert("tls".into(), Dynamic::from(tm));
                }
                pm.insert("service".into(), Dynamic::from(sm));
            }
            Dynamic::from(pm)
        })
        .collect();
    m.insert("ports".into(), Dynamic::from(ports));

    if let Some(os) = &h.os {
        let mut om = Map::new();
        om.insert("family".into(), Dynamic::from(os.family.clone()));
        om.insert("confidence".into(), Dynamic::from(os.confidence as i64));
        m.insert("os".into(), Dynamic::from(om));
    }
    m
}

fn discover_scripts(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("read_dir {:?}", path))? {
        let e = entry?;
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("rhai") {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// Extract the first non-empty comment line from a rhai script — used as
/// the "description" in --script-help. Comments start with `//`.
fn description_of(src: &str) -> String {
    for line in src.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("//") {
            let cleaned = rest.trim().trim_end_matches('.').to_string();
            if !cleaned.is_empty() {
                return cleaned;
            }
        } else if !l.is_empty() {
            // First non-comment line — no description available.
            return "(no description)".into();
        }
    }
    "(no description)".into()
}

/// Print the catalog of built-in and (optionally) user scripts.
pub fn print_help(user_path: Option<&str>) {
    use colored::*;
    println!(
        "\n{}\n",
        "RustyMap rhai scripts".bold().cyan()
    );
    println!("{}", "Built-in:".bold());
    for (name, src) in builtin_scripts() {
        println!(
            "  {:<22} {}",
            name.green().bold(),
            description_of(src)
        );
    }
    if let Some(path) = user_path {
        let p = Path::new(path);
        match discover_scripts(p) {
            Ok(scripts) if !scripts.is_empty() => {
                println!("\n{}", "User scripts:".bold());
                for sp in scripts {
                    let name = sp
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("script")
                        .to_string();
                    let desc = std::fs::read_to_string(&sp)
                        .map(|src| description_of(&src))
                        .unwrap_or_else(|_| "(unreadable)".into());
                    println!("  {:<22} {}", name.yellow().bold(), desc);
                }
            }
            _ => {}
        }
    }
    println!(
        "\n{}",
        "Run with --script PATH (or rely on built-ins, --no-builtin-scripts to opt out).".dimmed()
    );
}

/// Scripts baked into the binary at build time. Returns (name, source) pairs.
pub fn builtin_scripts() -> Vec<(&'static str, &'static str)> {
    vec![
        ("active-anonymous-ftp", include_str!("../scripts/active-anonymous-ftp.rhai")),
        ("active-elasticsearch-version", include_str!("../scripts/active-elasticsearch-version.rhai")),
        ("active-http-title", include_str!("../scripts/active-http-title.rhai")),
        ("active-redis-info", include_str!("../scripts/active-redis-info.rhai")),
        ("android-adb-exposed", include_str!("../scripts/android-adb-exposed.rhai")),
        ("anonymous-ftp", include_str!("../scripts/anonymous-ftp.rhai")),
        ("backup-exposed", include_str!("../scripts/backup-exposed.rhai")),
        ("cleartext-protocols", include_str!("../scripts/cleartext-protocols.rhai")),
        ("clickhouse-no-auth", include_str!("../scripts/clickhouse-no-auth.rhai")),
        ("cookie-flags-audit", include_str!("../scripts/cookie-flags-audit.rhai")),
        ("couchdb-no-auth", include_str!("../scripts/couchdb-no-auth.rhai")),
        ("default-cred-likely", include_str!("../scripts/default-cred-likely.rhai")),
        ("dns-zone-transfer-hint", include_str!("../scripts/dns-zone-transfer-hint.rhai")),
        ("docker-api-exposed", include_str!("../scripts/docker-api-exposed.rhai")),
        ("elasticsearch-open", include_str!("../scripts/elasticsearch-open.rhai")),
        ("etcd-v3-no-auth", include_str!("../scripts/etcd-v3-no-auth.rhai")),
        ("exposed-management", include_str!("../scripts/exposed-management.rhai")),
        ("flink-dashboard-exposed", include_str!("../scripts/flink-dashboard-exposed.rhai")),
        ("gitea-public-signup", include_str!("../scripts/gitea-public-signup.rhai")),
        ("graphql-introspection", include_str!("../scripts/graphql-introspection.rhai")),
        ("hashicorp-exposed", include_str!("../scripts/hashicorp-exposed.rhai")),
        ("http-admin-paths", include_str!("../scripts/http-admin-paths.rhai")),
        ("http-cors-wildcard", include_str!("../scripts/http-cors-wildcard.rhai")),
        ("http-missing-security-headers", include_str!("../scripts/http-missing-security-headers.rhai")),
        ("influxdb-no-auth", include_str!("../scripts/influxdb-no-auth.rhai")),
        ("ipmi-exposed", include_str!("../scripts/ipmi-exposed.rhai")),
        ("jenkins-anonymous", include_str!("../scripts/jenkins-anonymous.rhai")),
        ("jwt-alg-none", include_str!("../scripts/jwt-alg-none.rhai")),
        ("k8s-api-exposed", include_str!("../scripts/k8s-api-exposed.rhai")),
        ("kafka-no-auth", include_str!("../scripts/kafka-no-auth.rhai")),
        ("kibana-no-auth", include_str!("../scripts/kibana-no-auth.rhai")),
        ("memcached-info", include_str!("../scripts/memcached-info.rhai")),
        ("modern-auth-exposed", include_str!("../scripts/modern-auth-exposed.rhai")),
        ("mongodb-no-auth", include_str!("../scripts/mongodb-no-auth.rhai")),
        ("mqtt-anonymous", include_str!("../scripts/mqtt-anonymous.rhai")),
        ("mssql-default", include_str!("../scripts/mssql-default.rhai")),
        ("nfs-exposed", include_str!("../scripts/nfs-exposed.rhai")),
        ("old-openssh", include_str!("../scripts/old-openssh.rhai")),
        ("openldap-exposed", include_str!("../scripts/openldap-exposed.rhai")),
        ("portainer-exposed", include_str!("../scripts/portainer-exposed.rhai")),
        ("prometheus-no-auth", include_str!("../scripts/prometheus-no-auth.rhai")),
        ("prometheus-pushgateway-exposed", include_str!("../scripts/prometheus-pushgateway-exposed.rhai")),
        ("rabbitmq-management", include_str!("../scripts/rabbitmq-management.rhai")),
        ("redis-no-auth", include_str!("../scripts/redis-no-auth.rhai")),
        ("rsync-exposed", include_str!("../scripts/rsync-exposed.rhai")),
        ("smb-exposed", include_str!("../scripts/smb-exposed.rhai")),
        ("smtp-open-relay", include_str!("../scripts/smtp-open-relay.rhai")),
        ("snmp-public", include_str!("../scripts/snmp-public.rhai")),
        ("spark-master-ui-exposed", include_str!("../scripts/spark-master-ui-exposed.rhai")),
        ("tls-cert-issues", include_str!("../scripts/tls-cert-issues.rhai")),
        ("tls-deprecated", include_str!("../scripts/tls-deprecated.rhai")),
        ("vault-no-auth", include_str!("../scripts/vault-no-auth.rhai")),
        ("vnc-no-auth", include_str!("../scripts/vnc-no-auth.rhai")),
        // ── v0.72.0 NSE-equivalent batch ──
        ("ftp-banner-info", include_str!("../scripts/ftp-banner-info.rhai")),
        ("http-git-exposed", include_str!("../scripts/http-git-exposed.rhai")),
        ("http-robots", include_str!("../scripts/http-robots.rhai")),
        ("http-security-txt", include_str!("../scripts/http-security-txt.rhai")),
        ("http-server-tech", include_str!("../scripts/http-server-tech.rhai")),
        ("mysql-greeting", include_str!("../scripts/mysql-greeting.rhai")),
        ("rdp-exposed", include_str!("../scripts/rdp-exposed.rhai")),
        ("sip-options", include_str!("../scripts/sip-options.rhai")),
        ("smtp-banner", include_str!("../scripts/smtp-banner.rhai")),
        ("ssdp-upnp-info", include_str!("../scripts/ssdp-upnp-info.rhai")),
        // ── v0.73.0 batch: modern services (2020–2026) + web exposures ──
        ("ollama-exposed", include_str!("../scripts/ollama-exposed.rhai")),
        ("qdrant-exposed", include_str!("../scripts/qdrant-exposed.rhai")),
        ("meilisearch-exposed", include_str!("../scripts/meilisearch-exposed.rhai")),
        ("weaviate-exposed", include_str!("../scripts/weaviate-exposed.rhai")),
        ("typesense-exposed", include_str!("../scripts/typesense-exposed.rhai")),
        ("pocketbase-exposed", include_str!("../scripts/pocketbase-exposed.rhai")),
        ("supabase-exposed", include_str!("../scripts/supabase-exposed.rhai")),
        ("jellyfin-exposed", include_str!("../scripts/jellyfin-exposed.rhai")),
        ("immich-exposed", include_str!("../scripts/immich-exposed.rhai")),
        ("n8n-exposed", include_str!("../scripts/n8n-exposed.rhai")),
        ("uptime-kuma-exposed", include_str!("../scripts/uptime-kuma-exposed.rhai")),
        ("minio-console-exposed", include_str!("../scripts/minio-console-exposed.rhai")),
        ("seaweedfs-exposed", include_str!("../scripts/seaweedfs-exposed.rhai")),
        ("modern-redis-fork-info", include_str!("../scripts/modern-redis-fork-info.rhai")),
        ("redpanda-admin-exposed", include_str!("../scripts/redpanda-admin-exposed.rhai")),
        ("coolify-exposed", include_str!("../scripts/coolify-exposed.rhai")),
        ("traefik-dashboard-exposed", include_str!("../scripts/traefik-dashboard-exposed.rhai")),
        ("openobserve-exposed", include_str!("../scripts/openobserve-exposed.rhai")),
        ("signoz-exposed", include_str!("../scripts/signoz-exposed.rhai")),
        ("jaeger-ui-exposed", include_str!("../scripts/jaeger-ui-exposed.rhai")),
        ("loki-exposed", include_str!("../scripts/loki-exposed.rhai")),
        ("victoriametrics-exposed", include_str!("../scripts/victoriametrics-exposed.rhai")),
        ("node-exporter-exposed", include_str!("../scripts/node-exporter-exposed.rhai")),
        ("cadvisor-exposed", include_str!("../scripts/cadvisor-exposed.rhai")),
        ("grafana-alloy-exposed", include_str!("../scripts/grafana-alloy-exposed.rhai")),
        ("http-env-exposed", include_str!("../scripts/http-env-exposed.rhai")),
        ("http-open-dir", include_str!("../scripts/http-open-dir.rhai")),
        ("http-swagger-exposed", include_str!("../scripts/http-swagger-exposed.rhai")),
        ("http-actuator-exposed", include_str!("../scripts/http-actuator-exposed.rhai")),
        ("http-server-status", include_str!("../scripts/http-server-status.rhai")),
        ("http-laravel-debug", include_str!("../scripts/http-laravel-debug.rhai")),
        ("http-ds-store", include_str!("../scripts/http-ds-store.rhai")),
        ("http-adminer", include_str!("../scripts/http-adminer.rhai")),
        ("http-phpmyadmin", include_str!("../scripts/http-phpmyadmin.rhai")),
        ("http-wordpress-detect", include_str!("../scripts/http-wordpress-detect.rhai")),
        ("http-wp-user-enum", include_str!("../scripts/http-wp-user-enum.rhai")),
        ("http-nextjs-detect", include_str!("../scripts/http-nextjs-detect.rhai")),
        ("http-vite-dev", include_str!("../scripts/http-vite-dev.rhai")),
        ("clamav-clamd", include_str!("../scripts/clamav-clamd.rhai")),
        ("zookeeper-ruok", include_str!("../scripts/zookeeper-ruok.rhai")),
        ("nats-info", include_str!("../scripts/nats-info.rhai")),
        ("telnet-exposed", include_str!("../scripts/telnet-exposed.rhai")),
        ("rtsp-options", include_str!("../scripts/rtsp-options.rhai")),
        ("http-trace-enabled", include_str!("../scripts/http-trace-enabled.rhai")),
        ("sonarqube-exposed", include_str!("../scripts/sonarqube-exposed.rhai")),
        ("mongo-express-exposed", include_str!("../scripts/mongo-express-exposed.rhai")),
        ("arangodb-exposed", include_str!("../scripts/arangodb-exposed.rhai")),
        ("couchbase-exposed", include_str!("../scripts/couchbase-exposed.rhai")),
        ("jupyter-no-auth", include_str!("../scripts/jupyter-no-auth.rhai")),
        ("smtp-starttls-check", include_str!("../scripts/smtp-starttls-check.rhai")),
        ("http-xmlrpc-exposed", include_str!("../scripts/http-xmlrpc-exposed.rhai")),
        ("http-phpinfo", include_str!("../scripts/http-phpinfo.rhai")),
        ("docker-registry-exposed", include_str!("../scripts/docker-registry-exposed.rhai")),
        ("nacos-exposed", include_str!("../scripts/nacos-exposed.rhai")),
        ("activemq-openwire", include_str!("../scripts/activemq-openwire.rhai")),
        ("afp-exposed", include_str!("../scripts/afp-exposed.rhai")),
        ("amqp-rabbitmq", include_str!("../scripts/amqp-rabbitmq.rhai")),
        ("bacnet-exposed", include_str!("../scripts/bacnet-exposed.rhai")),
        ("bmc-redfish", include_str!("../scripts/bmc-redfish.rhai")),
        ("cassandra-exposed", include_str!("../scripts/cassandra-exposed.rhai")),
        ("chargen-service", include_str!("../scripts/chargen-service.rhai")),
        ("clickhouse-native", include_str!("../scripts/clickhouse-native.rhai")),
        ("coap-exposed", include_str!("../scripts/coap-exposed.rhai")),
        ("cockpit-exposed", include_str!("../scripts/cockpit-exposed.rhai")),
        ("cockroachdb-exposed", include_str!("../scripts/cockroachdb-exposed.rhai")),
        ("couchdb-native-exp", include_str!("../scripts/couchdb-native-exp.rhai")),
        ("cups-admin-exposed", include_str!("../scripts/cups-admin-exposed.rhai")),
        ("daytime-service", include_str!("../scripts/daytime-service.rhai")),
        ("db2-exposed", include_str!("../scripts/db2-exposed.rhai")),
        ("discard-service", include_str!("../scripts/discard-service.rhai")),
        ("dnp3-exposed", include_str!("../scripts/dnp3-exposed.rhai")),
        ("dot-exposed", include_str!("../scripts/dot-exposed.rhai")),
        ("echo-service", include_str!("../scripts/echo-service.rhai")),
        ("es-transport-exposed", include_str!("../scripts/es-transport-exposed.rhai")),
        ("ethernetip-exposed", include_str!("../scripts/ethernetip-exposed.rhai")),
        ("finger-exposed", include_str!("../scripts/finger-exposed.rhai")),
        ("firebird-exposed", include_str!("../scripts/firebird-exposed.rhai")),
        ("ftp-filezilla", include_str!("../scripts/ftp-filezilla.rhai")),
        ("ftp-microsoft", include_str!("../scripts/ftp-microsoft.rhai")),
        ("ftp-proftpd-detect", include_str!("../scripts/ftp-proftpd-detect.rhai")),
        ("ftp-pureftpd-detect", include_str!("../scripts/ftp-pureftpd-detect.rhai")),
        ("ftp-vsftpd-detect", include_str!("../scripts/ftp-vsftpd-detect.rhai")),
        ("git-daemon-exposed", include_str!("../scripts/git-daemon-exposed.rhai")),
        ("global-catalog-exp", include_str!("../scripts/global-catalog-exp.rhai")),
        ("grafana-3000-exposed", include_str!("../scripts/grafana-3000-exposed.rhai")),
        ("graylog-gelf-exposed", include_str!("../scripts/graylog-gelf-exposed.rhai")),
        ("hbase-master-exposed", include_str!("../scripts/hbase-master-exposed.rhai")),
        ("http-actuator-beans", include_str!("../scripts/http-actuator-beans.rhai")),
        ("http-actuator-loggers", include_str!("../scripts/http-actuator-loggers.rhai")),
        ("http-actuator-mappings", include_str!("../scripts/http-actuator-mappings.rhai")),
        ("http-airflow-detect", include_str!("../scripts/http-airflow-detect.rhai")),
        ("http-apidocs-v3", include_str!("../scripts/http-apidocs-v3.rhai")),
        ("http-app-properties", include_str!("../scripts/http-app-properties.rhai")),
        ("http-app-yml", include_str!("../scripts/http-app-yml.rhai")),
        ("http-apple-site-assoc", include_str!("../scripts/http-apple-site-assoc.rhai")),
        ("http-appsettings", include_str!("../scripts/http-appsettings.rhai")),
        ("http-artifactory", include_str!("../scripts/http-artifactory.rhai")),
        ("http-assetlinks", include_str!("../scripts/http-assetlinks.rhai")),
        ("http-aws-credentials", include_str!("../scripts/http-aws-credentials.rhai")),
        ("http-axis2-admin", include_str!("../scripts/http-axis2-admin.rhai")),
        ("http-bash-history", include_str!("../scripts/http-bash-history.rhai")),
        ("http-cacti-detect", include_str!("../scripts/http-cacti-detect.rhai")),
        ("http-citrix-detect", include_str!("../scripts/http-citrix-detect.rhai")),
        ("http-clientaccess", include_str!("../scripts/http-clientaccess.rhai")),
        ("http-coldfusion", include_str!("../scripts/http-coldfusion.rhai")),
        ("http-composer-json", include_str!("../scripts/http-composer-json.rhai")),
        ("http-consul-ui", include_str!("../scripts/http-consul-ui.rhai")),
        ("http-cpanel-detect", include_str!("../scripts/http-cpanel-detect.rhai")),
        ("http-crossdomain", include_str!("../scripts/http-crossdomain.rhai")),
        ("http-django-admin", include_str!("../scripts/http-django-admin.rhai")),
        ("http-dockerfile", include_str!("../scripts/http-dockerfile.rhai")),
        ("http-druid-console", include_str!("../scripts/http-druid-console.rhai")),
        ("http-drupal-detect", include_str!("../scripts/http-drupal-detect.rhai")),
        ("http-elastichead", include_str!("../scripts/http-elastichead.rhai")),
        ("http-elasticsearch-cat", include_str!("../scripts/http-elasticsearch-cat.rhai")),
        ("http-exchange-ews", include_str!("../scripts/http-exchange-ews.rhai")),
        ("http-flask-debug", include_str!("../scripts/http-flask-debug.rhai")),
        ("http-fortinet-detect", include_str!("../scripts/http-fortinet-detect.rhai")),
        ("http-git-config-file", include_str!("../scripts/http-git-config-file.rhai")),
        ("http-gitlab-detect", include_str!("../scripts/http-gitlab-detect.rhai")),
        ("http-graphql-playground", include_str!("../scripts/http-graphql-playground.rhai")),
        ("http-harbor-detect", include_str!("../scripts/http-harbor-detect.rhai")),
        ("http-hg-exposed", include_str!("../scripts/http-hg-exposed.rhai")),
        ("http-hystrix", include_str!("../scripts/http-hystrix.rhai")),
        ("http-idea-config", include_str!("../scripts/http-idea-config.rhai")),
        ("http-jboss-console", include_str!("../scripts/http-jboss-console.rhai")),
        ("http-jenkins-script", include_str!("../scripts/http-jenkins-script.rhai")),
        ("http-jolokia", include_str!("../scripts/http-jolokia.rhai")),
        ("http-joomla-detect", include_str!("../scripts/http-joomla-detect.rhai")),
        ("http-keycloak-detect", include_str!("../scripts/http-keycloak-detect.rhai")),
        ("http-magento-detect", include_str!("../scripts/http-magento-detect.rhai")),
        ("http-nagios-detect", include_str!("../scripts/http-nagios-detect.rhai")),
        ("http-netrc-exposed", include_str!("../scripts/http-netrc-exposed.rhai")),
        ("http-nexus-detect", include_str!("../scripts/http-nexus-detect.rhai")),
        ("http-npmrc", include_str!("../scripts/http-npmrc.rhai")),
        ("http-oidc-config", include_str!("../scripts/http-oidc-config.rhai")),
        ("http-owa-detect", include_str!("../scripts/http-owa-detect.rhai")),
        ("http-package-json", include_str!("../scripts/http-package-json.rhai")),
        ("http-plesk-detect", include_str!("../scripts/http-plesk-detect.rhai")),
        ("http-prometheus-fed", include_str!("../scripts/http-prometheus-fed.rhai")),
        ("http-pulse-vpn", include_str!("../scripts/http-pulse-vpn.rhai")),
        ("http-rancher-detect", include_str!("../scripts/http-rancher-detect.rhai")),
        ("http-sharepoint", include_str!("../scripts/http-sharepoint.rhai")),
        ("http-solr-admin", include_str!("../scripts/http-solr-admin.rhai")),
        ("http-spring-h2", include_str!("../scripts/http-spring-h2.rhai")),
        ("http-struts-devmode", include_str!("../scripts/http-struts-devmode.rhai")),
        ("http-struts-showcase", include_str!("../scripts/http-struts-showcase.rhai")),
        ("http-superset-detect", include_str!("../scripts/http-superset-detect.rhai")),
        ("http-svn-wcdb", include_str!("../scripts/http-svn-wcdb.rhai")),
        ("http-swagger-ui-html", include_str!("../scripts/http-swagger-ui-html.rhai")),
        ("http-tomcat-examples", include_str!("../scripts/http-tomcat-examples.rhai")),
        ("http-tomcat-manager", include_str!("../scripts/http-tomcat-manager.rhai")),
        ("http-vcenter-detect", include_str!("../scripts/http-vcenter-detect.rhai")),
        ("http-vscode-sftp", include_str!("../scripts/http-vscode-sftp.rhai")),
        ("http-webconfig", include_str!("../scripts/http-webconfig.rhai")),
        ("http-webinf-webxml", include_str!("../scripts/http-webinf-webxml.rhai")),
        ("http-weblogic-console", include_str!("../scripts/http-weblogic-console.rhai")),
        ("http-webmin-detect", include_str!("../scripts/http-webmin-detect.rhai")),
        ("http-wp-debug-log", include_str!("../scripts/http-wp-debug-log.rhai")),
        ("http-wp-login", include_str!("../scripts/http-wp-login.rhai")),
        ("http-wp-xmlrpc-pingback", include_str!("../scripts/http-wp-xmlrpc-pingback.rhai")),
        ("http-wso2-detect", include_str!("../scripts/http-wso2-detect.rhai")),
        ("http-zabbix-detect", include_str!("../scripts/http-zabbix-detect.rhai")),
        ("ident-service", include_str!("../scripts/ident-service.rhai")),
        ("iec104-exposed", include_str!("../scripts/iec104-exposed.rhai")),
        ("imap-courier", include_str!("../scripts/imap-courier.rhai")),
        ("imap-dovecot", include_str!("../scripts/imap-dovecot.rhai")),
        ("ipp-cups-exposed", include_str!("../scripts/ipp-cups-exposed.rhai")),
        ("irc-ngircd", include_str!("../scripts/irc-ngircd.rhai")),
        ("irc-unrealircd", include_str!("../scripts/irc-unrealircd.rhai")),
        ("isakmp-exposed", include_str!("../scripts/isakmp-exposed.rhai")),
        ("iscsi-exposed", include_str!("../scripts/iscsi-exposed.rhai")),
        ("jetdirect-exposed", include_str!("../scripts/jetdirect-exposed.rhai")),
        ("kerberos-exposed", include_str!("../scripts/kerberos-exposed.rhai")),
        ("kibana-5601-exposed", include_str!("../scripts/kibana-5601-exposed.rhai")),
        ("l2tp-exposed", include_str!("../scripts/l2tp-exposed.rhai")),
        ("ldaps-exposed", include_str!("../scripts/ldaps-exposed.rhai")),
        ("logstash-beats-exp", include_str!("../scripts/logstash-beats-exp.rhai")),
        ("lpd-exposed", include_str!("../scripts/lpd-exposed.rhai")),
        ("modbus-exposed", include_str!("../scripts/modbus-exposed.rhai")),
        ("mongodb-banner", include_str!("../scripts/mongodb-banner.rhai")),
        ("mqtt-mosquitto", include_str!("../scripts/mqtt-mosquitto.rhai")),
        ("msrpc-epmap-exposed", include_str!("../scripts/msrpc-epmap-exposed.rhai")),
        ("mysql-mariadb", include_str!("../scripts/mysql-mariadb.rhai")),
        ("mysql-version-bnr", include_str!("../scripts/mysql-version-bnr.rhai")),
        ("netbios-dgram-exp", include_str!("../scripts/netbios-dgram-exp.rhai")),
        ("netbios-name-svc", include_str!("../scripts/netbios-name-svc.rhai")),
        ("niagara-fox-exposed", include_str!("../scripts/niagara-fox-exposed.rhai")),
        ("nrpe-exposed", include_str!("../scripts/nrpe-exposed.rhai")),
        ("nsq-exposed", include_str!("../scripts/nsq-exposed.rhai")),
        ("ntp-banner-detect", include_str!("../scripts/ntp-banner-detect.rhai")),
        ("openvpn-exposed", include_str!("../scripts/openvpn-exposed.rhai")),
        ("oracle-tns-exposed", include_str!("../scripts/oracle-tns-exposed.rhai")),
        ("pcanywhere-exposed", include_str!("../scripts/pcanywhere-exposed.rhai")),
        ("pop3-dovecot", include_str!("../scripts/pop3-dovecot.rhai")),
        ("portmap-service", include_str!("../scripts/portmap-service.rhai")),
        ("postgres-banner", include_str!("../scripts/postgres-banner.rhai")),
        ("pptp-exposed", include_str!("../scripts/pptp-exposed.rhai")),
        ("profinet-exposed", include_str!("../scripts/profinet-exposed.rhai")),
        ("proxmox-exposed", include_str!("../scripts/proxmox-exposed.rhai")),
        ("pulsar-exposed", include_str!("../scripts/pulsar-exposed.rhai")),
        ("rdp-banner-detect", include_str!("../scripts/rdp-banner-detect.rhai")),
        ("rdp-gateway-exposed", include_str!("../scripts/rdp-gateway-exposed.rhai")),
        ("redis-cluster-bus", include_str!("../scripts/redis-cluster-bus.rhai")),
        ("redis-sentinel-exp", include_str!("../scripts/redis-sentinel-exp.rhai")),
        ("redis-version-bnr", include_str!("../scripts/redis-version-bnr.rhai")),
        ("rethinkdb-exposed", include_str!("../scripts/rethinkdb-exposed.rhai")),
        ("rexec-service", include_str!("../scripts/rexec-service.rhai")),
        ("rlogin-service", include_str!("../scripts/rlogin-service.rhai")),
        ("rsh-service", include_str!("../scripts/rsh-service.rhai")),
        ("s7comm-exposed", include_str!("../scripts/s7comm-exposed.rhai")),
        ("sip-asterisk", include_str!("../scripts/sip-asterisk.rhai")),
        ("sip-freeswitch", include_str!("../scripts/sip-freeswitch.rhai")),
        ("sip-tls-exposed", include_str!("../scripts/sip-tls-exposed.rhai")),
        ("smtp-exchange-bnr", include_str!("../scripts/smtp-exchange-bnr.rhai")),
        ("smtp-exim-detect", include_str!("../scripts/smtp-exim-detect.rhai")),
        ("smtp-open-helo", include_str!("../scripts/smtp-open-helo.rhai")),
        ("smtp-postfix", include_str!("../scripts/smtp-postfix.rhai")),
        ("smtp-sendmail", include_str!("../scripts/smtp-sendmail.rhai")),
        ("snmptrap-service", include_str!("../scripts/snmptrap-service.rhai")),
        ("splunkd-mgmt-exposed", include_str!("../scripts/splunkd-mgmt-exposed.rhai")),
        ("ssh-cisco-detect", include_str!("../scripts/ssh-cisco-detect.rhai")),
        ("ssh-dropbear-detect", include_str!("../scripts/ssh-dropbear-detect.rhai")),
        ("ssh-huawei-detect", include_str!("../scripts/ssh-huawei-detect.rhai")),
        ("ssh-libssh", include_str!("../scripts/ssh-libssh.rhai")),
        ("ssh-mikrotik-detect", include_str!("../scripts/ssh-mikrotik-detect.rhai")),
        ("ssh-paramiko", include_str!("../scripts/ssh-paramiko.rhai")),
        ("svn-exposed", include_str!("../scripts/svn-exposed.rhai")),
        ("telnet-busybox", include_str!("../scripts/telnet-busybox.rhai")),
        ("telnet-cisco-detect", include_str!("../scripts/telnet-cisco-detect.rhai")),
        ("telnet-linux-login", include_str!("../scripts/telnet-linux-login.rhai")),
        ("tftp-service", include_str!("../scripts/tftp-service.rhai")),
        ("upnp-exposed", include_str!("../scripts/upnp-exposed.rhai")),
        ("vmware-authd", include_str!("../scripts/vmware-authd.rhai")),
        ("vmware-vsphere-8443", include_str!("../scripts/vmware-vsphere-8443.rhai")),
        ("vnc-http-exposed", include_str!("../scripts/vnc-http-exposed.rhai")),
        ("vnc-version-bnr", include_str!("../scripts/vnc-version-bnr.rhai")),
        ("winbox-exposed", include_str!("../scripts/winbox-exposed.rhai")),
        ("winrm-http-exposed", include_str!("../scripts/winrm-http-exposed.rhai")),
        ("winrm-https-exposed", include_str!("../scripts/winrm-https-exposed.rhai")),
        ("x11-6001-exposed", include_str!("../scripts/x11-6001-exposed.rhai")),
        ("x11-open-detect", include_str!("../scripts/x11-open-detect.rhai")),
        ("zabbix-agent-exposed", include_str!("../scripts/zabbix-agent-exposed.rhai")),
        ("zeromq-exposed", include_str!("../scripts/zeromq-exposed.rhai")),
    ]
}

use std::sync::atomic::{AtomicBool, Ordering};
static SCRIPT_TRACE: AtomicBool = AtomicBool::new(false);

pub fn set_trace(on: bool) {
    SCRIPT_TRACE.store(on, Ordering::Relaxed);
}

fn trace_event(script: &str, host: &str, status: &str, detail: &str) {
    if !SCRIPT_TRACE.load(Ordering::Relaxed) {
        return;
    }
    // JSON Lines so the user can pipe stderr into jq.
    let now = chrono::Utc::now().to_rfc3339();
    eprintln!(
        "{{\"ts\":\"{}\",\"script\":\"{}\",\"host\":\"{}\",\"status\":\"{}\",\"detail\":{}}}",
        now,
        script,
        host,
        status,
        serde_json::to_string(detail).unwrap_or_else(|_| "\"\"".into())
    );
}

/// Build a rhai Engine with our network/probe primitives registered.
/// Used by both run_inline and run_scripts so file-based scripts get
/// the same active-probe API as the built-ins.
fn build_engine() -> Engine {
    let mut engine = Engine::new();
    // The default expression depth (64/32) trips on our larger built-ins
    // (cookie-flags-audit, etc.) when string interpolation nests deeply.
    engine.set_max_expr_depths(128, 64);

    // tcp_send(host, port, payload_string, timeout_ms) -> reply_string
    // Truncates the reply to 8 KiB. Returns "" on any failure.
    engine.register_fn("tcp_send", |host: &str, port: i64, payload: &str, timeout_ms: i64| -> String {
        let timeout = Duration::from_millis(timeout_ms.clamp(50, 30_000) as u64);
        let port = port.clamp(1, 65535) as u16;
        let mut addrs = match (host, port).to_socket_addrs() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };
        let addr = match addrs.next() {
            Some(a) => a,
            None => return String::new(),
        };
        let mut s = match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };
        let _ = s.set_read_timeout(Some(timeout));
        let _ = s.set_write_timeout(Some(timeout));
        if !payload.is_empty() && s.write_all(payload.as_bytes()).is_err() {
            return String::new();
        }
        let mut buf = [0u8; 8192];
        match s.read(&mut buf) {
            Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            Err(_) => String::new(),
        }
    });

    // udp_send(host, port, payload_string, timeout_ms) -> reply_string
    // Truncates the reply to 8 KiB. Returns "" on any failure.
    engine.register_fn("udp_send", |host: &str, port: i64, payload: &str, timeout_ms: i64| -> String {
        let timeout = Duration::from_millis(timeout_ms.clamp(50, 30_000) as u64);
        let port = port.clamp(1, 65535) as u16;
        let mut addrs = match (host, port).to_socket_addrs() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };
        let addr = match addrs.next() {
            Some(a) => a,
            None => return String::new(),
        };
        let sock = match std::net::UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };
        let _ = sock.set_read_timeout(Some(timeout));
        let _ = sock.set_write_timeout(Some(timeout));
        if sock.send_to(payload.as_bytes(), addr).is_err() {
            return String::new();
        }
        let mut buf = [0u8; 8192];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            Err(_) => String::new(),
        }
    });

    // hex_encode(s) / hex_decode(s) — operate on raw bytes of s
    engine.register_fn("hex_encode", |s: &str| -> String {
        s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
    });
    engine.register_fn("hex_decode", |s: &str| -> String {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16);
            let lo = (bytes[i + 1] as char).to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                _ => return String::new(),
            }
            i += 2;
        }
        String::from_utf8_lossy(&out).into_owned()
    });

    // base64_encode / base64_decode
    engine.register_fn("base64_encode", |s: &str| -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    });
    engine.register_fn("base64_decode", |s: &str| -> String {
        use base64::Engine as _;
        match base64::engine::general_purpose::STANDARD.decode(s) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(_) => String::new(),
        }
    });

    // Hash helpers — return lowercase-hex digests.
    engine.register_fn("md5", |s: &str| -> String {
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(s.as_bytes());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    });
    engine.register_fn("sha1", |s: &str| -> String {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(s.as_bytes());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    });
    engine.register_fn("sha256", |s: &str| -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(s.as_bytes());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    });
    engine.register_fn("hmac_sha256", |key: &str, msg: &str| -> String {
        use hmac::Mac;
        let mut mac = match hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()) {
            Ok(m) => m,
            Err(_) => return String::new(),
        };
        mac.update(msg.as_bytes());
        mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
    });

    // Regex helpers — failed compiles return false/empty as appropriate.
    engine.register_fn("regex_match", |pattern: &str, text: &str| -> bool {
        regex::Regex::new(pattern).map(|r| r.is_match(text)).unwrap_or(false)
    });
    engine.register_fn("regex_capture", |pattern: &str, text: &str| -> String {
        let r = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return String::new(),
        };
        r.captures(text)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_default()
    });
    engine.register_fn("regex_find_all", |pattern: &str, text: &str| -> Array {
        let r = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Array::new(),
        };
        r.find_iter(text)
            .map(|m| Dynamic::from(m.as_str().to_string()))
            .collect()
    });

    // sleep_ms(ms) — clamped to 5s so a runaway script can't stall the run.
    engine.register_fn("sleep_ms", |ms: i64| {
        let dur = Duration::from_millis(ms.clamp(0, 5_000) as u64);
        std::thread::sleep(dur);
    });

    // is_private_ip(s) — checks RFC1918 / link-local / loopback / ULA.
    engine.register_fn("is_private_ip", |s: &str| -> bool {
        match s.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => {
                a.is_private() || a.is_loopback() || a.is_link_local()
            }
            Ok(std::net::IpAddr::V6(a)) => {
                a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
            }
            Err(_) => false,
        }
    });

    // http_get(url, timeout_ms) -> map { status: i64, body: string, headers: string }
    // Uses reqwest::blocking with rustls. Returns map with status=0 on error.
    engine.register_fn("http_get", |url: &str, timeout_ms: i64| -> Map {
        use reqwest::blocking::Client;
        let timeout = Duration::from_millis(timeout_ms.clamp(50, 30_000) as u64);
        let mut out = Map::new();
        let client = match Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .user_agent("rustymap/script")
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                out.insert("status".into(), Dynamic::from(0i64));
                out.insert("body".into(), Dynamic::from(String::new()));
                out.insert("headers".into(), Dynamic::from(String::new()));
                return out;
            }
        };
        match client.get(url).send() {
            Ok(resp) => {
                let status = resp.status().as_u16() as i64;
                let headers: String = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\r\n");
                let body = resp.text().unwrap_or_default();
                let truncated: String = body.chars().take(8192).collect();
                out.insert("status".into(), Dynamic::from(status));
                out.insert("body".into(), Dynamic::from(truncated));
                out.insert("headers".into(), Dynamic::from(headers));
            }
            Err(_) => {
                out.insert("status".into(), Dynamic::from(0i64));
                out.insert("body".into(), Dynamic::from(String::new()));
                out.insert("headers".into(), Dynamic::from(String::new()));
            }
        }
        out
    });

    engine
}

/// Run a list of (name, source) scripts against a host set.
pub fn run_inline(
    scripts: &[(&str, &str)],
    hosts: &[HostResult],
    script_args: &[(String, String)],
) -> Vec<Finding> {
    if scripts.is_empty() {
        return Vec::new();
    }
    let engine = build_engine();
    let args_map: Map = script_args
        .iter()
        .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
        .collect();
    let mut findings = Vec::new();

    for (name, src) in scripts {
        let ast = match engine.compile(*src) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[script {}] parse error: {}", name, e);
                trace_event(name, "-", "parse_error", &e.to_string());
                continue;
            }
        };
        for h in hosts {
            if !h.up {
                continue;
            }
            let host_map = host_to_map(h);
            let mut scope = Scope::new();
            scope.push_dynamic("host", Dynamic::from(host_map));
            scope.push_dynamic("args", Dynamic::from(args_map.clone()));
            scope.push_dynamic("findings", Dynamic::from(Array::new()));
            let host_s = h.target.ip.to_string();
            trace_event(name, &host_s, "start", "");
            if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
                eprintln!("[script {} host {}] runtime error: {}", name, h.target.ip, e);
                trace_event(name, &host_s, "runtime_error", &e.to_string());
                continue;
            }
            let mut emitted = 0usize;
            if let Some(arr) = scope.get_value::<Array>("findings") {
                for v in arr {
                    if let Some(m) = v.try_cast::<Map>() {
                        let sev = m.get("severity").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_else(|| "info".into());
                        let msg = m.get("message").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_default();
                        let port = m.get("port").and_then(|d| d.as_int().ok()).map(|i| i as u16);
                        findings.push(Finding {
                            script: name.to_string(),
                            host: host_s.clone(),
                            port,
                            severity: sev,
                            message: msg,
                        });
                        emitted += 1;
                    }
                }
            }
            trace_event(name, &host_s, "done", &format!("{} finding(s)", emitted));
        }
    }
    findings
}

pub fn run_scripts(
    scripts_path: &str,
    hosts: &[HostResult],
    script_args: &[(String, String)],
) -> Result<Vec<Finding>> {
    let path = Path::new(scripts_path);
    let scripts = discover_scripts(path)?;
    if scripts.is_empty() {
        return Ok(vec![]);
    }

    let engine = build_engine();
    let mut findings = Vec::new();
    let args_map: Map = script_args
        .iter()
        .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
        .collect();

    for script_path in &scripts {
        let src = fs::read_to_string(script_path)
            .with_context(|| format!("read {:?}", script_path))?;
        let script_name = script_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("script")
            .to_string();

        let ast = match engine.compile(&src) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[script {}] parse error: {}", script_name, e);
                continue;
            }
        };

        for h in hosts {
            if !h.up {
                continue;
            }
            let host_map = host_to_map(h);
            let mut scope = Scope::new();
            scope.push_dynamic("host", Dynamic::from(host_map));
            scope.push_dynamic("args", Dynamic::from(args_map.clone()));
            scope.push_dynamic("findings", Dynamic::from(Array::new()));

            if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
                eprintln!("[script {} host {}] runtime error: {}", script_name, h.target.ip, e);
                continue;
            }

            if let Some(arr) = scope.get_value::<Array>("findings") {
                for v in arr {
                    if let Some(m) = v.try_cast::<Map>() {
                        let sev = m.get("severity").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_else(|| "info".into());
                        let msg = m.get("message").and_then(|d| d.clone().into_string().ok())
                            .unwrap_or_default();
                        let port = m.get("port").and_then(|d| d.as_int().ok()).map(|i| i as u16);
                        findings.push(Finding {
                            script: script_name.clone(),
                            host: h.target.ip.to_string(),
                            port,
                            severity: sev,
                            message: msg,
                        });
                    }
                }
            }
        }
    }

    Ok(findings)
}

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("\n-- Script findings --");
    for f in findings {
        let loc = match f.port {
            Some(p) => format!("{}:{}", f.host, p),
            None => f.host.clone(),
        };
        println!("  [{}] {} ({}) — {}", f.severity, loc, f.script, f.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_scripts_parse() {
        let engine = build_engine();
        for (name, src) in builtin_scripts() {
            engine
                .compile(src)
                .unwrap_or_else(|e| panic!("builtin script {} failed to parse: {}", name, e));
        }
    }

    #[test]
    fn new_sdk_primitives_work() {
        let engine = build_engine();
        // Smoke-test the encoding + hash + regex helpers via eval.
        let hex: String = engine.eval(r#"hex_encode("ab")"#).unwrap();
        assert_eq!(hex, "6162");
        let back: String = engine.eval(r#"hex_decode("6162")"#).unwrap();
        assert_eq!(back, "ab");
        let b64: String = engine.eval(r#"base64_encode("hi")"#).unwrap();
        assert_eq!(b64, "aGk=");
        let b64b: String = engine.eval(r#"base64_decode("aGk=")"#).unwrap();
        assert_eq!(b64b, "hi");
        let md: String = engine.eval(r#"md5("abc")"#).unwrap();
        assert_eq!(md, "900150983cd24fb0d6963f7d28e17f72");
        let sh1: String = engine.eval(r#"sha1("abc")"#).unwrap();
        assert_eq!(sh1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        let sh256: String = engine.eval(r#"sha256("abc")"#).unwrap();
        assert_eq!(sh256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let rm: bool = engine.eval(r#"regex_match("foo\\d+", "foo42")"#).unwrap();
        assert!(rm);
        let rc: String = engine.eval(r#"regex_capture("v(\\d+)", "v123")"#).unwrap();
        assert_eq!(rc, "123");
        let priv1: bool = engine.eval(r#"is_private_ip("10.1.2.3")"#).unwrap();
        assert!(priv1);
        let priv2: bool = engine.eval(r#"is_private_ip("8.8.8.8")"#).unwrap();
        assert!(!priv2);
    }
}
