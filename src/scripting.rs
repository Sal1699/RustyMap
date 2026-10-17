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
        ("http-phpmyadmin-detect", include_str!("../scripts/http-phpmyadmin-detect.rhai")),
        ("http-adminer-detect", include_str!("../scripts/http-adminer-detect.rhai")),
        ("http-grafana-login", include_str!("../scripts/http-grafana-login.rhai")),
        ("http-kibana-app", include_str!("../scripts/http-kibana-app.rhai")),
        ("http-rundeck-detect", include_str!("../scripts/http-rundeck-detect.rhai")),
        ("http-artifactory-detect", include_str!("../scripts/http-artifactory-detect.rhai")),
        ("http-sonarqube-detect", include_str!("../scripts/http-sonarqube-detect.rhai")),
        ("http-confluence-detect", include_str!("../scripts/http-confluence-detect.rhai")),
        ("http-jira-detect", include_str!("../scripts/http-jira-detect.rhai")),
        ("http-bamboo-detect", include_str!("../scripts/http-bamboo-detect.rhai")),
        ("http-bitbucket-detect", include_str!("../scripts/http-bitbucket-detect.rhai")),
        ("http-teamcity-detect", include_str!("../scripts/http-teamcity-detect.rhai")),
        ("http-gocd-detect", include_str!("../scripts/http-gocd-detect.rhai")),
        ("http-nomad-detect", include_str!("../scripts/http-nomad-detect.rhai")),
        ("http-traefik-dashboard", include_str!("../scripts/http-traefik-dashboard.rhai")),
        ("http-haproxy-stats", include_str!("../scripts/http-haproxy-stats.rhai")),
        ("http-librenms-detect", include_str!("../scripts/http-librenms-detect.rhai")),
        ("http-netdata-detect", include_str!("../scripts/http-netdata-detect.rhai")),
        ("http-cockpit-detect", include_str!("../scripts/http-cockpit-detect.rhai")),
        ("http-ispconfig-detect", include_str!("../scripts/http-ispconfig-detect.rhai")),
        ("http-directadmin-detect", include_str!("../scripts/http-directadmin-detect.rhai")),
        ("http-virtualmin-detect", include_str!("../scripts/http-virtualmin-detect.rhai")),
        ("http-phpinfo-exposed", include_str!("../scripts/http-phpinfo-exposed.rhai")),
        ("http-prestashop-detect", include_str!("../scripts/http-prestashop-detect.rhai")),
        ("http-opencart-detect", include_str!("../scripts/http-opencart-detect.rhai")),
        ("http-moodle-detect", include_str!("../scripts/http-moodle-detect.rhai")),
        ("http-mediawiki-detect", include_str!("../scripts/http-mediawiki-detect.rhai")),
        ("http-dokuwiki-detect", include_str!("../scripts/http-dokuwiki-detect.rhai")),
        ("http-nextcloud-detect", include_str!("../scripts/http-nextcloud-detect.rhai")),
        ("http-owncloud-detect", include_str!("../scripts/http-owncloud-detect.rhai")),
        ("http-seafile-detect", include_str!("../scripts/http-seafile-detect.rhai")),
        ("http-rocketchat-detect", include_str!("../scripts/http-rocketchat-detect.rhai")),
        ("http-mattermost-detect", include_str!("../scripts/http-mattermost-detect.rhai")),
        ("http-discourse-detect", include_str!("../scripts/http-discourse-detect.rhai")),
        ("http-phpbb-detect", include_str!("../scripts/http-phpbb-detect.rhai")),
        ("http-roundcube-detect", include_str!("../scripts/http-roundcube-detect.rhai")),
        ("http-horde-detect", include_str!("../scripts/http-horde-detect.rhai")),
        ("http-zimbra-detect", include_str!("../scripts/http-zimbra-detect.rhai")),
        ("http-pfsense-detect", include_str!("../scripts/http-pfsense-detect.rhai")),
        ("http-opnsense-detect", include_str!("../scripts/http-opnsense-detect.rhai")),
        ("http-mikrotik-webfig", include_str!("../scripts/http-mikrotik-webfig.rhai")),
        ("http-unifi-detect", include_str!("../scripts/http-unifi-detect.rhai")),
        ("http-synology-dsm", include_str!("../scripts/http-synology-dsm.rhai")),
        ("http-qnap-detect", include_str!("../scripts/http-qnap-detect.rhai")),
        ("http-truenas-detect", include_str!("../scripts/http-truenas-detect.rhai")),
        ("http-proxmox-detect", include_str!("../scripts/http-proxmox-detect.rhai")),
        ("http-minio-console", include_str!("../scripts/http-minio-console.rhai")),
        ("http-vault-ui", include_str!("../scripts/http-vault-ui.rhai")),
        ("http-nacos-detect", include_str!("../scripts/http-nacos-detect.rhai")),
        ("http-swagger-ui-detect", include_str!("../scripts/http-swagger-ui-detect.rhai")),
        ("http-graphiql-detect", include_str!("../scripts/http-graphiql-detect.rhai")),
        ("http-prometheus-ui", include_str!("../scripts/http-prometheus-ui.rhai")),
        ("http-alertmanager-ui", include_str!("../scripts/http-alertmanager-ui.rhai")),
        ("http-jaeger-ui", include_str!("../scripts/http-jaeger-ui.rhai")),
        ("http-argocd-detect", include_str!("../scripts/http-argocd-detect.rhai")),
        ("http-vmware-vcenter", include_str!("../scripts/http-vmware-vcenter.rhai")),
        ("http-citrix-adc", include_str!("../scripts/http-citrix-adc.rhai")),
        ("http-f5-bigip", include_str!("../scripts/http-f5-bigip.rhai")),
        ("http-paloalto-gp", include_str!("../scripts/http-paloalto-gp.rhai")),
        ("http-sonicwall-detect", include_str!("../scripts/http-sonicwall-detect.rhai")),
        ("http-hikvision-detect", include_str!("../scripts/http-hikvision-detect.rhai")),
        ("http-dahua-detect", include_str!("../scripts/http-dahua-detect.rhai")),
        ("http-axis-camera", include_str!("../scripts/http-axis-camera.rhai")),
        ("http-metabase-detect", include_str!("../scripts/http-metabase-detect.rhai")),
        ("http-redash-detect", include_str!("../scripts/http-redash-detect.rhai")),
        ("http-n8n-detect", include_str!("../scripts/http-n8n-detect.rhai")),
        ("http-nodered-detect", include_str!("../scripts/http-nodered-detect.rhai")),
        ("http-homeassistant-detect", include_str!("../scripts/http-homeassistant-detect.rhai")),
        ("http-openhab-detect", include_str!("../scripts/http-openhab-detect.rhai")),
        ("http-pihole-admin", include_str!("../scripts/http-pihole-admin.rhai")),
        ("http-observium-detect", include_str!("../scripts/http-observium-detect.rhai")),
        ("http-zoneminder-detect", include_str!("../scripts/http-zoneminder-detect.rhai")),
        ("http-emby-detect", include_str!("../scripts/http-emby-detect.rhai")),
        ("http-jellyfin-detect", include_str!("../scripts/http-jellyfin-detect.rhai")),
        ("http-plex-detect", include_str!("../scripts/http-plex-detect.rhai")),
        ("http-sonarr-detect", include_str!("../scripts/http-sonarr-detect.rhai")),
        ("http-radarr-detect", include_str!("../scripts/http-radarr-detect.rhai")),
        ("http-transmission-rpc", include_str!("../scripts/http-transmission-rpc.rhai")),
        ("http-qbittorrent-detect", include_str!("../scripts/http-qbittorrent-detect.rhai")),
        ("http-sabnzbd-detect", include_str!("../scripts/http-sabnzbd-detect.rhai")),
        ("http-gitea-detect", include_str!("../scripts/http-gitea-detect.rhai")),
        ("http-gogs-detect", include_str!("../scripts/http-gogs-detect.rhai")),
        ("http-woodpecker-ci", include_str!("../scripts/http-woodpecker-ci.rhai")),
        ("http-codeserver-detect", include_str!("../scripts/http-codeserver-detect.rhai")),
        ("http-jupyter-detect", include_str!("../scripts/http-jupyter-detect.rhai")),
        ("http-jupyterhub-detect", include_str!("../scripts/http-jupyterhub-detect.rhai")),
        ("http-rstudio-detect", include_str!("../scripts/http-rstudio-detect.rhai")),
        ("http-zeppelin-detect", include_str!("../scripts/http-zeppelin-detect.rhai")),
        ("http-mlflow-detect", include_str!("../scripts/http-mlflow-detect.rhai")),
        ("http-ray-dashboard", include_str!("../scripts/http-ray-dashboard.rhai")),
        ("http-nifi-detect", include_str!("../scripts/http-nifi-detect.rhai")),
        ("http-airflow-login", include_str!("../scripts/http-airflow-login.rhai")),
        ("http-camunda-detect", include_str!("../scripts/http-camunda-detect.rhai")),
        ("http-keycloak-admin", include_str!("../scripts/http-keycloak-admin.rhai")),
        ("http-authentik-detect", include_str!("../scripts/http-authentik-detect.rhai")),
        ("http-authelia-detect", include_str!("../scripts/http-authelia-detect.rhai")),
        ("http-casdoor-detect", include_str!("../scripts/http-casdoor-detect.rhai")),
        ("http-zitadel-detect", include_str!("../scripts/http-zitadel-detect.rhai")),
        ("http-wekan-detect", include_str!("../scripts/http-wekan-detect.rhai")),
        ("http-focalboard-detect", include_str!("../scripts/http-focalboard-detect.rhai")),
        ("http-vikunja-detect", include_str!("../scripts/http-vikunja-detect.rhai")),
        ("http-bookstack-detect", include_str!("../scripts/http-bookstack-detect.rhai")),
        ("http-wikijs-detect", include_str!("../scripts/http-wikijs-detect.rhai")),
        ("http-outline-detect", include_str!("../scripts/http-outline-detect.rhai")),
        ("http-paperless-detect", include_str!("../scripts/http-paperless-detect.rhai")),
        ("http-vaultwarden-detect", include_str!("../scripts/http-vaultwarden-detect.rhai")),
        ("http-bitwarden-detect", include_str!("../scripts/http-bitwarden-detect.rhai")),
        ("http-firefly-detect", include_str!("../scripts/http-firefly-detect.rhai")),
        ("http-grocy-detect", include_str!("../scripts/http-grocy-detect.rhai")),
        ("http-uptime-kuma", include_str!("../scripts/http-uptime-kuma.rhai")),
        ("http-statping-detect", include_str!("../scripts/http-statping-detect.rhai")),
        ("http-healthchecks-detect", include_str!("../scripts/http-healthchecks-detect.rhai")),
        ("http-gotify-detect", include_str!("../scripts/http-gotify-detect.rhai")),
        ("http-ntfy-detect", include_str!("../scripts/http-ntfy-detect.rhai")),
        ("http-changedetection-detect", include_str!("../scripts/http-changedetection-detect.rhai")),
        ("ssh-libssh-banner", include_str!("../scripts/ssh-libssh-banner.rhai")),
        ("ssh-paramiko-banner", include_str!("../scripts/ssh-paramiko-banner.rhai")),
        ("ssh-cisco-banner", include_str!("../scripts/ssh-cisco-banner.rhai")),
        ("ssh-mikrotik-banner", include_str!("../scripts/ssh-mikrotik-banner.rhai")),
        ("ssh-tectia-banner", include_str!("../scripts/ssh-tectia-banner.rhai")),
        ("ssh-bitvise-banner", include_str!("../scripts/ssh-bitvise-banner.rhai")),
        ("ssh-gitlab-shell-banner", include_str!("../scripts/ssh-gitlab-shell-banner.rhai")),
        ("ftp-filezilla-banner", include_str!("../scripts/ftp-filezilla-banner.rhai")),
        ("ftp-msftpd-banner", include_str!("../scripts/ftp-msftpd-banner.rhai")),
        ("ftp-servu-banner", include_str!("../scripts/ftp-servu-banner.rhai")),
        ("ftp-bftpd-banner", include_str!("../scripts/ftp-bftpd-banner.rhai")),
        ("ftp-pyftpdlib-banner", include_str!("../scripts/ftp-pyftpdlib-banner.rhai")),
        ("smtp-postfix-banner", include_str!("../scripts/smtp-postfix-banner.rhai")),
        ("smtp-exim-banner", include_str!("../scripts/smtp-exim-banner.rhai")),
        ("smtp-sendmail-banner", include_str!("../scripts/smtp-sendmail-banner.rhai")),
        ("smtp-exchange-banner", include_str!("../scripts/smtp-exchange-banner.rhai")),
        ("smtp-opensmtpd-banner", include_str!("../scripts/smtp-opensmtpd-banner.rhai")),
        ("smtp-haraka-banner", include_str!("../scripts/smtp-haraka-banner.rhai")),
        ("smtp-submission-postfix", include_str!("../scripts/smtp-submission-postfix.rhai")),
        ("imap-dovecot-banner", include_str!("../scripts/imap-dovecot-banner.rhai")),
        ("imap-courier-banner", include_str!("../scripts/imap-courier-banner.rhai")),
        ("imap-cyrus-banner", include_str!("../scripts/imap-cyrus-banner.rhai")),
        ("imap-exchange-banner", include_str!("../scripts/imap-exchange-banner.rhai")),
        ("pop3-dovecot-banner", include_str!("../scripts/pop3-dovecot-banner.rhai")),
        ("pop3-courier-banner", include_str!("../scripts/pop3-courier-banner.rhai")),
        ("pop3-qpopper-banner", include_str!("../scripts/pop3-qpopper-banner.rhai")),
        ("dns-bind-banner", include_str!("../scripts/dns-bind-banner.rhai")),
        ("dns-powerdns-banner", include_str!("../scripts/dns-powerdns-banner.rhai")),
        ("dns-unbound-banner", include_str!("../scripts/dns-unbound-banner.rhai")),
        ("dns-knot-banner", include_str!("../scripts/dns-knot-banner.rhai")),
        ("dns-nsd-banner", include_str!("../scripts/dns-nsd-banner.rhai")),
        ("dns-coredns-banner", include_str!("../scripts/dns-coredns-banner.rhai")),
        ("telnet-cisco-banner", include_str!("../scripts/telnet-cisco-banner.rhai")),
        ("telnet-linux-banner", include_str!("../scripts/telnet-linux-banner.rhai")),
        ("telnet-busybox-banner", include_str!("../scripts/telnet-busybox-banner.rhai")),
        ("telnet-hp-banner", include_str!("../scripts/telnet-hp-banner.rhai")),
        ("db-mariadb-banner", include_str!("../scripts/db-mariadb-banner.rhai")),
        ("db-percona-banner", include_str!("../scripts/db-percona-banner.rhai")),
        ("db-postgres-banner", include_str!("../scripts/db-postgres-banner.rhai")),
        ("db-mongodb-banner", include_str!("../scripts/db-mongodb-banner.rhai")),
        ("db-redis-banner", include_str!("../scripts/db-redis-banner.rhai")),
        ("db-memcached-banner", include_str!("../scripts/db-memcached-banner.rhai")),
        ("db-cassandra-banner", include_str!("../scripts/db-cassandra-banner.rhai")),
        ("db-couchdb-banner", include_str!("../scripts/db-couchdb-banner.rhai")),
        ("db-influxdb-banner", include_str!("../scripts/db-influxdb-banner.rhai")),
        ("db-elasticsearch-banner", include_str!("../scripts/db-elasticsearch-banner.rhai")),
        ("db-oracle-tns-banner", include_str!("../scripts/db-oracle-tns-banner.rhai")),
        ("db-mssql-banner", include_str!("../scripts/db-mssql-banner.rhai")),
        ("db-db2-banner", include_str!("../scripts/db-db2-banner.rhai")),
        ("db-cockroach-banner", include_str!("../scripts/db-cockroach-banner.rhai")),
        ("db-neo4j-banner", include_str!("../scripts/db-neo4j-banner.rhai")),
        ("db-arangodb-banner", include_str!("../scripts/db-arangodb-banner.rhai")),
        ("db-rethinkdb-banner", include_str!("../scripts/db-rethinkdb-banner.rhai")),
        ("db-clickhouse-native", include_str!("../scripts/db-clickhouse-native.rhai")),
        ("ldap-openldap-banner", include_str!("../scripts/ldap-openldap-banner.rhai")),
        ("ldap-ad-banner", include_str!("../scripts/ldap-ad-banner.rhai")),
        ("rdp-banner-info", include_str!("../scripts/rdp-banner-info.rhai")),
        ("vnc-realvnc-banner", include_str!("../scripts/vnc-realvnc-banner.rhai")),
        ("vnc-tightvnc-banner", include_str!("../scripts/vnc-tightvnc-banner.rhai")),
        ("vnc-tigervnc-banner", include_str!("../scripts/vnc-tigervnc-banner.rhai")),
        ("ntp-banner-info", include_str!("../scripts/ntp-banner-info.rhai")),
        ("sip-asterisk-banner", include_str!("../scripts/sip-asterisk-banner.rhai")),
        ("sip-freeswitch-banner", include_str!("../scripts/sip-freeswitch-banner.rhai")),
        ("sip-kamailio-banner", include_str!("../scripts/sip-kamailio-banner.rhai")),
        ("mqtt-mosquitto-banner", include_str!("../scripts/mqtt-mosquitto-banner.rhai")),
        ("amqp-rabbitmq-banner", include_str!("../scripts/amqp-rabbitmq-banner.rhai")),
        ("amqp-activemq-banner", include_str!("../scripts/amqp-activemq-banner.rhai")),
        ("nats-banner-info", include_str!("../scripts/nats-banner-info.rhai")),
        ("kafka-banner-info", include_str!("../scripts/kafka-banner-info.rhai")),
        ("zookeeper-banner-info", include_str!("../scripts/zookeeper-banner-info.rhai")),
        ("rpcbind-banner-info", include_str!("../scripts/rpcbind-banner-info.rhai")),
        ("rsync-banner-info", include_str!("../scripts/rsync-banner-info.rhai")),
        ("x11-banner-info", include_str!("../scripts/x11-banner-info.rhai")),
        ("irc-ircd-banner", include_str!("../scripts/irc-ircd-banner.rhai")),
        ("irc-unrealircd-banner", include_str!("../scripts/irc-unrealircd-banner.rhai")),
        ("xmpp-ejabberd-banner", include_str!("../scripts/xmpp-ejabberd-banner.rhai")),
        ("xmpp-prosody-banner", include_str!("../scripts/xmpp-prosody-banner.rhai")),
        ("http-apache-banner", include_str!("../scripts/http-apache-banner.rhai")),
        ("http-nginx-banner", include_str!("../scripts/http-nginx-banner.rhai")),
        ("http-iis-banner", include_str!("../scripts/http-iis-banner.rhai")),
        ("http-lighttpd-banner", include_str!("../scripts/http-lighttpd-banner.rhai")),
        ("http-caddy-banner", include_str!("../scripts/http-caddy-banner.rhai")),
        ("http-openresty-banner", include_str!("../scripts/http-openresty-banner.rhai")),
        ("http-tomcat-banner", include_str!("../scripts/http-tomcat-banner.rhai")),
        ("http-jetty-banner", include_str!("../scripts/http-jetty-banner.rhai")),
        ("http-gunicorn-banner", include_str!("../scripts/http-gunicorn-banner.rhai")),
        ("http-uvicorn-banner", include_str!("../scripts/http-uvicorn-banner.rhai")),
        ("http-kestrel-banner", include_str!("../scripts/http-kestrel-banner.rhai")),
        ("http-werkzeug-banner", include_str!("../scripts/http-werkzeug-banner.rhai")),
        ("coap-banner-info", include_str!("../scripts/coap-banner-info.rhai")),
        ("modbus-banner-info", include_str!("../scripts/modbus-banner-info.rhai")),
        ("bacnet-banner-info", include_str!("../scripts/bacnet-banner-info.rhai")),
        ("s7-banner-info", include_str!("../scripts/s7-banner-info.rhai")),
        ("dnp3-banner-info", include_str!("../scripts/dnp3-banner-info.rhai")),
        ("ethernetip-banner-info", include_str!("../scripts/ethernetip-banner-info.rhai")),
        ("iec104-banner-info", include_str!("../scripts/iec104-banner-info.rhai")),
        ("pjl-printer-banner", include_str!("../scripts/pjl-printer-banner.rhai")),
        ("ipp-printer-banner", include_str!("../scripts/ipp-printer-banner.rhai")),
        ("winrm-banner-info", include_str!("../scripts/winrm-banner-info.rhai")),
        ("docker-registry-banner", include_str!("../scripts/docker-registry-banner.rhai")),
        ("git-daemon-banner", include_str!("../scripts/git-daemon-banner.rhai")),
        ("svn-banner-info", include_str!("../scripts/svn-banner-info.rhai")),
        ("mumble-banner-info", include_str!("../scripts/mumble-banner-info.rhai")),
        ("teamspeak-banner-info", include_str!("../scripts/teamspeak-banner-info.rhai")),
        ("minecraft-banner-info", include_str!("../scripts/minecraft-banner-info.rhai")),
        ("rtsp-banner-info", include_str!("../scripts/rtsp-banner-info.rhai")),
        ("srt-banner-info", include_str!("../scripts/srt-banner-info.rhai")),
        ("sphinx-banner-info", include_str!("../scripts/sphinx-banner-info.rhai")),
        ("riak-banner-info", include_str!("../scripts/riak-banner-info.rhai")),
        ("scylla-banner-info", include_str!("../scripts/scylla-banner-info.rhai")),
        ("tarantool-banner-info", include_str!("../scripts/tarantool-banner-info.rhai")),
        ("aerospike-banner-info", include_str!("../scripts/aerospike-banner-info.rhai")),
        ("vertica-banner-info", include_str!("../scripts/vertica-banner-info.rhai")),
        ("greenplum-banner-info", include_str!("../scripts/greenplum-banner-info.rhai")),
        ("timescaledb-banner", include_str!("../scripts/timescaledb-banner.rhai")),
        ("questdb-banner-info", include_str!("../scripts/questdb-banner-info.rhai")),
        ("victoriametrics-banner", include_str!("../scripts/victoriametrics-banner.rhai")),
        ("http-typo3-detect", include_str!("../scripts/http-typo3-detect.rhai")),
        ("http-craftcms-detect", include_str!("../scripts/http-craftcms-detect.rhai")),
        ("http-strapi-detect", include_str!("../scripts/http-strapi-detect.rhai")),
        ("http-directus-detect", include_str!("../scripts/http-directus-detect.rhai")),
        ("http-ghost-admin", include_str!("../scripts/http-ghost-admin.rhai")),
        ("http-matomo-detect", include_str!("../scripts/http-matomo-detect.rhai")),
        ("http-plausible-detect", include_str!("../scripts/http-plausible-detect.rhai")),
        ("http-umami-detect", include_str!("../scripts/http-umami-detect.rhai")),
        ("http-posthog-detect", include_str!("../scripts/http-posthog-detect.rhai")),
        ("http-openproject-detect", include_str!("../scripts/http-openproject-detect.rhai")),
        ("http-taiga-detect", include_str!("../scripts/http-taiga-detect.rhai")),
        ("http-redmine-detect", include_str!("../scripts/http-redmine-detect.rhai")),
        ("http-kanboard-detect", include_str!("../scripts/http-kanboard-detect.rhai")),
        ("http-planka-detect", include_str!("../scripts/http-planka-detect.rhai")),
        ("http-kimai-detect", include_str!("../scripts/http-kimai-detect.rhai")),
        ("http-invoiceninja-detect", include_str!("../scripts/http-invoiceninja-detect.rhai")),
        ("http-akaunting-detect", include_str!("../scripts/http-akaunting-detect.rhai")),
        ("http-monica-detect", include_str!("../scripts/http-monica-detect.rhai")),
        ("http-snipeit-detect", include_str!("../scripts/http-snipeit-detect.rhai")),
        ("http-listmonk-detect", include_str!("../scripts/http-listmonk-detect.rhai")),
        ("http-mautic-detect", include_str!("../scripts/http-mautic-detect.rhai")),
        ("http-wallabag-detect", include_str!("../scripts/http-wallabag-detect.rhai")),
        ("http-freshrss-detect", include_str!("../scripts/http-freshrss-detect.rhai")),
        ("http-miniflux-detect", include_str!("../scripts/http-miniflux-detect.rhai")),
        ("http-searxng-detect", include_str!("../scripts/http-searxng-detect.rhai")),
        ("http-invidious-detect", include_str!("../scripts/http-invidious-detect.rhai")),
        ("http-filebrowser-detect", include_str!("../scripts/http-filebrowser-detect.rhai")),
        ("http-filestash-detect", include_str!("../scripts/http-filestash-detect.rhai")),
        ("http-pydio-detect", include_str!("../scripts/http-pydio-detect.rhai")),
        ("http-photoprism-detect", include_str!("../scripts/http-photoprism-detect.rhai")),
        ("http-immich-detect", include_str!("../scripts/http-immich-detect.rhai")),
        ("http-stirlingpdf-detect", include_str!("../scripts/http-stirlingpdf-detect.rhai")),
        ("http-cryptpad-detect", include_str!("../scripts/http-cryptpad-detect.rhai")),
        ("http-etherpad-detect", include_str!("../scripts/http-etherpad-detect.rhai")),
        ("http-hedgedoc-detect", include_str!("../scripts/http-hedgedoc-detect.rhai")),
        ("http-trilium-detect", include_str!("../scripts/http-trilium-detect.rhai")),
        ("http-memos-detect", include_str!("../scripts/http-memos-detect.rhai")),
        ("http-excalidraw-detect", include_str!("../scripts/http-excalidraw-detect.rhai")),
        ("http-drawio-detect", include_str!("../scripts/http-drawio-detect.rhai")),
        ("http-penpot-detect", include_str!("../scripts/http-penpot-detect.rhai")),
        ("http-plane-detect", include_str!("../scripts/http-plane-detect.rhai")),
        ("http-appsmith-detect", include_str!("../scripts/http-appsmith-detect.rhai")),
        ("http-budibase-detect", include_str!("../scripts/http-budibase-detect.rhai")),
        ("http-tooljet-detect", include_str!("../scripts/http-tooljet-detect.rhai")),
        ("http-nocodb-detect", include_str!("../scripts/http-nocodb-detect.rhai")),
        ("http-baserow-detect", include_str!("../scripts/http-baserow-detect.rhai")),
        ("http-grist-detect", include_str!("../scripts/http-grist-detect.rhai")),
        ("http-formbricks-detect", include_str!("../scripts/http-formbricks-detect.rhai")),
        ("http-uptrace-detect", include_str!("../scripts/http-uptrace-detect.rhai")),
        ("http-signoz-detect", include_str!("../scripts/http-signoz-detect.rhai")),
        ("http-sentry-detect", include_str!("../scripts/http-sentry-detect.rhai")),
        ("http-glitchtip-detect", include_str!("../scripts/http-glitchtip-detect.rhai")),
        ("http-coolify-detect", include_str!("../scripts/http-coolify-detect.rhai")),
        ("http-dokploy-detect", include_str!("../scripts/http-dokploy-detect.rhai")),
        ("http-caprover-detect", include_str!("../scripts/http-caprover-detect.rhai")),
        ("http-yacht-detect", include_str!("../scripts/http-yacht-detect.rhai")),
        ("http-dockge-detect", include_str!("../scripts/http-dockge-detect.rhai")),
        ("http-whatsupdocker-detect", include_str!("../scripts/http-whatsupdocker-detect.rhai")),
        ("http-watchtower-detect", include_str!("../scripts/http-watchtower-detect.rhai")),
        ("http-semaphore-detect", include_str!("../scripts/http-semaphore-detect.rhai")),
        ("http-rundeck-login", include_str!("../scripts/http-rundeck-login.rhai")),
        ("http-awx-detect", include_str!("../scripts/http-awx-detect.rhai")),
        ("http-foreman-detect", include_str!("../scripts/http-foreman-detect.rhai")),
        ("http-cobbler-detect", include_str!("../scripts/http-cobbler-detect.rhai")),
        ("http-netbox-detect", include_str!("../scripts/http-netbox-detect.rhai")),
        ("http-nautobot-detect", include_str!("../scripts/http-nautobot-detect.rhai")),
        ("http-phpipam-detect", include_str!("../scripts/http-phpipam-detect.rhai")),
        ("http-librecmc-detect", include_str!("../scripts/http-librecmc-detect.rhai")),
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
