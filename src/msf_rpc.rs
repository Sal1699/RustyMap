//! Metasploit RPC client (msfrpcd).
//!
//! Speaks the **MessagePack-RPC** protocol modern `msfrpcd` exposes
//! on its HTTPS endpoint (default `/api/1.0` on port 55553). Every
//! call is a HTTP POST with a msgpack-encoded array body:
//!
//!   `[method_name, token_or_arg1, arg2, …]`
//!
//! Responses are msgpack maps. On error the map contains
//! `"error" => true` + `"error_message" => "..."`.
//!
//! Auth flow:
//!   1. `auth.login(user, pass)` → temporary token, then
//!   2. `auth.token_generate()` → permanent token to reuse.
//!
//! We expose a `Client` that owns the token + reqwest handle plus
//! a generic `call(method, args)` returning the raw msgpack value.
//! Higher layers (`msf_import`, `msf_suggest`, `msf_fire`) map that
//! to typed structs.

use anyhow::{anyhow, Context, Result};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Generic msgpack value — we re-export a typed alias for clarity.
pub type Value = rmpv::Value;

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    endpoint: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectArgs {
    pub url: String,        // https://host:55553/api/1.0
    pub username: Option<String>,
    pub password: Option<String>,
    /// Pre-issued permanent token. When set we skip the login dance.
    pub token: Option<String>,
    pub timeout_secs: u64,
    pub accept_invalid_certs: bool,
}

impl Client {
    pub async fn connect(args: ConnectArgs) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout_secs))
            .danger_accept_invalid_certs(args.accept_invalid_certs)
            .user_agent("rustymap/msfrpc")
            .build()?;
        let mut c = Client {
            http,
            endpoint: args.url,
            token: args.token,
        };
        if c.token.is_none() {
            let user = args
                .username
                .clone()
                .ok_or_else(|| anyhow!("missing --msf-user (no token supplied)"))?;
            let pass = args
                .password
                .clone()
                .ok_or_else(|| anyhow!("missing --msf-pass (no token supplied)"))?;
            let resp = c.call_raw("auth.login", &[Value::from(user), Value::from(pass)]).await?;
            let map = expect_map(&resp)?;
            let result = lookup_str(map, "result");
            if result.as_deref() != Some("success") {
                return Err(anyhow!(
                    "MSF auth.login failed: {:?}",
                    lookup_str(map, "error_message")
                ));
            }
            let tok = lookup_str(map, "token")
                .ok_or_else(|| anyhow!("auth.login: missing token in response"))?;
            c.token = Some(tok);
        }
        Ok(c)
    }

    /// Issue a method call. The token is automatically prepended as
    /// the first argument when one is set (every authenticated method
    /// expects that shape).
    pub async fn call(&self, method: &str, args: &[Value]) -> Result<Value> {
        let mut full: Vec<Value> = Vec::with_capacity(args.len() + 1);
        if let Some(tok) = &self.token {
            full.push(Value::from(tok.clone()));
        }
        for v in args {
            full.push(v.clone());
        }
        self.call_raw(method, &full).await
    }

    /// Like `call` but does not auto-prepend the token. Used for the
    /// `auth.login` step itself.
    pub async fn call_raw(&self, method: &str, args: &[Value]) -> Result<Value> {
        let mut payload: Vec<Value> = Vec::with_capacity(args.len() + 1);
        payload.push(Value::from(method.to_string()));
        for v in args {
            payload.push(v.clone());
        }
        let array = Value::Array(payload);
        let body = encode::to_vec_named(&array).context("msgpack encode")?;
        let resp = self
            .http
            .post(&self.endpoint)
            .header("Content-Type", "binary/message-pack")
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.endpoint))?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "msfrpcd returned HTTP {} ({} bytes)",
                status,
                bytes.len()
            ));
        }
        let value: Value = decode::from_slice(&bytes).context("msgpack decode")?;
        if let Some(map) = value.as_map() {
            if has_error_flag(map) {
                let msg = lookup_str(map, "error_message").unwrap_or_else(|| "unknown error".into());
                return Err(anyhow!("msfrpc error: {}", msg));
            }
        }
        Ok(value)
    }

    /// Quick liveness check.
    pub async fn version(&self) -> Result<String> {
        let v = self.call("core.version", &[]).await?;
        let map = expect_map(&v)?;
        Ok(lookup_str(map, "version").unwrap_or_else(|| "?".into()))
    }
}

// ── small helpers for msgpack map access ─────────────────────────

fn expect_map(v: &Value) -> Result<&Vec<(Value, Value)>> {
    v.as_map().ok_or_else(|| anyhow!("expected msgpack map, got {:?}", v))
}

fn lookup<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::String(s) if s.as_str() == Some(key) => Some(v),
        Value::Binary(b) if std::str::from_utf8(b).ok() == Some(key) => Some(v),
        _ => None,
    })
}

fn lookup_str(map: &[(Value, Value)], key: &str) -> Option<String> {
    lookup(map, key).and_then(|v| value_as_str(v))
}

fn has_error_flag(map: &[(Value, Value)]) -> bool {
    lookup(map, "error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Pull a string value out of a msgpack `Value`, tolerating both
/// `Value::String` and `Value::Binary` (msfrpc switches between them
/// depending on what method you called and which Ruby version is
/// running on the server side).
pub fn value_as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => s.as_str().map(String::from),
        Value::Binary(b) => std::str::from_utf8(b).ok().map(String::from),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_as_str_handles_string_variant() {
        let v = Value::from("hello");
        assert_eq!(value_as_str(&v).as_deref(), Some("hello"));
    }

    #[test]
    fn value_as_str_handles_binary_variant() {
        let v = Value::Binary(b"world".to_vec());
        assert_eq!(value_as_str(&v).as_deref(), Some("world"));
    }

    #[test]
    fn value_as_str_returns_none_for_other_types() {
        assert!(value_as_str(&Value::from(42)).is_none());
        assert!(value_as_str(&Value::Boolean(true)).is_none());
    }

    #[test]
    fn lookup_finds_keys_in_either_string_form() {
        let map = vec![
            (Value::from("name"), Value::from("rustymap")),
            (Value::Binary(b"version".to_vec()), Value::from("0.62.0")),
        ];
        assert_eq!(lookup_str(&map, "name").as_deref(), Some("rustymap"));
        assert_eq!(lookup_str(&map, "version").as_deref(), Some("0.62.0"));
        assert!(lookup_str(&map, "absent").is_none());
    }

    #[test]
    fn has_error_flag_recognises_true_value() {
        let map = vec![
            (Value::from("error"), Value::Boolean(true)),
            (Value::from("error_message"), Value::from("nope")),
        ];
        assert!(has_error_flag(&map));
    }

    #[test]
    fn has_error_flag_default_false() {
        let map = vec![(Value::from("result"), Value::from("success"))];
        assert!(!has_error_flag(&map));
    }
}
