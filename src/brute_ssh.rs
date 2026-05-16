//! SSH bruteforce adapter via the `russh` Pure-Rust SSH client.
//!
//! Each attempt:
//!   1. Connect.
//!   2. Negotiate KEX + cipher (russh handles the algorithm dance).
//!   3. Call `authenticate_password(user, pass)`.
//!   4. Disconnect.
//!
//! No key-based fallback, no agent — passwords only by design.
//! `Disable host-key checking via a permissive Handler` because the
//! goal here is "do these credentials work", not "is the server's
//! identity trusted".
//!
//! Heavy by dep-graph standards (russh pulls ring + ssh-key +
//! ssh-encoding) but cleanly Pure Rust — no libssh2 / OpenSSH
//! subprocess. Compile time on a fresh build adds ~30 seconds.

use crate::brute::{BruteAdapter, BruteConfig};
use anyhow::Result;
use async_trait::async_trait;
use russh::client::{self, Handle};
use russh_keys::key::PublicKey;
use std::sync::Arc;
use tokio::time::timeout;

pub struct SshAdapter;

#[async_trait]
impl BruteAdapter for SshAdapter {
    fn protocol(&self) -> &'static str { "ssh" }
    async fn try_one(&self, cfg: &BruteConfig, user: &str, pass: &str) -> Result<bool> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(cfg.timeout),
            ..Default::default()
        });
        let handler = AcceptAllHandler;
        let connect_fut = client::connect(config, cfg.target, handler);
        let mut handle: Handle<AcceptAllHandler> = match timeout(cfg.timeout, connect_fut).await {
            Ok(Ok(h)) => h,
            _ => return Ok(false),
        };
        // Authenticate — russh 0.45 returns bool directly
        let auth = handle.authenticate_password(user, pass);
        let result = match timeout(cfg.timeout, auth).await {
            Ok(Ok(success)) => success,
            _ => false,
        };
        // Best-effort clean disconnect; ignore any error.
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "bye", "en")
            .await;
        Ok(result)
    }
}

/// Permissive handler — the bruteforce flow doesn't care about
/// the server's host-key identity, only whether credentials work.
struct AcceptAllHandler;

#[async_trait]
impl client::Handler for AcceptAllHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_advertises_ssh() {
        assert_eq!(SshAdapter.protocol(), "ssh");
    }

    // Live-network tests for SSH would need a local sshd fixture;
    // skipped here. The framework-level coverage in `brute::tests`
    // already exercises the run/stop-on-success/safety-gate logic
    // via the StubAdapter, which is sufficient.
}
