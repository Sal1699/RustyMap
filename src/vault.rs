use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub username: String,
    pub secret: String,
    pub kind: String, // ssh, http, smb, etc.
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultPlain {
    pub entries: BTreeMap<String, VaultEntry>, // key: "name" e.g. "proxmox-root"
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(password: &str, salt_str: &str) -> Result<[u8; 32]> {
    let salt = SaltString::from_b64(salt_str).map_err(|e| anyhow!("salt parse: {}", e))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2: {}", e))?;
    let raw = hash.hash.ok_or_else(|| anyhow!("no hash output"))?;
    let bytes = raw.as_bytes();
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    Ok(out)
}

pub fn load(path: &Path, password: &str) -> Result<VaultPlain> {
    if !path.exists() {
        return Ok(VaultPlain::default());
    }
    let raw = fs::read_to_string(path).context("read vault")?;
    let file: VaultFile = serde_json::from_str(&raw).context("parse vault file")?;
    let key_bytes = derive_key(password, &file.salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = B64.decode(&file.nonce).context("b64 nonce")?;
    let ct = B64.decode(&file.ciphertext).context("b64 ct")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| anyhow!("decryption failed (wrong password?)"))?;
    let v: VaultPlain = serde_json::from_slice(&plain).context("parse plaintext")?;
    Ok(v)
}

pub fn save(path: &Path, password: &str, vault: &VaultPlain) -> Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let salt_str = salt.as_str().to_string();
    let key_bytes = derive_key(password, &salt_str)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = serde_json::to_vec(vault)?;
    let ct = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|e| anyhow!("encrypt: {}", e))?;
    let file = VaultFile {
        salt: salt_str,
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ct),
    };
    fs::write(path, serde_json::to_string_pretty(&file)?)?;
    Ok(())
}

pub fn add(path: &Path, password: &str, name: &str, entry: VaultEntry) -> Result<()> {
    let mut v = load(path, password)?;
    v.entries.insert(name.to_string(), entry);
    save(path, password, &v)
}

pub fn list(path: &Path, password: &str) -> Result<Vec<(String, VaultEntry)>> {
    let v = load(path, password)?;
    Ok(v.entries.into_iter().collect())
}

pub fn remove(path: &Path, password: &str, name: &str) -> Result<bool> {
    let mut v = load(path, password)?;
    let was = v.entries.remove(name).is_some();
    save(path, password, &v)?;
    Ok(was)
}
