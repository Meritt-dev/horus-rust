//! Connector-secret encryption at rest (HOR-452).
//!
//! Connector credentials are AES-256-GCM encrypted into `.horus/secrets.local.json`
//! (gitignored, 0600), and a single 32-byte **master key** — held by the OS, NOT the
//! repo — decrypts them. Master-key transport, in precedence order:
//!   1. `HORUS_SECRET_KEY` env var — base64 of 32 bytes is used raw; anything else is a
//!      passphrase, KDF'd with scrypt and a fixed salt (deterministic across machines).
//!   2. OS keychain — macOS `security`, Linux `secret-tool`, Windows DPAPI (PowerShell).
//!   3. 0600 key file at `~/.horus/keyring/master.key` — fallback, surfaced with a warning.
//!
//! The envelope is byte-compatible with the TypeScript implementation.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

/// An AES-256-GCM encrypted secret value (all binary fields base64-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Envelope version (always 1).
    pub v: u8,
    /// Always `aes-256-gcm`.
    pub alg: String,
    /// Master-key fingerprint (first 16 hex of sha256(key)) — detects wrong-key decrypts.
    pub kid: String,
    /// 12-byte GCM nonce.
    pub iv: String,
    /// Ciphertext.
    pub ct: String,
    /// 16-byte GCM auth tag.
    pub tag: String,
}

impl EncryptedSecret {
    /// Type guard: parse `v` only when it is a well-formed envelope.
    pub fn from_value(v: &Value) -> Option<EncryptedSecret> {
        let o = v.as_object()?;
        if o.get("v")?.as_u64()? != 1 || o.get("alg")?.as_str()? != "aes-256-gcm" {
            return None;
        }
        Some(EncryptedSecret {
            v: 1,
            alg: "aes-256-gcm".to_string(),
            kid: o.get("kid")?.as_str()?.to_string(),
            iv: o.get("iv")?.as_str()?.to_string(),
            ct: o.get("ct")?.as_str()?.to_string(),
            tag: o.get("tag")?.as_str()?.to_string(),
        })
    }
}

/// Type guard: is `v` a well-formed EncryptedSecret envelope?
pub fn is_encrypted_secret(v: &Value) -> bool {
    EncryptedSecret::from_value(v).is_some()
}

/// Where the active master key came from (for `secrets status` / doctor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasterKeySource {
    Env,
    Keychain,
    File,
    GeneratedKeychain,
    GeneratedFile,
}

pub type MasterKey = [u8; KEY_BYTES];

#[derive(Debug, Clone)]
pub struct MasterKeyResult {
    pub key: MasterKey,
    pub source: MasterKeySource,
    /// Non-fatal note to surface to the user (e.g. weaker file-fallback storage).
    pub warning: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// A master key is required but none can be found/persisted.
    #[error("{0}")]
    MasterKeyUnavailable(String),
    #[error("Encrypted secret was sealed with a different master key (key fingerprint mismatch). Re-run `horus connect` to re-encrypt, or restore the original key.")]
    KeyMismatch,
    /// Node's message for a GCM auth failure, kept so callers see the same text.
    #[error("Unsupported state or unable to authenticate data")]
    Authentication,
    #[error("Encrypted secret field `{0}` is not valid base64")]
    Encoding(&'static str),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ENV_VAR: &str = "HORUS_SECRET_KEY";
const KEY_SERVICE: &str = "horus";
const KEY_ACCOUNT: &str = "master-key";
const KEY_LABEL: &str = "Horus connector-secret master key";
/// Fixed salt so an env passphrase derives the same key on every machine.
const KDF_SALT: &[u8] = b"horus.secret.kdf.v1";
const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 12;
/// Hard ceiling for any keychain CLI call: a locked keychain can block on a GUI prompt
/// that cannot render in a headless shell. On timeout we degrade to the next source.
const CMD_TIMEOUT: Duration = Duration::from_millis(4000);

static CACHE: Mutex<Option<(MasterKey, MasterKeySource)>> = Mutex::new(None);

/// Reset the in-process key cache (handy after a rekey).
pub fn reset_master_key_cache() {
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Lenient-padding decoder: Node's `Buffer.from(s, 'base64')` accepts unpadded input.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

// ---------------------------------------------------------------------------
// Key derivation / fingerprint
// ---------------------------------------------------------------------------

fn fingerprint(key: &[u8]) -> String {
    hex::encode(Sha256::digest(key))[..16].to_string()
}

/// Turn the `HORUS_SECRET_KEY` value into a 32-byte key. A base64 string that decodes
/// to exactly 32 bytes is used verbatim; anything else is a passphrase, scrypt-stretched
/// with Node's `scryptSync` defaults (N=16384, r=8, p=1).
fn key_from_env_value(value: &str) -> MasterKey {
    let trimmed = value.trim();
    if let Ok(decoded) = STANDARD.decode(trimmed) {
        if decoded.len() == KEY_BYTES && STANDARD.encode(&decoded) == trimmed {
            return decoded.try_into().expect("32 bytes");
        }
    }
    let mut out = [0u8; KEY_BYTES];
    let params = scrypt::Params::new(14, 8, 1, KEY_BYTES).expect("valid scrypt params");
    scrypt::scrypt(trimmed.as_bytes(), KDF_SALT, &params, &mut out).expect("scrypt output length");
    out
}

// ---------------------------------------------------------------------------
// OS keychain transport (best-effort; any failure → None/false so we degrade)
// ---------------------------------------------------------------------------

fn keyring_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".horus").join("keyring")
}
/// Path of the 0600 key-file fallback (`~/.horus/keyring/master.key`).
pub fn master_key_file_path() -> PathBuf {
    keyring_dir().join("master.key")
}
fn dpapi_blob_path() -> PathBuf {
    keyring_dir().join("master.key.dpapi")
}

/// Run a CLI with a hard timeout. Returns stdout when it exits 0 within the limit.
fn run_cli(bin: &str, args: &[&str], stdin: Option<&[u8]>, env: &[(&str, String)]) -> Option<Vec<u8>> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    if let Some(input) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(input);
        }
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < CMD_TIMEOUT => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

fn cli_text(out: Option<Vec<u8>>) -> Option<String> {
    let v = String::from_utf8_lossy(&out?).trim().to_string();
    (!v.is_empty()).then_some(v)
}

fn mac_keychain_get() -> Option<String> {
    cli_text(run_cli("security", &["find-generic-password", "-s", KEY_SERVICE, "-a", KEY_ACCOUNT, "-w"], None, &[]))
}
fn mac_keychain_set(b64: &str) -> bool {
    // -U: update if it already exists
    run_cli(
        "security",
        &["add-generic-password", "-U", "-s", KEY_SERVICE, "-a", KEY_ACCOUNT, "-l", KEY_LABEL, "-w", b64],
        None,
        &[],
    )
    .is_some()
}

fn linux_keychain_get() -> Option<String> {
    cli_text(run_cli("secret-tool", &["lookup", "service", KEY_SERVICE, "account", KEY_ACCOUNT], None, &[]))
}
fn linux_keychain_set(b64: &str) -> bool {
    run_cli(
        "secret-tool",
        &["store", "--label", KEY_LABEL, "service", KEY_SERVICE, "account", KEY_ACCOUNT],
        Some(b64.as_bytes()),
        &[],
    )
    .is_some()
}

fn powershell_bin() -> Option<&'static str> {
    ["powershell", "pwsh"]
        .into_iter()
        .find(|bin| run_cli(bin, &["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], None, &[]).is_some())
}
/// Windows: DPAPI (user-scoped) protect the key to a blob file. Key passed via env, never argv.
fn win_keychain_get() -> Option<String> {
    let ps = powershell_bin()?;
    let blob = dpapi_blob_path();
    if !blob.exists() {
        return None;
    }
    let script = r#"
$enc = Get-Content -Path $env:HORUS_DPAPI_BLOB -Raw
$sec = ConvertTo-SecureString $enc
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }"#;
    cli_text(run_cli(
        ps,
        &["-NoProfile", "-NonInteractive", "-Command", script],
        None,
        &[("HORUS_DPAPI_BLOB", blob.to_string_lossy().into_owned())],
    ))
}
fn win_keychain_set(b64: &str) -> bool {
    let Some(ps) = powershell_bin() else { return false };
    let _ = std::fs::create_dir_all(keyring_dir());
    let blob = dpapi_blob_path();
    let script = r#"
$sec = ConvertTo-SecureString $env:HORUS_DPAPI_KEY -AsPlainText -Force
$enc = ConvertFrom-SecureString $sec
Set-Content -Path $env:HORUS_DPAPI_BLOB -Value $enc -NoNewline"#;
    run_cli(
        ps,
        &["-NoProfile", "-NonInteractive", "-Command", script],
        None,
        &[("HORUS_DPAPI_KEY", b64.to_string()), ("HORUS_DPAPI_BLOB", blob.to_string_lossy().into_owned())],
    )
    .is_some()
}

fn os_keychain_get() -> Option<String> {
    match std::env::consts::OS {
        "macos" => mac_keychain_get(),
        "linux" => linux_keychain_get(),
        "windows" => win_keychain_get(),
        _ => None,
    }
}
fn os_keychain_set(b64: &str) -> bool {
    match std::env::consts::OS {
        "macos" => mac_keychain_set(b64),
        "linux" => linux_keychain_set(b64),
        "windows" => win_keychain_set(b64),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 0600 key-file fallback
// ---------------------------------------------------------------------------

fn key_file_get() -> Option<String> {
    let v = std::fs::read_to_string(master_key_file_path()).ok()?.trim().to_string();
    (!v.is_empty()).then_some(v)
}
fn key_file_set(b64: &str) -> bool {
    std::fs::create_dir_all(keyring_dir()).is_ok() && write_file_0600(&master_key_file_path(), format!("{b64}\n").as_bytes()).is_ok()
}

/// Write `contents` to `path` with mode 0600 (chmod after write so pre-existing files are
/// tightened too — the create mode is ignored when the file already exists).
pub fn write_file_0600(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key resolution
// ---------------------------------------------------------------------------

fn cache(key: MasterKey, source: MasterKeySource) -> (MasterKey, MasterKeySource) {
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, source));
    (key, source)
}

fn key_from_b64(s: &str) -> Option<MasterKey> {
    LENIENT.decode(s).ok()?.try_into().ok()
}

/// Resolve an EXISTING key (env → keychain → file). Does not generate.
fn resolve_existing_key() -> Option<(MasterKey, MasterKeySource)> {
    if let Some(cached) = *CACHE.lock().unwrap_or_else(|e| e.into_inner()) {
        return Some(cached);
    }
    if let Some(env_val) = std::env::var(ENV_VAR).ok().filter(|v| !v.trim().is_empty()) {
        return Some(cache(key_from_env_value(&env_val), MasterKeySource::Env));
    }
    if let Some(key) = os_keychain_get().and_then(|s| key_from_b64(&s)) {
        return Some(cache(key, MasterKeySource::Keychain));
    }
    if let Some(key) = key_file_get().and_then(|s| key_from_b64(&s)) {
        return Some(cache(key, MasterKeySource::File));
    }
    None
}

/// Master key for DECRYPTION. None when unavailable so callers can degrade.
pub fn get_master_key_for_read() -> Option<MasterKey> {
    resolve_existing_key().map(|(k, _)| k)
}

/// Get-or-create the master key for ENCRYPTION: resolves an existing key, or generates a
/// random one and persists it to the keychain (file fallback).
pub fn ensure_master_key() -> Result<MasterKeyResult, SecretError> {
    if let Some((key, source)) = resolve_existing_key() {
        return Ok(MasterKeyResult { key, source, warning: None });
    }
    let mut key = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    let b64 = STANDARD.encode(key);

    if os_keychain_set(&b64) {
        cache(key, MasterKeySource::GeneratedKeychain);
        return Ok(MasterKeyResult { key, source: MasterKeySource::GeneratedKeychain, warning: None });
    }
    let path = master_key_file_path().display().to_string();
    if key_file_set(&b64) {
        cache(key, MasterKeySource::GeneratedFile);
        return Ok(MasterKeyResult {
            key,
            source: MasterKeySource::GeneratedFile,
            warning: Some(format!(
                "No OS keychain available — stored the master key at {path} (mode 0600).\n\
                 It is in your home directory (never the repo), but is protected only by file permissions.\n\
                 For stronger isolation set {ENV_VAR} to a passphrase, or run on a host with a keyring."
            )),
        });
    }
    Err(SecretError::MasterKeyUnavailable(format!(
        "Could not persist a master key (no keychain and {path} is not writable). Set {ENV_VAR} to a passphrase and retry."
    )))
}

#[derive(Debug, Clone, Serialize)]
pub struct MasterKeyStatus {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<MasterKeySource>,
    pub detail: String,
}

/// Human-readable status of the master key for `secrets status` / doctor (never reveals it).
pub fn master_key_status() -> MasterKeyStatus {
    let Some((_, source)) = resolve_existing_key() else {
        return MasterKeyStatus {
            available: false,
            source: None,
            detail: format!("no master key yet — one is created on first `horus connect` (keychain, or {ENV_VAR})."),
        };
    };
    let detail = match source {
        MasterKeySource::Env => format!("{ENV_VAR} environment variable"),
        MasterKeySource::Keychain | MasterKeySource::GeneratedKeychain => os_keychain_label().to_string(),
        MasterKeySource::File | MasterKeySource::GeneratedFile => {
            format!("key file {} (0600 fallback)", master_key_file_path().display())
        }
    };
    MasterKeyStatus { available: true, source: Some(source), detail }
}

fn os_keychain_label() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS Keychain",
        "linux" => "libsecret keyring (secret-tool)",
        "windows" => "Windows DPAPI (user-scoped)",
        _ => "OS keychain",
    }
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt a plaintext secret. Uses the ensured master key by default.
pub fn encrypt_secret(plaintext: &str, key: Option<&MasterKey>) -> Result<EncryptedSecret, SecretError> {
    let k = match key {
        Some(k) => *k,
        None => ensure_master_key()?.key,
    };
    let mut iv = [0u8; IV_BYTES];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new((&k).into());
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext.as_bytes(), aad: &[] })
        .map_err(|_| SecretError::Authentication)?;
    let tag = sealed.split_off(sealed.len() - 16);
    Ok(EncryptedSecret {
        v: 1,
        alg: "aes-256-gcm".to_string(),
        kid: fingerprint(&k),
        iv: STANDARD.encode(iv),
        ct: STANDARD.encode(&sealed),
        tag: STANDARD.encode(&tag),
    })
}

/// Decrypt an EncryptedSecret. `MasterKeyUnavailable` when no key is present;
/// `KeyMismatch`/`Authentication` on a wrong key or tampering.
pub fn decrypt_secret(blob: &EncryptedSecret, key: Option<&MasterKey>) -> Result<String, SecretError> {
    let k = match key {
        Some(k) => *k,
        None => get_master_key_for_read().ok_or_else(|| {
            SecretError::MasterKeyUnavailable(format!(
                "Cannot decrypt: master key not found (set {ENV_VAR} or restore the OS keychain entry)."
            ))
        })?,
    };
    if blob.kid != fingerprint(&k) {
        return Err(SecretError::KeyMismatch);
    }
    let iv = LENIENT.decode(&blob.iv).map_err(|_| SecretError::Encoding("iv"))?;
    let mut ct = LENIENT.decode(&blob.ct).map_err(|_| SecretError::Encoding("ct"))?;
    let tag = LENIENT.decode(&blob.tag).map_err(|_| SecretError::Encoding("tag"))?;
    if iv.len() != IV_BYTES || tag.len() != 16 {
        return Err(SecretError::Authentication);
    }
    ct.extend_from_slice(&tag);
    let plain = Aes256Gcm::new((&k).into())
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: &[] })
        .map_err(|_| SecretError::Authentication)?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}
