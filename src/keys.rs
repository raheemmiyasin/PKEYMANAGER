//! Discovering and describing SSH keys in ~/.ssh.
//!
//! Safety rule for this module: private key files are opened only to read their
//! *header* (cipher name / PEM headers) so we can tell whether a passphrase is set.
//! Their bytes are never returned, stored, printed, copied or moved.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest, Sha256};

/// Whether the private key half is protected by a passphrase.
///
/// Rust enums are "tagged unions": unlike a Java enum, each variant can carry its
/// own data (`Encrypted` carries the cipher name). Closer to a sealed interface
/// with record implementations in Java 17+.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    Encrypted(String),
    Unencrypted,
    Unknown,
    NoPrivateKey,
}

impl Protection {
    pub fn label(&self) -> String {
        match self {
            Protection::Encrypted(c) => format!("passphrase ({c})"),
            Protection::Unencrypted => "NO passphrase".into(),
            Protection::Unknown => "unknown format".into(),
            Protection::NoPrivateKey => "no private key".into(),
        }
    }
}

/// One place where a key is referenced (authorized_keys line, ssh config Host block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub name: String,
    pub pub_path: PathBuf,
    pub priv_path: Option<PathBuf>,
    /// Unix permission bits of the private key, e.g. 0o600.
    pub priv_mode: Option<u32>,
    pub key_type: String,
    pub blob_b64: String,
    pub comment: String,
    pub fingerprint: String,
    pub protection: Protection,
    pub in_agent: bool,
    pub usages: Vec<Usage>,
}

impl KeyInfo {
    /// The full public key line, exactly as it should be pasted into GitHub etc.
    pub fn public_line(&self) -> String {
        if self.comment.is_empty() {
            format!("{} {}", self.key_type, self.blob_b64)
        } else {
            format!("{} {} {}", self.key_type, self.blob_b64, self.comment)
        }
    }

    /// Short type name for the table: "ssh-ed25519" -> "ED25519".
    pub fn short_type(&self) -> String {
        let t = self.key_type.as_str();
        let s = match t {
            "ssh-ed25519" => "ED25519",
            "ssh-rsa" => "RSA",
            "ssh-dss" => "DSA",
            "sk-ssh-ed25519@openssh.com" => "ED25519-SK",
            "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA-SK",
            _ if t.starts_with("ecdsa-sha2-") => "ECDSA",
            _ => t,
        };
        s.to_string()
    }

    /// Private key readable by group/others? ssh refuses to use such keys.
    pub fn perms_too_open(&self) -> bool {
        matches!(self.priv_mode, Some(m) if m & 0o077 != 0)
    }
}

/// Parsed `<type> <base64> [comment]` line.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub key_type: String,
    pub blob_b64: String,
    pub comment: String,
}

/// Parse an OpenSSH public key line. Returns `None` for anything malformed.
///
/// `&str` is a *borrowed* view into someone else's string (like a read-only
/// reference in Java that the compiler guarantees outlives its use). We return
/// owned `String`s so the result doesn't depend on the input staying alive.
pub fn parse_public_key(line: &str) -> Option<PublicKey> {
    let mut parts = line.split_whitespace();
    let key_type = parts.next()?;
    let blob = parts.next()?;
    // Must be valid base64 and the blob must start with the same type string.
    let raw = STANDARD.decode(blob).ok()?;
    if read_ssh_string(&raw, 0)?.0 != key_type.as_bytes() {
        return None;
    }
    let comment = parts.collect::<Vec<_>>().join(" ");
    Some(PublicKey {
        key_type: key_type.to_string(),
        blob_b64: blob.to_string(),
        comment,
    })
}

/// SHA256 fingerprint in the same format as `ssh-keygen -lf` (SHA256:base64-no-padding).
pub fn fingerprint(blob_b64: &str) -> Option<String> {
    let raw = STANDARD.decode(blob_b64).ok()?;
    let digest = Sha256::digest(&raw);
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
}

/// Read an SSH wire-format string (u32 big-endian length + bytes) at `pos`.
/// Returns the bytes and the position just after them.
///
/// The lifetime `'a` says "the returned slice borrows from `buf`": the compiler
/// will reject any caller that tries to use the slice after `buf` is gone.
#[allow(clippy::needless_lifetimes)] // written out on purpose, for learning
fn read_ssh_string<'a>(buf: &'a [u8], pos: usize) -> Option<(&'a [u8], usize)> {
    let len_bytes: [u8; 4] = buf.get(pos..pos + 4)?.try_into().ok()?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let start = pos + 4;
    let data = buf.get(start..start.checked_add(len)?)?;
    Some((data, start + len))
}

/// Inspect a private key's *header only* to see if it is passphrase protected.
pub fn detect_protection(contents: &str) -> Protection {
    const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

    if let Some(start) = contents.find(OPENSSH_BEGIN) {
        let after = &contents[start + OPENSSH_BEGIN.len()..];
        let body_end = after.find(OPENSSH_END).unwrap_or(after.len());
        let b64: String = after[..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let Ok(raw) = STANDARD.decode(b64) else {
            return Protection::Unknown;
        };
        const MAGIC: &[u8] = b"openssh-key-v1\0";
        if !raw.starts_with(MAGIC) {
            return Protection::Unknown;
        }
        return match read_ssh_string(&raw, MAGIC.len()) {
            Some((b"none", _)) => Protection::Unencrypted,
            Some((cipher, _)) => Protection::Encrypted(String::from_utf8_lossy(cipher).into()),
            None => Protection::Unknown,
        };
    }
    // Legacy PEM formats (old RSA/ECDSA keys, PKCS#8).
    if contents.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return Protection::Encrypted("pkcs8".into());
    }
    if contents.contains("PRIVATE KEY-----") {
        if contents.contains("Proc-Type: 4,ENCRYPTED") {
            let cipher = contents
                .lines()
                .find_map(|l| l.strip_prefix("DEK-Info: "))
                .and_then(|v| v.split(',').next())
                .unwrap_or("pem");
            return Protection::Encrypted(cipher.to_string());
        }
        return Protection::Unencrypted;
    }
    Protection::Unknown
}

fn read_private_key_protection(path: &Path) -> Protection {
    // Private keys are a few KB; refuse anything big so we never slurp random files.
    match fs::metadata(path) {
        Ok(m) if m.len() <= 64 * 1024 => {}
        _ => return Protection::Unknown,
    }
    // `contents` is dropped (freed) at the end of this function: ownership means
    // nothing else can hold on to it, so the key material never leaves this scope.
    match fs::read_to_string(path) {
        Ok(contents) => detect_protection(&contents),
        Err(_) => Protection::Unknown,
    }
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// Scan `ssh_dir` for `*.pub` files and build a `KeyInfo` for each.
/// `agent` holds fingerprints currently loaded in ssh-agent.
pub fn scan(ssh_dir: &Path, agent: &HashSet<String>) -> anyhow::Result<Vec<KeyInfo>> {
    let mut keys = Vec::new();
    let entries = match fs::read_dir(ssh_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
        Err(e) => return Err(e.into()),
    };

    let authorized = load_authorized_keys(ssh_dir);
    let config_ids = load_config_identities(ssh_dir);

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") || !path.is_file() {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(pk) = text.lines().find_map(parse_public_key) else {
            continue;
        };
        let Some(fp) = fingerprint(&pk.blob_b64) else {
            continue;
        };

        let priv_candidate = path.with_extension("");
        let priv_path = priv_candidate.is_file().then_some(priv_candidate);
        let protection = priv_path
            .as_deref()
            .map(read_private_key_protection)
            .unwrap_or(Protection::NoPrivateKey);
        let priv_mode = priv_path.as_deref().and_then(file_mode);

        let mut usages: Vec<Usage> = authorized
            .iter()
            .filter(|(_, _, blob)| *blob == pk.blob_b64)
            .map(|(file, line, _)| Usage {
                source: file.clone(),
                detail: format!("line {line}: this key can log in to THIS Mac"),
            })
            .collect();
        if let Some(pp) = &priv_path {
            for (host, id_path) in &config_ids {
                if same_file(id_path, pp) {
                    usages.push(Usage {
                        source: "~/.ssh/config".into(),
                        detail: format!("Host {host}"),
                    });
                }
            }
        }

        keys.push(KeyInfo {
            name: path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            in_agent: agent.contains(&fp),
            pub_path: path,
            priv_path,
            priv_mode,
            key_type: pk.key_type,
            blob_b64: pk.blob_b64,
            comment: pk.comment,
            fingerprint: fp,
            protection,
            usages,
        });
    }
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// (file label, line number, key blob) for every key in authorized_keys(2).
fn load_authorized_keys(ssh_dir: &Path) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for name in ["authorized_keys", "authorized_keys2"] {
        let Ok(text) = fs::read_to_string(ssh_dir.join(name)) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Lines may start with options (from="...",no-pty ...). Find the
            // first "<type> <blob>" pair that parses as a real key.
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let found = tokens.windows(2).find_map(|w| {
                parse_public_key(&format!("{} {}", w[0], w[1])).map(|pk| pk.blob_b64)
            });
            if let Some(blob) = found {
                out.push((format!("~/.ssh/{name}"), i + 1, blob));
            }
        }
    }
    out
}

/// (Host pattern, IdentityFile path) pairs from ~/.ssh/config.
/// A small parser: handles `Host`, `Match` (shown as-is) and `IdentityFile`
/// with `~` expansion. `Include` files are not followed.
pub fn parse_config_identities(text: &str, home: &Path, ssh_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut current_host = String::from("* (global)");
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Keywords are case-insensitive and may use "Key Value" or "Key=Value".
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim(), v.trim().trim_start_matches('=').trim()),
            None => continue,
        };
        let value = value.trim_matches('"');
        match key.to_ascii_lowercase().as_str() {
            "host" => current_host = value.to_string(),
            "match" => current_host = format!("Match {value}"),
            "identityfile" => {
                let p = if let Some(rest) = value.strip_prefix("~/") {
                    home.join(rest)
                } else if Path::new(value).is_absolute() {
                    PathBuf::from(value)
                } else {
                    ssh_dir.join(value)
                };
                out.push((current_host.clone(), p));
            }
            _ => {}
        }
    }
    out
}

/// Every name used in a `Host` line of ~/.ssh/config (patterns included).
pub fn config_host_names(ssh_dir: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(ssh_dir.join("config")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            k.eq_ignore_ascii_case("host").then_some(v)
        })
        .flat_map(|v| {
            v.split_whitespace()
                .map(|h| h.trim_matches('"').to_string())
        })
        .collect()
}

fn load_config_identities(ssh_dir: &Path) -> Vec<(String, PathBuf)> {
    let home = ssh_dir.parent().unwrap_or(ssh_dir);
    match fs::read_to_string(ssh_dir.join("config")) {
        Ok(text) => parse_config_identities(&text, home, ssh_dir),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway key generated for these tests only.
    const PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwl5p9MDS0Miy8ciLkR+kHUEbaV3z4H/Ol9q+halenY test@example";

    #[test]
    fn parses_public_key() {
        let pk = parse_public_key(PUB).unwrap();
        assert_eq!(pk.key_type, "ssh-ed25519");
        assert_eq!(pk.comment, "test@example");
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // Expected value from `ssh-keygen -lf` on the same key.
        let pk = parse_public_key(PUB).unwrap();
        assert_eq!(
            fingerprint(&pk.blob_b64).unwrap(),
            "SHA256:FA27cUSSf1Q5v4OMGvMY4NlXBlEvLItMQ6nzovpuHq8"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_public_key("ssh-ed25519 notbase64!!").is_none());
        assert!(
            parse_public_key(
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIKwl5p9MDS0Miy8ciLkR+kHUEbaV3z4H/Ol9q+halenY"
            )
            .is_none()
        );
        assert!(parse_public_key("").is_none());
    }

    #[test]
    fn config_identities() {
        let cfg = "Host github.com\n  IdentityFile ~/.ssh/id_work\nHost=box\n IdentityFile=\"/abs/key\"\n";
        let ids = parse_config_identities(cfg, Path::new("/Users/me"), Path::new("/Users/me/.ssh"));
        assert_eq!(
            ids[0],
            ("github.com".into(), PathBuf::from("/Users/me/.ssh/id_work"))
        );
        assert_eq!(ids[1], ("box".into(), PathBuf::from("/abs/key")));
    }

    /// End-to-end scan of a temp ~/.ssh with real keys. Skipped if ssh-keygen is missing.
    #[test]
    fn scan_real_keys() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("pkm-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let keygen = |name: &str, pass: &str| {
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", pass, "-C", name, "-f"])
                .arg(dir.join(name))
                .status()
        };
        if keygen("plain", "").is_err() {
            eprintln!("ssh-keygen not found, skipping");
            return;
        }
        keygen("locked", "secret-pass").unwrap();
        // A public key with no private half.
        fs::write(dir.join("other.pub"), format!("{PUB}\n")).unwrap();
        // Reference "plain" from authorized_keys and config.
        let plain_pub = fs::read_to_string(dir.join("plain.pub")).unwrap();
        fs::write(dir.join("authorized_keys"), format!("no-pty {plain_pub}")).unwrap();
        fs::write(
            dir.join("config"),
            format!(
                "Host github.com\n  IdentityFile {}\n",
                dir.join("plain").display()
            ),
        )
        .unwrap();

        let keys = scan(&dir, &HashSet::new()).unwrap();
        let get = |n: &str| keys.iter().find(|k| k.name == n).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(get("plain").protection, Protection::Unencrypted);
        assert!(matches!(get("locked").protection, Protection::Encrypted(_)));
        assert_eq!(get("other").protection, Protection::NoPrivateKey);
        assert_eq!(get("plain").priv_mode, Some(0o600));
        assert_eq!(get("plain").usages.len(), 2, "{:?}", get("plain").usages);
        assert!(get("locked").usages.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pem_detection() {
        let enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABC\n\nxx\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            detect_protection(enc),
            Protection::Encrypted("AES-128-CBC".into())
        );
        let plain = "-----BEGIN RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(detect_protection(plain), Protection::Unencrypted);
        assert_eq!(detect_protection("hello"), Protection::Unknown);
    }
}
