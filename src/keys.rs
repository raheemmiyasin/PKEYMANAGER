//! Discovering and describing SSH keys in ~/.ssh.
//!
//! Safety rule for this module: private key files are opened only to read their
//! *header* (cipher name / PEM headers) so we can tell whether a passphrase is set.
//! Their bytes are never returned, stored, printed, copied or moved.

// A hash set, like java.util.HashSet.
use std::collections::HashSet;
// File system functions: read files, list folders, file metadata.
use std::fs;
// `Path` = borrowed path (read-only view), `PathBuf` = owned path you can keep.
use std::path::{Path, PathBuf};

// `Engine` is a trait (interface); importing it makes `.decode()` / `.encode()` callable.
use base64::Engine;
// Two ready-made base64 engines: standard alphabet with and without `=` padding.
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
// SHA-256 hashing. `Digest` is the trait that provides `Sha256::digest(...)`.
use sha2::{Digest, Sha256};

/// Whether the private key half is protected by a passphrase.
///
/// Rust enums are "tagged unions": unlike a Java enum, each variant can carry its
/// own data (`Encrypted` carries the cipher name). Closer to a sealed interface
/// with record implementations in Java 17+.
///
/// `#[derive(...)]` auto-generates common behaviour:
///   Debug     -> can be printed with `{:?}` (like toString for debugging)
///   Clone     -> `.clone()` makes a deep copy
///   PartialEq, Eq -> `==` works (like equals())
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    // Has a passphrase; the String is the cipher, e.g. "aes256-ctr".
    Encrypted(String),
    // No passphrase: anyone with the file can use it.
    Unencrypted,
    // We couldn't read or recognise the file.
    Unknown,
    // Only the .pub exists here.
    NoPrivateKey,
}

impl Protection {
    /// Human-readable text for the details panel.
    pub fn label(&self) -> String {
        // `match self` checks which variant this is.
        match self {
            // `c` gets bound to the String inside Encrypted.
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
    // Which file, e.g. "~/.ssh/config".
    pub source: String,
    // What in that file, e.g. "Host github.com".
    pub detail: String,
}

/// Everything we know about one key. One row in the table.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    // File name without .pub, e.g. "id_ed25519".
    pub name: String,
    // Full path of the .pub file.
    pub pub_path: PathBuf,
    // Path of the private key, if it exists next to the .pub.
    pub priv_path: Option<PathBuf>,
    /// Unix permission bits of the private key, e.g. 0o600.
    /// `u32` = unsigned 32-bit integer.
    pub priv_mode: Option<u32>,
    // e.g. "ssh-ed25519".
    pub key_type: String,
    // The base64 middle part of the public key.
    pub blob_b64: String,
    // The comment at the end of the public key line.
    pub comment: String,
    // "SHA256:..." as printed by ssh-keygen -lf.
    pub fingerprint: String,
    // Passphrase status of the private key.
    pub protection: Protection,
    // Is it loaded in ssh-agent right now?
    pub in_agent: bool,
    // Where it's referenced.
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
        // `.as_str()` borrows the String as a &str so we can match on text.
        let t = self.key_type.as_str();
        // `match` works on strings too (Java's switch on String).
        let s = match t {
            "ssh-ed25519" => "ED25519",
            "ssh-rsa" => "RSA",
            "ssh-dss" => "DSA",
            "sk-ssh-ed25519@openssh.com" => "ED25519-SK",
            "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA-SK",
            // Guard: any type starting with "ecdsa-sha2-".
            _ if t.starts_with("ecdsa-sha2-") => "ECDSA",
            // Unknown type: show as-is.
            _ => t,
        };
        // Turn the borrowed &str into an owned String to return.
        s.to_string()
    }

    /// Private key readable by group/others? ssh refuses to use such keys.
    pub fn perms_too_open(&self) -> bool {
        // True if priv_mode is Some(m) AND any of the group/other bits (077) are set.
        // `&` here is bitwise AND (not a borrow) because it sits between two numbers.
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
    // An iterator over the words of the line (split on any whitespace).
    let mut parts = line.split_whitespace();
    // First word. `?` on an Option: if None, return None from this function.
    let key_type = parts.next()?;
    // Second word: the base64 data.
    let blob = parts.next()?;
    // Must be valid base64 and the blob must start with the same type string.
    // `.ok()` turns the Result into an Option so `?` works here.
    let raw = STANDARD.decode(blob).ok()?;
    // `.0` takes the first element of the returned tuple (the bytes).
    // `as_bytes()` views the &str as raw bytes for comparison.
    if read_ssh_string(&raw, 0)?.0 != key_type.as_bytes() {
        return None;
    }
    // Remaining words joined back together = the comment.
    // `collect::<Vec<_>>()` gathers an iterator into a Vec; `_` lets the compiler infer the item type.
    let comment = parts.collect::<Vec<_>>().join(" ");
    // Build the result, converting the borrowed &str pieces into owned Strings.
    Some(PublicKey {
        key_type: key_type.to_string(),
        blob_b64: blob.to_string(),
        comment,
    })
}

/// SHA256 fingerprint in the same format as `ssh-keygen -lf` (SHA256:base64-no-padding).
pub fn fingerprint(blob_b64: &str) -> Option<String> {
    // Decode the base64 text into raw bytes (`Vec<u8>`, like byte[]).
    let raw = STANDARD.decode(blob_b64).ok()?;
    // Hash the bytes.
    let digest = Sha256::digest(&raw);
    // Encode the hash as base64 without `=` padding, with "SHA256:" in front.
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
}

/// Read an SSH wire-format string (u32 big-endian length + bytes) at `pos`.
/// Returns the bytes and the position just after them.
///
/// The lifetime `'a` says "the returned slice borrows from `buf`": the compiler
/// will reject any caller that tries to use the slice after `buf` is gone.
/// `&'a [u8]` is a slice: a borrowed view of part of a byte array, no copying.
#[allow(clippy::needless_lifetimes)] // written out on purpose, for learning
fn read_ssh_string<'a>(buf: &'a [u8], pos: usize) -> Option<(&'a [u8], usize)> {
    // Take the 4 length bytes. `buf.get(range)` returns None instead of panicking
    // if out of bounds; `try_into()` converts the slice into a fixed [u8; 4] array.
    let len_bytes: [u8; 4] = buf.get(pos..pos + 4)?.try_into().ok()?;
    // Interpret them as a big-endian number, then convert to usize.
    let len = u32::from_be_bytes(len_bytes) as usize;
    // Data starts right after the length.
    let start = pos + 4;
    // `checked_add` returns None on overflow instead of wrapping around,
    // so a corrupt length can't crash us.
    let data = buf.get(start..start.checked_add(len)?)?;
    // Return a tuple: (the bytes, where the next field starts).
    Some((data, start + len))
}

/// Inspect a private key's *header only* to see if it is passphrase protected.
pub fn detect_protection(contents: &str) -> Protection {
    // Local constants: the markers around a modern OpenSSH private key.
    const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

    // `find` returns Option<usize>: the byte index of the marker, if present.
    if let Some(start) = contents.find(OPENSSH_BEGIN) {
        // `&contents[a..]` is a slice of the string from index a to the end (no copy).
        let after = &contents[start + OPENSSH_BEGIN.len()..];
        // Where the base64 body ends (or the end of text if the END marker is missing).
        let body_end = after.find(OPENSSH_END).unwrap_or(after.len());
        // Keep the body's characters minus newlines/spaces, collected into a String.
        let b64: String = after[..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        // Decode; on failure we can't tell, so Unknown.
        let Ok(raw) = STANDARD.decode(b64) else {
            return Protection::Unknown;
        };
        // Every OpenSSH key starts with these bytes. `b"..."` is a byte-string literal.
        const MAGIC: &[u8] = b"openssh-key-v1\0";
        if !raw.starts_with(MAGIC) {
            return Protection::Unknown;
        }
        // The first field after the magic is the cipher name: "none" = no passphrase.
        return match read_ssh_string(&raw, MAGIC.len()) {
            // Pattern on the bytes directly: matches if the field is exactly "none".
            Some((b"none", _)) => Protection::Unencrypted,
            // Any other cipher means it's encrypted. `from_utf8_lossy` turns bytes into text.
            Some((cipher, _)) => Protection::Encrypted(String::from_utf8_lossy(cipher).into()),
            None => Protection::Unknown,
        };
        // `raw` (the decoded key bytes) is freed here as it goes out of scope.
    }
    // Legacy PEM formats (old RSA/ECDSA keys, PKCS#8).
    if contents.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return Protection::Encrypted("pkcs8".into());
    }
    // Old-style "BEGIN RSA PRIVATE KEY" etc.
    if contents.contains("PRIVATE KEY-----") {
        // These headers mark an encrypted PEM key.
        if contents.contains("Proc-Type: 4,ENCRYPTED") {
            // Find the "DEK-Info: AES-128-CBC,..." line and take the cipher name.
            let cipher = contents
                .lines()
                // `find_map` returns the first non-None result; strip_prefix returns
                // the rest of the line if it started with the prefix.
                .find_map(|l| l.strip_prefix("DEK-Info: "))
                // Take the part before the first comma.
                .and_then(|v| v.split(',').next())
                // Fallback label.
                .unwrap_or("pem");
            return Protection::Encrypted(cipher.to_string());
        }
        return Protection::Unencrypted;
    }
    // Not a private key format we know.
    Protection::Unknown
}

/// Open the private key file just long enough to check its header.
fn read_private_key_protection(path: &Path) -> Protection {
    // Private keys are a few KB; refuse anything big so we never slurp random files.
    match fs::metadata(path) {
        // Size OK: do nothing and carry on.
        Ok(m) if m.len() <= 64 * 1024 => {}
        // Too big or unreadable.
        _ => return Protection::Unknown,
    }
    // `contents` is dropped (freed) at the end of this function: ownership means
    // nothing else can hold on to it, so the key material never leaves this scope.
    match fs::read_to_string(path) {
        // `&contents` lends the text to detect_protection; we keep ownership.
        Ok(contents) => detect_protection(&contents),
        Err(_) => Protection::Unknown,
    }
}

// `#[cfg(unix)]` = compile this version only on Unix-like systems (macOS, Linux).
#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    // Importing a trait inside a function limits it to this function.
    // `PermissionsExt` adds the Unix-only `.mode()` method.
    use std::os::unix::fs::PermissionsExt;
    // Read metadata, ignore errors, and keep only the permission bits (rwxrwxrwx).
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

// Fallback for non-Unix systems (e.g. Windows): no Unix modes there.
// `_path` starts with `_` to say "intentionally unused" (silences the warning).
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// Scan `ssh_dir` for `*.pub` files and build a `KeyInfo` for each.
/// `agent` holds fingerprints currently loaded in ssh-agent.
pub fn scan(ssh_dir: &Path, agent: &HashSet<String>) -> anyhow::Result<Vec<KeyInfo>> {
    // The result list; the compiler infers it's Vec<KeyInfo> from how it's used later.
    let mut keys = Vec::new();
    // List the folder.
    let entries = match fs::read_dir(ssh_dir) {
        Ok(e) => e,
        // Folder doesn't exist: not an error, just no keys.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
        // Other errors (e.g. permission denied): pass up. `.into()` converts to anyhow::Error.
        Err(e) => return Err(e.into()),
    };

    // Read authorized_keys and ~/.ssh/config once, up front.
    let authorized = load_authorized_keys(ssh_dir);
    let config_ids = load_config_identities(ssh_dir);

    // `.flatten()` skips entries that failed to read (each entry is a Result).
    for entry in entries.flatten() {
        // Full path of this file.
        let path = entry.path();
        // Skip anything that isn't a regular file ending in ".pub".
        // `extension()` gives Option<&OsStr>; `to_str()` converts to Option<&str>.
        if path.extension().and_then(|e| e.to_str()) != Some("pub") || !path.is_file() {
            continue;
        }
        // Read the .pub file; skip it if unreadable.
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        // First line that parses as a public key. Passing the function name
        // `parse_public_key` directly instead of a closure.
        let Some(pk) = text.lines().find_map(parse_public_key) else {
            continue;
        };
        // Compute the fingerprint.
        let Some(fp) = fingerprint(&pk.blob_b64) else {
            continue;
        };

        // "id_ed25519.pub" -> "id_ed25519": the expected private key path.
        let priv_candidate = path.with_extension("");
        // `cond.then_some(x)` = `if cond { Some(x) } else { None }`.
        // Note: priv_candidate is *moved* into the Option here.
        let priv_path = priv_candidate.is_file().then_some(priv_candidate);
        // `as_deref()` turns Option<PathBuf> into Option<&Path> (borrow the inside).
        // If there's a private key, check its passphrase; otherwise NoPrivateKey.
        let protection = priv_path
            .as_deref()
            .map(read_private_key_protection)
            .unwrap_or(Protection::NoPrivateKey);
        // Permission bits of the private key, if any.
        let priv_mode = priv_path.as_deref().and_then(file_mode);

        // Find lines in authorized_keys with the same key.
        let mut usages: Vec<Usage> = authorized
            .iter()
            // Each item is a tuple (file, line, blob); `_` skips fields we don't need.
            // `*blob` dereferences the borrowed String to compare its value.
            .filter(|(_, _, blob)| *blob == pk.blob_b64)
            // Turn each match into a Usage.
            .map(|(file, line, _)| Usage {
                source: file.clone(),
                detail: format!("line {line}: this key can log in to THIS Mac"),
            })
            .collect();
        // Look for Host blocks in ~/.ssh/config whose IdentityFile is this private key.
        if let Some(pp) = &priv_path {
            // `&config_ids` iterates by reference (no copying of the Vec).
            for (host, id_path) in &config_ids {
                if same_file(id_path, pp) {
                    usages.push(Usage {
                        source: "~/.ssh/config".into(),
                        detail: format!("Host {host}"),
                    });
                }
            }
        }

        // Build the KeyInfo and add it to the list.
        keys.push(KeyInfo {
            // File name without extension, converted to a String
            // (`to_string_lossy` handles non-UTF-8 names safely).
            name: path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            // Is this fingerprint in the agent's set?
            in_agent: agent.contains(&fp),
            // `path` is moved into the struct here; we can't use `path` after this line.
            // (That's why `name` above is computed first.)
            pub_path: path,
            priv_path,
            priv_mode,
            // Move the Strings out of `pk` into our struct (no copying).
            key_type: pk.key_type,
            blob_b64: pk.blob_b64,
            comment: pk.comment,
            fingerprint: fp,
            protection,
            usages,
        });
    }
    // Sort alphabetically by name. `cmp` returns Less/Equal/Greater, like compareTo.
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}

/// Are two paths the same file? Resolves symlinks and `..` first.
fn same_file(a: &Path, b: &Path) -> bool {
    // Match on a tuple of two Results at once.
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        // Both resolved: compare the real paths.
        (Ok(x), Ok(y)) => x == y,
        // Otherwise compare the paths as written.
        _ => a == b,
    }
}

/// (file label, line number, key blob) for every key in authorized_keys(2).
fn load_authorized_keys(ssh_dir: &Path) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    // Loop over an array of the two possible file names.
    for name in ["authorized_keys", "authorized_keys2"] {
        // Skip a file that doesn't exist.
        let Ok(text) = fs::read_to_string(ssh_dir.join(name)) else {
            continue;
        };
        // `enumerate()` pairs each item with its index (0-based), like a for-i loop.
        for (i, line) in text.lines().enumerate() {
            // Shadow `line` with its trimmed version.
            let line = line.trim();
            // Skip blank lines and comments.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Lines may start with options (from="...",no-pty ...). Find the
            // first "<type> <blob>" pair that parses as a real key.
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // `windows(2)` yields every pair of neighbours: [a,b], [b,c], [c,d]...
            let found = tokens.windows(2).find_map(|w| {
                parse_public_key(&format!("{} {}", w[0], w[1])).map(|pk| pk.blob_b64)
            });
            // Record it with a 1-based line number for humans.
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
    // Settings before any Host line apply to all hosts.
    let mut current_host = String::from("* (global)");
    for raw in text.lines() {
        let line = raw.trim();
        // Skip blank lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Keywords are case-insensitive and may use "Key Value" or "Key=Value".
        // `split_once` splits at the first character matching the closure.
        // `c: char` gives the closure parameter an explicit type.
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim(), v.trim().trim_start_matches('=').trim()),
            // A line with no value: skip it.
            None => continue,
        };
        // Remove surrounding double quotes.
        let value = value.trim_matches('"');
        // Compare the keyword in lowercase. `.as_str()` lets us match a String against literals.
        match key.to_ascii_lowercase().as_str() {
            // A new Host block starts.
            "host" => current_host = value.to_string(),
            "match" => current_host = format!("Match {value}"),
            // An IdentityFile inside the current block.
            "identityfile" => {
                // Turn the value into a full path. `if let ... else if ... else` chain:
                let p = if let Some(rest) = value.strip_prefix("~/") {
                    // "~/.ssh/x" -> "/Users/you/.ssh/x".
                    home.join(rest)
                } else if Path::new(value).is_absolute() {
                    // Already a full path.
                    PathBuf::from(value)
                } else {
                    // Relative path: relative to ~/.ssh.
                    ssh_dir.join(value)
                };
                // `.clone()` because current_host keeps being used for later lines.
                out.push((current_host.clone(), p));
            }
            // Other keywords are irrelevant here.
            _ => {}
        }
    }
    out
}

/// Every name used in a `Host` line of ~/.ssh/config (patterns included).
pub fn config_host_names(ssh_dir: &Path) -> Vec<String> {
    // No config file: empty list.
    let Ok(text) = fs::read_to_string(ssh_dir.join("config")) else {
        return Vec::new();
    };
    text.lines()
        // Keep only the value part of "Host ..." lines.
        .filter_map(|l| {
            let l = l.trim();
            // `?` inside a closure that returns Option: skip lines with no space/=.
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            // Case-insensitive "host"? Then Some(v), else None.
            k.eq_ignore_ascii_case("host").then_some(v)
        })
        // A Host line can list several names; `flat_map` flattens them into one stream.
        .flat_map(|v| {
            v.split_whitespace()
                .map(|h| h.trim_matches('"').to_string())
        })
        // Gather into a Vec<String> (the return type tells collect what to build).
        .collect()
}

/// Read ~/.ssh/config and return its IdentityFile entries.
fn load_config_identities(ssh_dir: &Path) -> Vec<(String, PathBuf)> {
    // Home folder = parent of ~/.ssh. `unwrap_or` falls back to ssh_dir itself.
    let home = ssh_dir.parent().unwrap_or(ssh_dir);
    match fs::read_to_string(ssh_dir.join("config")) {
        Ok(text) => parse_config_identities(&text, home, ssh_dir),
        Err(_) => Vec::new(),
    }
}

// Unit tests, compiled only by `cargo test`.
#[cfg(test)]
mod tests {
    // Everything from this file, including private functions.
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
        // Not base64.
        assert!(parse_public_key("ssh-ed25519 notbase64!!").is_none());
        // Says rsa but the data is an ed25519 key.
        assert!(
            parse_public_key(
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIKwl5p9MDS0Miy8ciLkR+kHUEbaV3z4H/Ol9q+halenY"
            )
            .is_none()
        );
        // Empty line.
        assert!(parse_public_key("").is_none());
    }

    #[test]
    fn config_identities() {
        // Both "Key Value" and "Key=Value" styles, with ~ and an absolute path.
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
        // A unique temp folder per test run (process id in the name).
        let dir = std::env::temp_dir().join(format!("pkm-test-{}", std::process::id()));
        // `let _ =` deliberately ignores the result (it's fine if the folder didn't exist).
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // A closure that runs ssh-keygen; it borrows `dir` from the surrounding function.
        let keygen = |name: &str, pass: &str| {
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", pass, "-C", name, "-f"])
                .arg(dir.join(name))
                .status()
        };
        // If ssh-keygen isn't installed, skip instead of failing.
        if keygen("plain", "").is_err() {
            eprintln!("ssh-keygen not found, skipping");
            return;
        }
        // A key with a passphrase.
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

        // Run the real scan with an empty agent set.
        let keys = scan(&dir, &HashSet::new()).unwrap();
        // Small helper closure to find a key by name.
        let get = |n: &str| keys.iter().find(|k| k.name == n).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(get("plain").protection, Protection::Unencrypted);
        assert!(matches!(get("locked").protection, Protection::Encrypted(_)));
        assert_eq!(get("other").protection, Protection::NoPrivateKey);
        assert_eq!(get("plain").priv_mode, Some(0o600));
        // Third argument = message printed if the assertion fails.
        assert_eq!(get("plain").usages.len(), 2, "{:?}", get("plain").usages);
        assert!(get("locked").usages.is_empty());
        // Clean up the temp folder.
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pem_detection() {
        // Old-style encrypted RSA key header.
        let enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABC\n\nxx\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            detect_protection(enc),
            Protection::Encrypted("AES-128-CBC".into())
        );
        // Old-style unencrypted key.
        let plain = "-----BEGIN RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(detect_protection(plain), Protection::Unencrypted);
        // Not a key at all.
        assert_eq!(detect_protection("hello"), Protection::Unknown);
    }
}
