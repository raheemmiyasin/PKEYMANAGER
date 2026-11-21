//! Thin wrappers around the system's OpenSSH tools and the clipboard.
//!
//! Anything that may ask for a passphrase (ssh-keygen, ssh-add) runs
//! *interactively* with the real terminal, so the passphrase goes straight from
//! your keyboard to OpenSSH and never passes through this program.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// State of ssh-agent as seen by `ssh-add -l`.
pub enum AgentStatus {
    Running(HashSet<String>),
    NoAgent,
    Error(String),
}

/// On macOS use Apple's ssh-add, because only it understands
/// `--apple-use-keychain`. A Homebrew openssh earlier in PATH would not.
pub fn ssh_add_bin() -> &'static str {
    if cfg!(target_os = "macos") && Path::new("/usr/bin/ssh-add").exists() {
        "/usr/bin/ssh-add"
    } else {
        "ssh-add"
    }
}

/// Fingerprints of keys currently loaded in the agent.
pub fn agent_fingerprints() -> AgentStatus {
    let out = match Command::new(ssh_add_bin())
        .args(["-l", "-E", "sha256"])
        .output()
    {
        Ok(o) => o,
        Err(e) => return AgentStatus::Error(format!("cannot run ssh-add: {e}")),
    };
    // Exit codes: 0 = keys listed, 1 = agent has no keys, 2 = no agent.
    match out.status.code() {
        Some(0) | Some(1) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let fps = text
                .lines()
                .filter_map(|l| l.split_whitespace().nth(1))
                .filter(|f| f.starts_with("SHA256:"))
                .map(str::to_string)
                .collect();
            AgentStatus::Running(fps)
        }
        Some(2) => AgentStatus::NoAgent,
        _ => AgentStatus::Error(String::from_utf8_lossy(&out.stderr).trim().to_string()),
    }
}

/// Copy text to the system clipboard (pbcopy on macOS; wl-copy/xclip elsewhere).
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else {
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])]
    };
    for (bin, args) in candidates {
        let Ok(mut child) = Command::new(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        // `take()` moves the stdin handle out of `child`; when `stdin` goes out of
        // scope at the end of the block it is closed, which tells pbcopy we're done.
        {
            let mut stdin = child.stdin.take().context("no stdin")?;
            stdin.write_all(text.as_bytes())?;
        }
        let status = child.wait()?;
        if status.success() {
            return Ok(());
        }
    }
    bail!("no clipboard tool found (pbcopy / wl-copy / xclip)")
}

/// A command to run with the terminal handed over to it.
/// Built by the app, executed by main.rs after leaving the TUI.
#[derive(Debug, Clone)]
pub struct Interactive {
    pub program: String,
    pub args: Vec<String>,
    /// Shown before running so you know what is being asked.
    pub banner: String,
    /// Shown in the status bar if it exits 0.
    pub success_msg: String,
    /// Extra step to do only if the command succeeded.
    pub then: Option<AfterSuccess>,
}

/// Follow-up work after a successful interactive command.
#[derive(Debug, Clone)]
pub enum AfterSuccess {
    /// Append a `Host` block to ~/.ssh/config.
    AddHostAlias(HostAlias),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAlias {
    pub alias: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity: PathBuf,
}

impl HostAlias {
    pub fn to_config_block(&self) -> String {
        let mut b = format!("\nHost {}\n  HostName {}\n", self.alias, self.hostname);
        if let Some(u) = &self.user {
            b += &format!("  User {u}\n");
        }
        if let Some(p) = self.port {
            b += &format!("  Port {p}\n");
        }
        b += &format!(
            "  IdentityFile {}\n  IdentitiesOnly yes\n",
            quote_if_needed(&self.identity.display().to_string())
        );
        b
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.contains(' ') {
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

/// Append a Host block to `<ssh_dir>/config`, creating it with mode 600 if needed.
/// Only ever appends: existing entries are never rewritten.
pub fn append_host_alias(ssh_dir: &Path, alias: &HostAlias) -> Result<PathBuf> {
    use std::fs::OpenOptions;
    let path = ssh_dir.join("config");
    let existed = path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = existed; // silence unused warning on non-unix
    file.write_all(alias.to_config_block().as_bytes())?;
    Ok(path)
}

/// Split "user@host" into (Some(user), host); "host" gives (None, host).
pub fn split_destination(dest: &str) -> (Option<String>, String) {
    match dest.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, dest.to_string()),
    }
}

/// `ssh-copy-id -i key.pub [-p port] user@host`: logs in once (server password
/// is typed into ssh itself) and appends the key to ~/.ssh/authorized_keys on the server.
pub fn copy_id_to_server(
    pub_path: &Path,
    has_private: bool,
    dest: &str,
    port: Option<u16>,
    then: Option<AfterSuccess>,
) -> Interactive {
    let mut args = Vec::new();
    // ssh-copy-id normally logs in with the private key first to see if it is
    // already installed. With only the .pub here that check can't work, so force.
    if !has_private {
        args.push("-f".to_string());
    }
    args.push("-i".into());
    args.push(pub_path.display().to_string());
    if let Some(p) = port {
        args.push("-p".into());
        args.push(p.to_string());
    }
    args.push(dest.to_string());
    Interactive {
        program: "ssh-copy-id".into(),
        args,
        banner: format!(
            "Installing {} on {dest}. Enter the SERVER password if asked.",
            pub_path.file_name().unwrap_or_default().to_string_lossy()
        ),
        success_msg: format!("Key installed on {dest}"),
        then,
    }
}

impl Interactive {
    pub fn run(&self) -> Result<bool> {
        println!("\n== {} ==", self.banner);
        println!("$ {} {}\n", self.program, self.args.join(" "));
        let status = Command::new(&self.program)
            .args(&self.args)
            .status()
            .with_context(|| format!("failed to start {}", self.program))?;
        Ok(status.success())
    }
}

/// `ssh-keygen -t ed25519` — ssh-keygen prompts for the passphrase itself.
pub fn generate_ed25519(path: &Path, comment: &str) -> Result<Interactive> {
    if path.exists() || path.with_extension("pub").exists() {
        bail!("{} already exists, pick another name", path.display());
    }
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    Ok(Interactive {
        program: "ssh-keygen".into(),
        args: vec![
            "-t".into(),
            "ed25519".into(),
            // 100 KDF rounds: slows down brute force of a stolen key file.
            "-a".into(),
            "100".into(),
            "-C".into(),
            comment.into(),
            "-f".into(),
            path.display().to_string(),
        ],
        banner: "Generating a new ed25519 key. Choose a passphrase when asked.".into(),
        success_msg: format!("Created {}", path.display()),
        then: None,
    })
}

/// `ssh-add --apple-use-keychain <key>` on macOS (stores the passphrase in Keychain).
pub fn add_to_agent(priv_path: &Path) -> Interactive {
    let mut args = Vec::new();
    if cfg!(target_os = "macos") {
        args.push("--apple-use-keychain".to_string());
    }
    args.push(priv_path.display().to_string());
    Interactive {
        program: ssh_add_bin().into(),
        args,
        banner: "Adding key to ssh-agent. Enter the passphrase if asked.".into(),
        success_msg: format!("Added {} to agent", priv_path.display()),
        then: None,
    }
}

/// `ssh-add -d <key.pub>` — removes it from the running agent only (files untouched).
pub fn remove_from_agent(pub_path: &Path) -> Result<()> {
    let out = Command::new(ssh_add_bin())
        .arg("-d")
        .arg(pub_path)
        .output()
        .context("cannot run ssh-add")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// ~/.ssh, or $PKEYMANAGER_SSH_DIR if set (handy for trying the app on a copy).
pub fn ssh_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PKEYMANAGER_SSH_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh")
}

/// Create ~/.ssh with mode 700 if it doesn't exist yet.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
