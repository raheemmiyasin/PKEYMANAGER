//! Thin wrappers around the system's OpenSSH tools and the clipboard.
//!
//! Anything that may ask for a passphrase (ssh-keygen, ssh-add) runs
//! *interactively* with the real terminal, so the passphrase goes straight from
//! your keyboard to OpenSSH and never passes through this program.

// Set of fingerprints returned by the agent.
use std::collections::HashSet;
// The `Write` trait gives files/pipes the `.write_all()` method.
use std::io::Write;
// Borrowed and owned file paths.
use std::path::{Path, PathBuf};
// `Command` runs external programs (like Java's ProcessBuilder);
// `Stdio` says where their input/output goes.
use std::process::{Command, Stdio};

// From the anyhow crate:
//   Context -> adds `.context("msg")` to errors (wraps them with a message, like a cause chain)
//   Result  -> Result<T, anyhow::Error>
//   bail!   -> macro: `return Err(anyhow!("..."))`, i.e. "throw new Exception(...)"
use anyhow::{Context, Result, bail};

/// State of ssh-agent as seen by `ssh-add -l`.
pub enum AgentStatus {
    // Agent running; holds the fingerprints of the loaded keys.
    Running(HashSet<String>),
    // No agent reachable.
    NoAgent,
    // Something else went wrong; holds the message.
    Error(String),
}

/// On macOS use Apple's ssh-add, because only it understands
/// `--apple-use-keychain`. A Homebrew openssh earlier in PATH would not.
pub fn ssh_add_bin() -> &'static str {
    // `cfg!(target_os = "macos")` is true when compiled for macOS (decided at compile time).
    if cfg!(target_os = "macos") && Path::new("/usr/bin/ssh-add").exists() {
        "/usr/bin/ssh-add"
    } else {
        // Elsewhere, use whatever is on PATH.
        "ssh-add"
    }
}

/// Fingerprints of keys currently loaded in the agent.
pub fn agent_fingerprints() -> AgentStatus {
    // Run `ssh-add -l -E sha256` and capture its output (doesn't touch the terminal).
    let out = match Command::new(ssh_add_bin())
        .args(["-l", "-E", "sha256"])
        .output()
    {
        Ok(o) => o,
        // Couldn't start ssh-add at all.
        Err(e) => return AgentStatus::Error(format!("cannot run ssh-add: {e}")),
    };
    // Exit codes: 0 = keys listed, 1 = agent has no keys, 2 = no agent.
    // `.code()` is Option<i32> (None if killed by a signal).
    match out.status.code() {
        Some(0) | Some(1) => {
            // Output bytes -> text. "lossy" replaces invalid UTF-8 instead of failing.
            let text = String::from_utf8_lossy(&out.stdout);
            // Each line looks like "256 SHA256:abc... comment (ED25519)".
            let fps = text
                .lines()
                // Take the 2nd word of each line (`nth(1)`, 0-based).
                .filter_map(|l| l.split_whitespace().nth(1))
                // Keep only real fingerprints.
                .filter(|f| f.starts_with("SHA256:"))
                // &str -> String. `str::to_string` is the function itself, like String::valueOf.
                .map(str::to_string)
                // Collect into a HashSet (inferred from AgentStatus::Running's type).
                .collect();
            AgentStatus::Running(fps)
        }
        Some(2) => AgentStatus::NoAgent,
        // Any other code: report ssh-add's error text.
        _ => AgentStatus::Error(String::from_utf8_lossy(&out.stderr).trim().to_string()),
    }
}

/// Copy text to the system clipboard (pbcopy on macOS; wl-copy/xclip elsewhere).
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    // A list of (program, arguments) to try in order.
    // `&[(&str, &[&str])]` reads: a slice of tuples, each a program name and a slice of args.
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else {
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])]
    };
    // Try each candidate until one works.
    for (bin, args) in candidates {
        // Start the program with a pipe on its stdin, discarding its output.
        // `.spawn()` starts it without waiting (like ProcessBuilder.start()).
        let Ok(mut child) = Command::new(bin)
            // `*args` dereferences: `args` here is a reference to a slice.
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            // Program not installed: try the next one.
            continue;
        };
        // `take()` moves the stdin handle out of `child`; when `stdin` goes out of
        // scope at the end of the block it is closed, which tells pbcopy we're done.
        // (Like try-with-resources: closing happens automatically at the `}`.)
        {
            // `.context("no stdin")` turns a None into an error with that message; `?` returns it.
            let mut stdin = child.stdin.take().context("no stdin")?;
            // Send the text as bytes.
            stdin.write_all(text.as_bytes())?;
        }
        // Wait for the program to finish.
        let status = child.wait()?;
        if status.success() {
            return Ok(());
        }
    }
    // None worked: return an error.
    bail!("no clipboard tool found (pbcopy / wl-copy / xclip)")
}

/// A command to run with the terminal handed over to it.
/// Built by the app, executed by main.rs after leaving the TUI.
#[derive(Debug, Clone)]
pub struct Interactive {
    // Program name, e.g. "ssh-keygen".
    pub program: String,
    // Its arguments.
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

/// The data for one `Host` block in ~/.ssh/config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAlias {
    // Short name you'll type: `ssh <alias>`.
    pub alias: String,
    // Real host name or IP.
    pub hostname: String,
    // Login user, if one was given.
    pub user: Option<String>,
    // Port, if not the default.
    pub port: Option<u16>,
    // Private key to use.
    pub identity: PathBuf,
}

impl HostAlias {
    /// Build the text to append to ~/.ssh/config.
    pub fn to_config_block(&self) -> String {
        // `\n` is a newline. `mut` because we keep adding to the String.
        let mut b = format!("\nHost {}\n  HostName {}\n", self.alias, self.hostname);
        // Only add "User" if we have one. `&self.user` borrows the Option to look inside.
        if let Some(u) = &self.user {
            // `+=` appends to a String; it takes a &str, hence `&format!(...)`.
            b += &format!("  User {u}\n");
        }
        // u16 is a simple Copy type, so no `&` needed.
        if let Some(p) = self.port {
            b += &format!("  Port {p}\n");
        }
        // IdentitiesOnly makes ssh use only this key, not every key in the agent.
        b += &format!(
            "  IdentityFile {}\n  IdentitiesOnly yes\n",
            quote_if_needed(&self.identity.display().to_string())
        );
        b
    }
}

/// Wrap a path in quotes if it contains a space (ssh config needs that).
fn quote_if_needed(s: &str) -> String {
    if s.contains(' ') {
        // `\"` is an escaped double quote inside a string.
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

/// Append a Host block to `<ssh_dir>/config`, creating it with mode 600 if needed.
/// Only ever appends: existing entries are never rewritten.
pub fn append_host_alias(ssh_dir: &Path, alias: &HostAlias) -> Result<PathBuf> {
    // OpenOptions configures how to open a file (like Java's StandardOpenOption flags).
    use std::fs::OpenOptions;
    let path = ssh_dir.join("config");
    // Remember whether it already existed, to set permissions on a new file only.
    let existed = path.exists();
    // Open for appending, creating the file if missing.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        // `with_context(|| ...)` adds a message; the closure only runs if there was an error.
        .with_context(|| format!("cannot open {}", path.display()))?;
    // On Unix, make a brand-new config readable only by you (ssh insists on this).
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = existed; // silence unused warning on non-unix
    // Write the block. The file is closed automatically when `file` goes out of scope.
    file.write_all(alias.to_config_block().as_bytes())?;
    Ok(path)
}

/// Split "user@host" into (Some(user), host); "host" gives (None, host).
pub fn split_destination(dest: &str) -> (Option<String>, String) {
    // `rsplit_once` splits at the LAST '@' (user names rarely contain '@', but just in case).
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
    // Build the argument list step by step.
    let mut args = Vec::new();
    // ssh-copy-id normally logs in with the private key first to see if it is
    // already installed. With only the .pub here that check can't work, so force.
    if !has_private {
        args.push("-f".to_string());
    }
    // `-i <file>`: which public key to install.
    args.push("-i".into());
    args.push(pub_path.display().to_string());
    // `-p <port>` only if a port was given.
    if let Some(p) = port {
        args.push("-p".into());
        args.push(p.to_string());
    }
    // Finally the destination, e.g. ubuntu@1.2.3.4.
    args.push(dest.to_string());
    // Build and return the command description (the last expression, no semicolon).
    Interactive {
        program: "ssh-copy-id".into(),
        args,
        banner: format!(
            "Installing {} on {dest}. Enter the SERVER password if asked.",
            pub_path.file_name().unwrap_or_default().to_string_lossy()
        ),
        success_msg: format!("Key installed on {dest}"),
        // `then` is moved into the struct.
        then,
    }
}

impl Interactive {
    /// Run the command attached to the real terminal and wait for it.
    /// Ok(true) = exit code 0, Ok(false) = non-zero, Err = couldn't start.
    pub fn run(&self) -> Result<bool> {
        // Print what is about to happen, so the user knows what's asking for input.
        println!("\n== {} ==", self.banner);
        println!("$ {} {}\n", self.program, self.args.join(" "));
        // `.status()` runs the program with our terminal as its stdin/stdout and waits.
        let status = Command::new(&self.program)
            .args(&self.args)
            .status()
            .with_context(|| format!("failed to start {}", self.program))?;
        Ok(status.success())
    }
}

/// `ssh-keygen -t ed25519` — ssh-keygen prompts for the passphrase itself.
pub fn generate_ed25519(path: &Path, comment: &str) -> Result<Interactive> {
    // Never overwrite an existing key.
    if path.exists() || path.with_extension("pub").exists() {
        bail!("{} already exists, pick another name", path.display());
    }
    // Make sure ~/.ssh exists with safe permissions.
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    Ok(Interactive {
        program: "ssh-keygen".into(),
        // `vec![...]` creates a Vec with these items.
        args: vec![
            // Key type.
            "-t".into(),
            "ed25519".into(),
            // 100 KDF rounds: slows down brute force of a stolen key file.
            "-a".into(),
            "100".into(),
            // Comment stored in the public key.
            "-C".into(),
            comment.into(),
            // Output file.
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
    // Only Apple's ssh-add knows this flag.
    if cfg!(target_os = "macos") {
        args.push("--apple-use-keychain".to_string());
    }
    // The private key file to load.
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
    // Runs silently in the background (`.output()` captures instead of showing).
    let out = Command::new(ssh_add_bin())
        .arg("-d")
        .arg(pub_path)
        .output()
        .context("cannot run ssh-add")?;
    // Non-zero exit: turn its error text into our error.
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// ~/.ssh, or $PKEYMANAGER_SSH_DIR if set (handy for trying the app on a copy).
pub fn ssh_dir() -> PathBuf {
    // `var_os` reads an environment variable; None if not set.
    if let Some(dir) = std::env::var_os("PKEYMANAGER_SSH_DIR") {
        return PathBuf::from(dir);
    }
    // $HOME/.ssh, or ./.ssh if HOME isn't set.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh")
}

/// Create ~/.ssh with mode 700 if it doesn't exist yet.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    // Already there: nothing to do.
    if dir.exists() {
        return Ok(());
    }
    // Create it (and any missing parents), like Files.createDirectories.
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    // On Unix, restrict to the owner only (rwx------).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
