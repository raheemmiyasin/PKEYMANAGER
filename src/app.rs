//! Application state and keyboard handling. No drawing here (see ui.rs) and no
//! terminal juggling (see main.rs): this keeps the logic easy to reason about.

use std::path::PathBuf;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::keys::{self, KeyInfo};
use crate::ssh::{self, AfterSuccess, AgentStatus, HostAlias, Interactive};

/// Which screen/popup has the keyboard.
pub enum Mode {
    Normal,
    ViewKey,
    Help,
    Generate(GenerateForm),
    CopyToServer(ServerForm),
}

/// Form for "copy key to server" (ssh-copy-id).
#[derive(Default)]
pub struct ServerForm {
    /// [destination, port, alias]
    pub fields: [String; 3],
    pub focus: usize,
    pub error: Option<String>,
}

impl ServerForm {
    pub const LABELS: [&'static str; 3] = ["Server", "Port", "Save as"];
    pub const HINTS: [&'static str; 3] = [
        "user@host, user@1.2.3.4, or a Host name from ~/.ssh/config",
        "blank = 22 (or whatever ~/.ssh/config says)",
        "optional: add `Host <name>` to ~/.ssh/config so `ssh <name>` works",
    ];
}

#[derive(Default)]
pub struct GenerateForm {
    pub filename: String,
    pub comment: String,
    /// 0 = filename, 1 = comment
    pub focus: usize,
    pub error: Option<String>,
}

/// What the main loop should do after a key press.
///
/// Returning an "intent" instead of doing it here is a common Rust pattern: the
/// App doesn't need to own the terminal, so we avoid borrowing it in two places
/// at once (the borrow checker would object, like a ConcurrentModificationException
/// caught at compile time).
pub enum Action {
    None,
    Quit,
    RunInteractive(Interactive),
}

pub struct App {
    pub ssh_dir: PathBuf,
    pub keys: Vec<KeyInfo>,
    pub table: TableState,
    pub mode: Mode,
    pub status: String,
    pub agent_note: String,
}

impl App {
    pub fn new() -> Self {
        let mut app = App {
            ssh_dir: ssh::ssh_dir(),
            keys: Vec::new(),
            table: TableState::default(),
            mode: Mode::Normal,
            status: String::new(),
            agent_note: String::new(),
        };
        app.refresh();
        app.status = "Press ? for help".into();
        app
    }

    /// Re-scan ~/.ssh and the agent, keeping the selection on the same key if possible.
    pub fn refresh(&mut self) {
        let selected_fp = self.selected().map(|k| k.fingerprint.clone());

        let agent = match ssh::agent_fingerprints() {
            AgentStatus::Running(set) => {
                self.agent_note = format!("agent: {} key(s) loaded", set.len());
                set
            }
            AgentStatus::NoAgent => {
                self.agent_note = "agent: not running".into();
                Default::default()
            }
            AgentStatus::Error(e) => {
                self.agent_note = format!("agent: {e}");
                Default::default()
            }
        };

        match keys::scan(&self.ssh_dir, &agent) {
            Ok(k) => self.keys = k,
            Err(e) => {
                self.keys.clear();
                self.status = format!("Cannot read {}: {e}", self.ssh_dir.display());
            }
        }

        let idx = selected_fp
            .and_then(|fp| self.keys.iter().position(|k| k.fingerprint == fp))
            .or(if self.keys.is_empty() { None } else { Some(0) });
        self.table.select(idx);
    }

    /// `Option<&KeyInfo>`: maybe a borrowed reference into `self.keys`.
    /// Like returning a nullable pointer, but the compiler forces callers to
    /// handle the `None` case and forbids keeping it after `keys` changes.
    pub fn selected(&self) -> Option<&KeyInfo> {
        self.table.selected().and_then(|i| self.keys.get(i))
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        // We match on a *reference* (`&self.mode`) so nothing is moved out of `self`.
        // None of the arms keep that borrow alive, so they may call `&mut self` methods.
        match &self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::ViewKey | Mode::Help => {
                match key.code {
                    KeyCode::Char('c') if matches!(self.mode, Mode::ViewKey) => {
                        self.copy_selected()
                    }
                    _ => self.mode = Mode::Normal,
                }
                Action::None
            }
            Mode::Generate(_) => self.on_key_generate(key),
            Mode::CopyToServer(_) => self.on_key_server(key),
        }
    }

    fn on_key_normal(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home => self.table.select_first(),
            KeyCode::End => self.table.select_last(),
            KeyCode::Enter | KeyCode::Char('v') => {
                if self.selected().is_some() {
                    self.mode = Mode::ViewKey;
                }
            }
            KeyCode::Char('c') => self.copy_selected(),
            KeyCode::Char('r') => {
                self.refresh();
                self.status = "Refreshed".into();
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('n') | KeyCode::Char('g') => {
                self.mode = Mode::Generate(GenerateForm {
                    filename: free_filename(&self.ssh_dir),
                    comment: default_comment(),
                    ..Default::default()
                });
            }
            KeyCode::Char('a') => return self.add_selected_to_agent(),
            KeyCode::Char('d') => self.remove_selected_from_agent(),
            KeyCode::Char('s') if self.selected().is_some() => {
                self.mode = Mode::CopyToServer(ServerForm::default());
            }
            _ => {}
        }
        Action::None
    }

    fn move_selection(&mut self, delta: i32) {
        if self.keys.is_empty() {
            return;
        }
        let len = self.keys.len() as i32;
        let cur = self.table.selected().unwrap_or(0) as i32;
        self.table
            .select(Some((cur + delta).rem_euclid(len) as usize));
    }

    fn copy_selected(&mut self) {
        // Clone the line first: we can't hold a borrow of self.keys while also
        // assigning to self.status (two borrows of `self`, one mutable).
        let Some(line) = self.selected().map(KeyInfo::public_line) else {
            return;
        };
        let name = self.selected().map(|k| k.name.clone()).unwrap_or_default();
        self.status = match ssh::copy_to_clipboard(&line) {
            Ok(()) => format!("Copied public key {name}.pub to clipboard"),
            Err(e) => format!("Copy failed: {e}"),
        };
    }

    fn add_selected_to_agent(&mut self) -> Action {
        let Some(k) = self.selected() else {
            return Action::None;
        };
        match &k.priv_path {
            None => {
                self.status = format!("{} has no private key here, nothing to add", k.name);
                Action::None
            }
            Some(_) if k.perms_too_open() => {
                self.status = format!(
                    "Private key permissions too open; run: chmod 600 {}",
                    k.priv_path.as_ref().unwrap().display()
                );
                Action::None
            }
            Some(p) => Action::RunInteractive(ssh::add_to_agent(p)),
        }
    }

    fn remove_selected_from_agent(&mut self) {
        let Some(k) = self.selected() else { return };
        if !k.in_agent {
            self.status = format!("{} is not loaded in the agent", k.name);
            return;
        }
        let (name, pub_path) = (k.name.clone(), k.pub_path.clone());
        self.status = match ssh::remove_from_agent(&pub_path) {
            Ok(()) => format!("Removed {name} from agent (files untouched)"),
            Err(e) => format!("Remove failed: {e}"),
        };
        self.refresh();
    }

    fn on_key_generate(&mut self, key: KeyEvent) -> Action {
        let Mode::Generate(form) = &mut self.mode else {
            return Action::None;
        };
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.status = "Cancelled".into();
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                form.focus = 1 - form.focus;
            }
            KeyCode::Backspace => {
                field_mut(form).pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                field_mut(form).clear();
            }
            // Ignore other Ctrl/Alt chords so they don't end up as text.
            KeyCode::Char(_)
                if key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {}
            KeyCode::Char(c) => {
                field_mut(form).push(c);
                form.error = None;
            }
            KeyCode::Enter => {
                let name = form.filename.trim();
                if let Err(msg) = validate_filename(name) {
                    form.error = Some(msg.into());
                    return Action::None;
                }
                let path = self.ssh_dir.join(name);
                match ssh::generate_ed25519(&path, form.comment.trim()) {
                    Ok(cmd) => {
                        self.mode = Mode::Normal;
                        return Action::RunInteractive(cmd);
                    }
                    Err(e) => form.error = Some(e.to_string()),
                }
            }
            _ => {}
        }
        Action::None
    }

    fn on_key_server(&mut self, key: KeyEvent) -> Action {
        let Mode::CopyToServer(form) = &mut self.mode else {
            return Action::None;
        };
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.status = "Cancelled".into();
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % 3,
            KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + 2) % 3,
            KeyCode::Enter => {
                // Clone what we need from the selected key first, then build the
                // command. `self.selected()` borrows `self` immutably, and we still
                // hold `form` (a mutable borrow of self.mode), so we can't call it
                // here; index into `self.keys` directly instead. Disjoint fields
                // (`self.mode` vs `self.keys`) can be borrowed at the same time.
                let Some(k) = self.table.selected().and_then(|i| self.keys.get(i)) else {
                    return Action::None;
                };
                let hosts = keys::config_host_names(&self.ssh_dir);
                match build_copy_command(form, k, &hosts) {
                    Ok(cmd) => {
                        self.mode = Mode::Normal;
                        return Action::RunInteractive(cmd);
                    }
                    Err(e) => form.error = Some(e),
                }
            }
            _ => {
                if edit_text(&mut form.fields[form.focus], key) {
                    form.error = None;
                }
            }
        }
        Action::None
    }

    /// Called by main.rs after an interactive command finishes.
    pub fn after_interactive(&mut self, cmd: &Interactive, result: anyhow::Result<bool>) {
        self.status = match result {
            Ok(true) => match &cmd.then {
                None => cmd.success_msg.clone(),
                Some(AfterSuccess::AddHostAlias(alias)) => {
                    match ssh::append_host_alias(&self.ssh_dir, alias) {
                        Ok(_) => format!(
                            "{}. Added Host {} to ~/.ssh/config: try `ssh {}`",
                            cmd.success_msg, alias.alias, alias.alias
                        ),
                        Err(e) => format!("{}, but saving the alias failed: {e}", cmd.success_msg),
                    }
                }
            },
            Ok(false) => format!("{} exited with an error", cmd.program),
            Err(e) => e.to_string(),
        };
        let status = std::mem::take(&mut self.status);
        self.refresh();
        self.status = status;
    }
}

/// Shared text editing for form fields. Returns true if the text changed.
fn edit_text(field: &mut String, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Backspace => field.pop().is_some(),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            field.clear();
            true
        }
        KeyCode::Char(_)
            if key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            false
        }
        KeyCode::Char(c) => {
            field.push(c);
            true
        }
        _ => false,
    }
}

/// Validate the server form and turn it into an ssh-copy-id command.
/// Returns `Err(message)` to show in the form.
fn build_copy_command(
    form: &ServerForm,
    key: &KeyInfo,
    existing_hosts: &[String],
) -> Result<Interactive, String> {
    let [dest, port, alias] = &form.fields;
    let (dest, port, alias) = (dest.trim(), port.trim(), alias.trim());

    if dest.is_empty() {
        return Err("Server is required, e.g. ubuntu@203.0.113.10".into());
    }
    // A leading '-' would be read as an option by ssh-copy-id.
    if dest.starts_with('-') || dest.contains(char::is_whitespace) {
        return Err("Server must look like user@host (no spaces, no leading '-')".into());
    }
    let port: Option<u16> = if port.is_empty() {
        None
    } else {
        match port.parse::<u16>() {
            Ok(p) if p > 0 => Some(p),
            _ => return Err(format!("Port must be a number 1-65535, got '{port}'")),
        }
    };

    let then = if alias.is_empty() {
        None
    } else {
        if !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err("Alias: letters, digits, '-', '_' and '.' only".into());
        }
        if existing_hosts.iter().any(|h| h == alias) {
            return Err(format!("Host {alias} already exists in ~/.ssh/config"));
        }
        let Some(identity) = key.priv_path.clone() else {
            return Err("This key has no private key here, so an alias can't use it".into());
        };
        let (user, hostname) = ssh::split_destination(dest);
        if existing_hosts.contains(&hostname) {
            return Err(format!(
                "{hostname} is already a Host alias; leave 'Save as' empty"
            ));
        }
        Some(AfterSuccess::AddHostAlias(HostAlias {
            alias: alias.to_string(),
            hostname,
            user,
            port,
            identity,
        }))
    };

    Ok(ssh::copy_id_to_server(
        &key.pub_path,
        key.priv_path.is_some(),
        dest,
        port,
        then,
    ))
}

fn field_mut(form: &mut GenerateForm) -> &mut String {
    if form.focus == 0 {
        &mut form.filename
    } else {
        &mut form.comment
    }
}

fn validate_filename(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Filename is required");
    }
    if name.contains('/') || name.starts_with('.') || name.ends_with(".pub") {
        return Err(
            "Use a plain file name like id_ed25519_github (no '/', no leading '.', no .pub)",
        );
    }
    Ok(())
}

/// First of id_ed25519, id_ed25519_2, id_ed25519_3 ... that doesn't exist yet.
fn free_filename(dir: &std::path::Path) -> String {
    (1..)
        .map(|n| {
            if n == 1 {
                "id_ed25519".to_string()
            } else {
                format!("id_ed25519_{n}")
            }
        })
        .find(|name| !dir.join(name).exists() && !dir.join(format!("{name}.pub")).exists())
        .expect("infinite iterator always finds a name")
}

fn default_comment() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "me".into());
    let host = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mac".into());
    format!("{user}@{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_rules() {
        assert!(validate_filename("id_ed25519_github").is_ok());
        assert!(validate_filename("").is_err());
        assert!(validate_filename("../evil").is_err());
        assert!(validate_filename("x.pub").is_err());
    }

    fn sample_key() -> KeyInfo {
        KeyInfo {
            name: "id_test".into(),
            pub_path: "/u/.ssh/id_test.pub".into(),
            priv_path: Some("/u/.ssh/id_test".into()),
            priv_mode: Some(0o600),
            key_type: "ssh-ed25519".into(),
            blob_b64: String::new(),
            comment: String::new(),
            fingerprint: String::new(),
            protection: keys::Protection::Encrypted("aes256-ctr".into()),
            in_agent: false,
            usages: vec![],
        }
    }

    fn form(dest: &str, port: &str, alias: &str) -> ServerForm {
        ServerForm {
            fields: [dest.into(), port.into(), alias.into()],
            ..Default::default()
        }
    }

    #[test]
    fn copy_command_args() {
        let cmd =
            build_copy_command(&form("ubuntu@10.0.0.5", "2222", ""), &sample_key(), &[]).unwrap();
        assert_eq!(cmd.program, "ssh-copy-id");
        assert_eq!(
            cmd.args,
            ["-i", "/u/.ssh/id_test.pub", "-p", "2222", "ubuntu@10.0.0.5"]
        );
        assert!(cmd.then.is_none());
    }

    #[test]
    fn copy_command_validation() {
        let k = sample_key();
        let hosts = vec!["prod".to_string()];
        assert!(build_copy_command(&form("", "", ""), &k, &hosts).is_err());
        assert!(build_copy_command(&form("-oProxyCommand=x", "", ""), &k, &hosts).is_err());
        assert!(build_copy_command(&form("u@h", "99999", ""), &k, &hosts).is_err());
        assert!(build_copy_command(&form("u@h", "", "prod"), &k, &hosts).is_err());
        assert!(build_copy_command(&form("u@h", "", "bad name"), &k, &hosts).is_err());
        // Existing alias as destination is fine without "Save as".
        assert!(build_copy_command(&form("prod", "", ""), &k, &hosts).is_ok());
    }

    #[test]
    fn alias_block() {
        let cmd =
            build_copy_command(&form("ubuntu@10.0.0.5", "", "web1"), &sample_key(), &[]).unwrap();
        let Some(AfterSuccess::AddHostAlias(a)) = cmd.then else {
            panic!("no alias")
        };
        assert_eq!(
            a.to_config_block(),
            "\nHost web1\n  HostName 10.0.0.5\n  User ubuntu\n  IdentityFile /u/.ssh/id_test\n  IdentitiesOnly yes\n"
        );
    }
}
