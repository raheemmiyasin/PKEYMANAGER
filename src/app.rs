//! Application state and keyboard handling. No drawing here (see ui.rs) and no
//! terminal juggling (see main.rs): this keeps the logic easy to reason about.

// `PathBuf` is an owned, growable file path (like java.nio.file.Path, but mutable).
// Its borrowed, read-only cousin is `&Path` (like `String` vs `&str`).
use std::path::PathBuf;

// Key event types: which key (`KeyCode`), the full event (`KeyEvent`),
// and modifier keys such as Ctrl/Alt (`KeyModifiers`).
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
// Remembers which row of the key table is selected.
use ratatui::widgets::TableState;

// `crate::` means "from the root of this project" (like a fully-qualified
// package name). `self` imports the module itself so we can write `keys::scan`.
use crate::keys::{self, KeyInfo};
// Types and functions from our ssh.rs module.
use crate::ssh::{self, AfterSuccess, AgentStatus, HostAlias, Interactive};

/// Which screen/popup has the keyboard.
///
/// `pub` makes it visible outside this file (Rust items are private by default,
/// the opposite of Java's package-private default).
/// An `enum` in Rust can hold data in each variant (`Generate` carries a form).
/// Think of it as a sealed interface with one record per variant.
pub enum Mode {
    // The main list view.
    Normal,
    // Popup showing the full public key.
    ViewKey,
    // Popup listing the keyboard shortcuts.
    Help,
    // "New key" form; the form's state lives inside the variant.
    Generate(GenerateForm),
    // "Copy key to server" form.
    CopyToServer(ServerForm),
}

/// Form for "copy key to server" (ssh-copy-id).
///
/// `#[derive(Default)]` asks the compiler to write a `default()` constructor that
/// sets every field to its default (empty strings, 0, None). Like Lombok annotations.
#[derive(Default)]
pub struct ServerForm {
    /// [destination, port, alias]
    /// `[String; 3]` is a fixed-size array of exactly 3 Strings.
    pub fields: [String; 3],
    // Which field is being edited: 0, 1 or 2.
    // `usize` is an unsigned integer the size of a pointer; Rust uses it for indexes.
    pub focus: usize,
    // Error message to show in the form, or None when there is no error.
    pub error: Option<String>,
}

// `impl X { ... }` holds the methods/constants that belong to type X,
// like the body of a Java class. Data (struct) and behaviour (impl) are separate.
impl ServerForm {
    // `const` = compile-time constant, like `static final` in Java.
    // `&'static str` is a string literal baked into the program; `'static` means
    // "lives for the whole run of the program".
    pub const LABELS: [&'static str; 3] = ["Server", "Port", "Save as"];
    // Grey help text shown under each field.
    pub const HINTS: [&'static str; 3] = [
        "user@host, user@1.2.3.4, or a Host name from ~/.ssh/config",
        "blank = 22 (or whatever ~/.ssh/config says)",
        "optional: add `Host <name>` to ~/.ssh/config so `ssh <name>` works",
    ];
}

/// State of the "New ed25519 key" form.
#[derive(Default)]
pub struct GenerateForm {
    // File name for the new key, e.g. "id_ed25519_github".
    pub filename: String,
    // Comment stored inside the public key, e.g. "me@mac".
    pub comment: String,
    /// 0 = filename, 1 = comment
    pub focus: usize,
    // Validation error to display, if any.
    pub error: Option<String>,
}

/// What the main loop should do after a key press.
///
/// Returning an "intent" instead of doing it here is a common Rust pattern: the
/// App doesn't need to own the terminal, so we avoid borrowing it in two places
/// at once (the borrow checker would object, like a ConcurrentModificationException
/// caught at compile time).
pub enum Action {
    // Keep going.
    None,
    // Exit the program.
    Quit,
    // Leave the TUI and run this command (ssh-keygen, ssh-add, ssh-copy-id).
    RunInteractive(Interactive),
}

/// All the state of the running app. One instance lives in main.rs.
pub struct App {
    // Folder being scanned, normally ~/.ssh.
    pub ssh_dir: PathBuf,
    // The keys found. `Vec<T>` is a growable list, like `ArrayList<T>`.
    pub keys: Vec<KeyInfo>,
    // Which row is selected in the table.
    pub table: TableState,
    // Current screen/popup.
    pub mode: Mode,
    // Message in the yellow status line at the bottom.
    pub status: String,
    // Text in the header about ssh-agent, e.g. "agent: 2 key(s) loaded".
    pub agent_note: String,
}

impl App {
    // `-> Self` means "returns an App". `Self` is an alias for the type being implemented.
    // Rust has no constructors; a `new()` function is just a naming convention.
    pub fn new() -> Self {
        // Build the struct by naming every field (no `new` keyword in Rust).
        let mut app = App {
            // Find the ssh folder (~/.ssh or $PKEYMANAGER_SSH_DIR).
            ssh_dir: ssh::ssh_dir(),
            // Empty list for now; refresh() fills it.
            keys: Vec::new(),
            // Nothing selected yet.
            table: TableState::default(),
            // Start on the main screen.
            mode: Mode::Normal,
            // Empty strings.
            status: String::new(),
            agent_note: String::new(),
        };
        // Scan the folder and the agent. `app.refresh()` borrows `app` mutably for the call.
        app.refresh();
        // `.into()` converts the string literal (&str) into an owned String.
        app.status = "Press ? for help".into();
        // Return the app (no `return` needed for the last expression).
        app
    }

    /// Re-scan ~/.ssh and the agent, keeping the selection on the same key if possible.
    ///
    /// `&mut self` = this method may change the App (like a non-const method).
    /// `&self` would be read-only access.
    pub fn refresh(&mut self) {
        // Remember the fingerprint of the selected key so we can re-select it.
        // `.map(|k| ...)` transforms the value inside an Option (like Optional.map in Java).
        // `.clone()` makes our own copy of the String, because the borrowed key will
        // disappear when we replace `self.keys` below.
        let selected_fp = self.selected().map(|k| k.fingerprint.clone());

        // Ask ssh-agent which keys it holds. `match` here is an expression: each
        // arm's last value becomes the value of `agent`.
        let agent = match ssh::agent_fingerprints() {
            // Agent running: `set` is the set of fingerprints inside the variant.
            AgentStatus::Running(set) => {
                // `format!` builds a String, like String.format; `{}` is replaced by set.len().
                self.agent_note = format!("agent: {} key(s) loaded", set.len());
                // No semicolon: this is the value of the arm.
                set
            }
            // No agent: use an empty set.
            AgentStatus::NoAgent => {
                self.agent_note = "agent: not running".into();
                // `Default::default()` = the default value of the expected type (an empty HashSet).
                Default::default()
            }
            // Some other error; `{e}` inserts the variable `e` directly into the text.
            AgentStatus::Error(e) => {
                self.agent_note = format!("agent: {e}");
                Default::default()
            }
        };

        // Scan the folder. `&self.ssh_dir` and `&agent` lend the values without giving them away.
        match keys::scan(&self.ssh_dir, &agent) {
            // Success: replace the old list. The old Vec is freed automatically here.
            Ok(k) => self.keys = k,
            // Failure: empty the list and show the error.
            Err(e) => {
                self.keys.clear();
                self.status = format!("Cannot read {}: {e}", self.ssh_dir.display());
            }
        }

        // Work out which row to select:
        // `and_then` runs the closure only if we had a fingerprint, and the closure
        // itself returns an Option (position() is None if the key is gone).
        // `.iter().position(...)` finds the index of the first matching item, like indexOf with a predicate.
        // `.or(...)` supplies a fallback when the result is None: first row, or nothing if the list is empty.
        let idx = selected_fp
            .and_then(|fp| self.keys.iter().position(|k| k.fingerprint == fp))
            .or(if self.keys.is_empty() { None } else { Some(0) });
        // Apply the selection to the table.
        self.table.select(idx);
    }

    /// `Option<&KeyInfo>`: maybe a borrowed reference into `self.keys`.
    /// Like returning a nullable pointer, but the compiler forces callers to
    /// handle the `None` case and forbids keeping it after `keys` changes.
    pub fn selected(&self) -> Option<&KeyInfo> {
        // `table.selected()` is Option<usize>; `keys.get(i)` is Option<&KeyInfo>
        // (None if out of range, instead of throwing IndexOutOfBounds).
        self.table.selected().and_then(|i| self.keys.get(i))
    }

    /// Handle one key press and say what the main loop should do next.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        // Ctrl+C always quits. `&&` is logical AND; `==` compares values (like .equals in Java).
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        // We match on a *reference* (`&self.mode`) so nothing is moved out of `self`.
        // None of the arms keep that borrow alive, so they may call `&mut self` methods.
        match &self.mode {
            // Main screen: delegate to a helper method.
            Mode::Normal => self.on_key_normal(key),
            // `|` in a pattern means "either of these".
            Mode::ViewKey | Mode::Help => {
                match key.code {
                    // `if ...` after a pattern is a "guard": the arm only matches if it's true.
                    // `matches!(value, Pattern)` returns true/false.
                    // So: 'c' copies, but only while viewing a key.
                    KeyCode::Char('c') if matches!(self.mode, Mode::ViewKey) => {
                        self.copy_selected()
                    }
                    // `_` matches anything else: any other key closes the popup.
                    _ => self.mode = Mode::Normal,
                }
                // Popups never ask the main loop to do anything.
                Action::None
            }
            // `Generate(_)`: `_` ignores the data inside the variant.
            Mode::Generate(_) => self.on_key_generate(key),
            Mode::CopyToServer(_) => self.on_key_server(key),
        }
    }

    /// Keys on the main screen. Private (no `pub`): only usable inside this file.
    fn on_key_normal(&mut self, key: KeyEvent) -> Action {
        match key.code {
            // q or Esc quits. `return` leaves the function early with this value.
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            // Arrow down or j: move one row down.
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            // Arrow up or k: move one row up.
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            // Home/End jump to first/last row.
            KeyCode::Home => self.table.select_first(),
            KeyCode::End => self.table.select_last(),
            // Enter or v: open the "view public key" popup if a key is selected.
            KeyCode::Enter | KeyCode::Char('v') => {
                if self.selected().is_some() {
                    self.mode = Mode::ViewKey;
                }
            }
            // c: copy the public key to the clipboard.
            KeyCode::Char('c') => self.copy_selected(),
            // r: rescan.
            KeyCode::Char('r') => {
                self.refresh();
                self.status = "Refreshed".into();
            }
            // ?: show help.
            KeyCode::Char('?') => self.mode = Mode::Help,
            // n or g: open the "new key" form with sensible defaults.
            KeyCode::Char('n') | KeyCode::Char('g') => {
                self.mode = Mode::Generate(GenerateForm {
                    // First unused name like id_ed25519_2.
                    filename: free_filename(&self.ssh_dir),
                    // "user@hostname".
                    comment: default_comment(),
                    // `..Default::default()` = "all other fields take their default values"
                    // (like a builder that fills in the rest).
                    ..Default::default()
                });
            }
            // a: add to agent. This may need to run ssh-add, so we return its Action.
            KeyCode::Char('a') => return self.add_selected_to_agent(),
            // d: remove from agent (runs immediately, no prompt needed).
            KeyCode::Char('d') => self.remove_selected_from_agent(),
            // s: open the "copy to server" form, only if a key is selected (guard).
            KeyCode::Char('s') if self.selected().is_some() => {
                self.mode = Mode::CopyToServer(ServerForm::default());
            }
            // Ignore every other key. `match` must cover all cases, so `_` is required.
            _ => {}
        }
        // For all arms that didn't `return`, nothing more to do.
        Action::None
    }

    /// Move the selection up (-1) or down (+1), wrapping around at the ends.
    fn move_selection(&mut self, delta: i32) {
        // Nothing to move in an empty list.
        if self.keys.is_empty() {
            return;
        }
        // `as i32` converts the number type. Rust never converts numbers silently,
        // unlike Java's automatic int/long widening.
        let len = self.keys.len() as i32;
        // Current row, or 0 if none. `unwrap_or` = Optional.orElse.
        let cur = self.table.selected().unwrap_or(0) as i32;
        // `rem_euclid` is a modulo that is never negative, so -1 wraps to the last row.
        self.table
            .select(Some((cur + delta).rem_euclid(len) as usize));
    }

    /// Copy the selected public key to the clipboard and report in the status bar.
    fn copy_selected(&mut self) {
        // Clone the line first: we can't hold a borrow of self.keys while also
        // assigning to self.status (two borrows of `self`, one mutable).
        // `KeyInfo::public_line` passes the method itself as the function (like KeyInfo::publicLine in Java).
        let Some(line) = self.selected().map(KeyInfo::public_line) else {
            // No key selected: do nothing.
            return;
        };
        // Copy the name too; `unwrap_or_default()` gives "" if None.
        let name = self.selected().map(|k| k.name.clone()).unwrap_or_default();
        // `&line` lends the String as a &str. Status message depends on success/failure.
        self.status = match ssh::copy_to_clipboard(&line) {
            Ok(()) => format!("Copied public key {name}.pub to clipboard"),
            Err(e) => format!("Copy failed: {e}"),
        };
    }

    /// Prepare `ssh-add` for the selected key, or explain why it can't be added.
    fn add_selected_to_agent(&mut self) -> Action {
        // `k` is a borrowed reference to the selected key.
        let Some(k) = self.selected() else {
            return Action::None;
        };
        // Look at the private key path (an Option<PathBuf>) by reference.
        match &k.priv_path {
            // No private key file next to the .pub: nothing to load.
            None => {
                self.status = format!("{} has no private key here, nothing to add", k.name);
                Action::None
            }
            // Private key exists but is readable by others: ssh-add would refuse it.
            Some(_) if k.perms_too_open() => {
                // `.as_ref().unwrap()`: we know it's Some here; `unwrap()` takes the
                // value out and would crash if it were None (like Optional.get()).
                self.status = format!(
                    "Private key permissions too open; run: chmod 600 {}",
                    k.priv_path.as_ref().unwrap().display()
                );
                Action::None
            }
            // All good: ask main.rs to run ssh-add interactively.
            Some(p) => Action::RunInteractive(ssh::add_to_agent(p)),
        }
    }

    /// Run `ssh-add -d` for the selected key.
    fn remove_selected_from_agent(&mut self) {
        // `else { return }` on one line: leave if no key is selected.
        let Some(k) = self.selected() else { return };
        // `!k.in_agent` = not loaded; nothing to remove.
        if !k.in_agent {
            self.status = format!("{} is not loaded in the agent", k.name);
            return;
        }
        // Copy the two values we need into a tuple `(a, b)` and unpack it into two
        // variables. After this, `k` (the borrow of self) is no longer used, so we
        // are free to modify `self` below.
        let (name, pub_path) = (k.name.clone(), k.pub_path.clone());
        self.status = match ssh::remove_from_agent(&pub_path) {
            Ok(()) => format!("Removed {name} from agent (files untouched)"),
            Err(e) => format!("Remove failed: {e}"),
        };
        // Rescan so the Agent column updates.
        self.refresh();
    }

    /// Keys while the "New key" form is open.
    fn on_key_generate(&mut self, key: KeyEvent) -> Action {
        // Get a mutable reference to the form stored inside `self.mode`.
        let Mode::Generate(form) = &mut self.mode else {
            return Action::None;
        };
        match key.code {
            // Esc closes the form without doing anything.
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.status = "Cancelled".into();
            }
            // Tab / arrows switch between the 2 fields (0 <-> 1).
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                form.focus = 1 - form.focus;
            }
            // Backspace removes the last character. `.pop()` returns it; we ignore it.
            KeyCode::Backspace => {
                field_mut(form).pop();
            }
            // Ctrl+U empties the field.
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                field_mut(form).clear();
            }
            // Ignore other Ctrl/Alt chords so they don't end up as text.
            KeyCode::Char(_)
                if key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {}
            // A normal character: `c` is the char inside `Char(c)`; append it.
            KeyCode::Char(c) => {
                field_mut(form).push(c);
                form.error = None;
            }
            // Enter: validate and create the key.
            KeyCode::Enter => {
                // `.trim()` returns a &str view without surrounding spaces (no copy made).
                let name = form.filename.trim();
                // `if let Err(msg) = ...` runs the block only when the result is an Err.
                if let Err(msg) = validate_filename(name) {
                    form.error = Some(msg.into());
                    return Action::None;
                }
                // Build the full path: ~/.ssh/<name>.
                let path = self.ssh_dir.join(name);
                // Prepare the ssh-keygen command (fails if the file already exists).
                match ssh::generate_ed25519(&path, form.comment.trim()) {
                    Ok(cmd) => {
                        // Close the form and ask main.rs to run ssh-keygen.
                        self.mode = Mode::Normal;
                        return Action::RunInteractive(cmd);
                    }
                    // Show the error in the form. `.to_string()` turns the error into text.
                    Err(e) => form.error = Some(e.to_string()),
                }
            }
            // Any other key (F1, PageUp...): ignore.
            _ => {}
        }
        Action::None
    }

    /// Keys while the "Copy to server" form is open.
    fn on_key_server(&mut self, key: KeyEvent) -> Action {
        // Mutable reference to the form inside the enum variant.
        let Mode::CopyToServer(form) = &mut self.mode else {
            return Action::None;
        };
        match key.code {
            // Close the form.
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.status = "Cancelled".into();
            }
            // Next field, wrapping 0 -> 1 -> 2 -> 0. `%` is modulo.
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % 3,
            // Previous field: +2 mod 3 is the same as -1 without going negative
            // (usize can't be negative).
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
                // Host names already in ~/.ssh/config, to avoid duplicates.
                let hosts = keys::config_host_names(&self.ssh_dir);
                // Validate the form and build the ssh-copy-id command.
                match build_copy_command(form, k, &hosts) {
                    Ok(cmd) => {
                        self.mode = Mode::Normal;
                        return Action::RunInteractive(cmd);
                    }
                    // Show the validation message in the form.
                    Err(e) => form.error = Some(e),
                }
            }
            // Any other key edits the focused field.
            _ => {
                // `&mut form.fields[form.focus]` lends the focused String for editing.
                if edit_text(&mut form.fields[form.focus], key) {
                    // Clear the old error once the user types something.
                    form.error = None;
                }
            }
        }
        Action::None
    }

    /// Called by main.rs after an interactive command finishes.
    ///
    /// `cmd: &Interactive` borrows the command; `result` is moved in (we take ownership).
    pub fn after_interactive(&mut self, cmd: &Interactive, result: anyhow::Result<bool>) {
        // Decide the status message. Nested `match` expressions return a String.
        self.status = match result {
            // Command ran and exited with code 0.
            Ok(true) => match &cmd.then {
                // No follow-up step: just the success message.
                None => cmd.success_msg.clone(),
                // Follow-up: append a Host block to ~/.ssh/config.
                Some(AfterSuccess::AddHostAlias(alias)) => {
                    match ssh::append_host_alias(&self.ssh_dir, alias) {
                        // `Ok(_)`: success; `_` ignores the returned path.
                        Ok(_) => format!(
                            "{}. Added Host {} to ~/.ssh/config: try `ssh {}`",
                            cmd.success_msg, alias.alias, alias.alias
                        ),
                        Err(e) => format!("{}, but saving the alias failed: {e}", cmd.success_msg),
                    }
                }
            },
            // Command ran but exited with a non-zero code.
            Ok(false) => format!("{} exited with an error", cmd.program),
            // Command could not even start (e.g. program not found).
            Err(e) => e.to_string(),
        };
        // `std::mem::take` moves the String out and leaves an empty one behind.
        // We do this because refresh() may overwrite `self.status`, and we want
        // to keep our message.
        let status = std::mem::take(&mut self.status);
        // Rescan so new keys / agent changes show up.
        self.refresh();
        // Put our message back.
        self.status = status;
    }
}

/// Shared text editing for form fields. Returns true if the text changed.
///
/// A free function (not inside `impl`), like a static helper method.
/// `field: &mut String` = we may change the caller's String in place.
fn edit_text(field: &mut String, key: KeyEvent) -> bool {
    match key.code {
        // `pop()` returns Some(char) if something was removed; `.is_some()` turns that into true/false.
        KeyCode::Backspace => field.pop().is_some(),
        // Ctrl+U: clear.
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            field.clear();
            true
        }
        // Other Ctrl/Alt chords: ignore.
        KeyCode::Char(_)
            if key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            false
        }
        // Plain character: append.
        KeyCode::Char(c) => {
            field.push(c);
            true
        }
        // Anything else: no change.
        _ => false,
    }
}

/// Validate the server form and turn it into an ssh-copy-id command.
/// Returns `Err(message)` to show in the form.
///
/// `existing_hosts: &[String]` is a "slice": a borrowed view of a list
/// (works with a Vec or an array), like passing a read-only List<String>.
fn build_copy_command(
    form: &ServerForm,
    key: &KeyInfo,
    existing_hosts: &[String],
) -> Result<Interactive, String> {
    // Destructure the 3-element array into 3 named references.
    let [dest, port, alias] = &form.fields;
    // Shadowing: re-declare the same names as trimmed &str views. Allowed in Rust,
    // and common for "the same thing, cleaned up".
    let (dest, port, alias) = (dest.trim(), port.trim(), alias.trim());

    // Server is mandatory.
    if dest.is_empty() {
        return Err("Server is required, e.g. ubuntu@203.0.113.10".into());
    }
    // A leading '-' would be read as an option by ssh-copy-id.
    // `char::is_whitespace` passes a function as the "what to look for" argument.
    if dest.starts_with('-') || dest.contains(char::is_whitespace) {
        return Err("Server must look like user@host (no spaces, no leading '-')".into());
    }
    // Parse the port. `if` is an expression in Rust, so its value goes into `port`.
    // `u16` is an unsigned 16-bit integer (0..65535), exactly the range of TCP ports.
    let port: Option<u16> = if port.is_empty() {
        None
    } else {
        // `parse::<u16>()` converts text to a number, returning Result (like Integer.parseInt
        // but without throwing). `::<u16>` ("turbofish") tells it which type to produce.
        match port.parse::<u16>() {
            // Valid and not 0.
            Ok(p) if p > 0 => Some(p),
            // Anything else is an error; `return` leaves the whole function.
            _ => return Err(format!("Port must be a number 1-65535, got '{port}'")),
        }
    };

    // Work out the optional follow-up step (saving a Host alias).
    let then = if alias.is_empty() {
        // No alias requested.
        None
    } else {
        // `.chars().all(...)`: true if every character passes the test.
        // `"-_.".contains(c)`: c is one of those three characters.
        if !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err("Alias: letters, digits, '-', '_' and '.' only".into());
        }
        // Refuse a name that is already in ~/.ssh/config.
        if existing_hosts.iter().any(|h| h == alias) {
            return Err(format!("Host {alias} already exists in ~/.ssh/config"));
        }
        // The alias needs a private key to point IdentityFile at.
        let Some(identity) = key.priv_path.clone() else {
            return Err("This key has no private key here, so an alias can't use it".into());
        };
        // "ubuntu@1.2.3.4" -> (Some("ubuntu"), "1.2.3.4").
        let (user, hostname) = ssh::split_destination(dest);
        // If the destination is itself an alias, a new alias would point at a fake host name.
        if existing_hosts.contains(&hostname) {
            return Err(format!(
                "{hostname} is already a Host alias; leave 'Save as' empty"
            ));
        }
        // Build the follow-up step. Field names match variable names, so
        // `hostname,` is shorthand for `hostname: hostname,`.
        Some(AfterSuccess::AddHostAlias(HostAlias {
            alias: alias.to_string(),
            hostname,
            user,
            port,
            identity,
        }))
    };

    // Everything is valid: build the ssh-copy-id command and wrap it in Ok.
    Ok(ssh::copy_id_to_server(
        &key.pub_path,
        key.priv_path.is_some(),
        dest,
        port,
        then,
    ))
}

/// Return the field (filename or comment) that currently has focus.
///
/// Returning `&mut String` hands out a writable loan into `form`. The compiler
/// knows the result borrows from `form` and won't let the form be used elsewhere
/// while that loan is active.
fn field_mut(form: &mut GenerateForm) -> &mut String {
    if form.focus == 0 {
        &mut form.filename
    } else {
        &mut form.comment
    }
}

/// Check the new key's file name is safe. `Result<(), &'static str>`:
/// Ok(()) means valid; Err holds a fixed message.
fn validate_filename(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Filename is required");
    }
    // Block paths like "../x", hidden files, and names ending in .pub.
    if name.contains('/') || name.starts_with('.') || name.ends_with(".pub") {
        return Err(
            "Use a plain file name like id_ed25519_github (no '/', no leading '.', no .pub)",
        );
    }
    Ok(())
}

/// First of id_ed25519, id_ed25519_2, id_ed25519_3 ... that doesn't exist yet.
fn free_filename(dir: &std::path::Path) -> String {
    // `(1..)` is an endless range 1, 2, 3, ... Iterators are lazy (like Java Streams),
    // so only as many numbers as needed are generated.
    (1..)
        // Turn each number into a candidate file name.
        .map(|n| {
            if n == 1 {
                "id_ed25519".to_string()
            } else {
                format!("id_ed25519_{n}")
            }
        })
        // Stop at the first name where neither the key nor its .pub exists.
        .find(|name| !dir.join(name).exists() && !dir.join(format!("{name}.pub")).exists())
        // `find` returns an Option; `expect` unwraps it, crashing with this message if None
        // (which can't happen with an endless range).
        .expect("infinite iterator always finds a name")
}

/// Default comment for a new key: "user@short-hostname".
fn default_comment() -> String {
    // Read the USER environment variable; fall back to "me" if missing.
    // `|_|` is a closure that ignores its argument (the error).
    let user = std::env::var("USER").unwrap_or_else(|_| "me".into());
    // Run `hostname -s` and take its output.
    let host = std::process::Command::new("hostname")
        .arg("-s")
        // Run it and capture output. Returns Result.
        .output()
        // `.ok()` converts Result into Option (drops the error).
        .ok()
        // Convert the raw bytes to text and trim the trailing newline.
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        // Treat an empty result as "no value".
        .filter(|s| !s.is_empty())
        // Fallback if anything failed.
        .unwrap_or_else(|| "mac".into());
    format!("{user}@{host}")
}

// `#[cfg(test)]` = only compile this module when running `cargo test`.
// Like a src/test folder, but Rust usually keeps unit tests in the same file.
#[cfg(test)]
mod tests {
    // `super::*` imports everything from the parent module (this file), including private items.
    use super::*;

    // `#[test]` marks a test function, like JUnit's @Test.
    #[test]
    fn filename_rules() {
        // `assert!(cond)` fails the test if cond is false.
        assert!(validate_filename("id_ed25519_github").is_ok());
        assert!(validate_filename("").is_err());
        assert!(validate_filename("../evil").is_err());
        assert!(validate_filename("x.pub").is_err());
    }

    // Helper that builds a fake key for the tests.
    fn sample_key() -> KeyInfo {
        KeyInfo {
            name: "id_test".into(),
            pub_path: "/u/.ssh/id_test.pub".into(),
            priv_path: Some("/u/.ssh/id_test".into()),
            // `0o600` is an octal number literal (like 0600 in C/Java).
            priv_mode: Some(0o600),
            key_type: "ssh-ed25519".into(),
            blob_b64: String::new(),
            comment: String::new(),
            fingerprint: String::new(),
            protection: keys::Protection::Encrypted("aes256-ctr".into()),
            in_agent: false,
            // `vec![]` is a macro that creates an empty Vec.
            usages: vec![],
        }
    }

    // Helper that builds a filled-in server form.
    fn form(dest: &str, port: &str, alias: &str) -> ServerForm {
        ServerForm {
            fields: [dest.into(), port.into(), alias.into()],
            ..Default::default()
        }
    }

    #[test]
    fn copy_command_args() {
        // `.unwrap()` in tests is fine: if it's an Err, the test fails with a panic.
        let cmd =
            build_copy_command(&form("ubuntu@10.0.0.5", "2222", ""), &sample_key(), &[]).unwrap();
        // `assert_eq!(a, b)` fails if a != b and prints both values, like assertEquals.
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
        // Empty server.
        assert!(build_copy_command(&form("", "", ""), &k, &hosts).is_err());
        // Attempt to smuggle an ssh option in as the server.
        assert!(build_copy_command(&form("-oProxyCommand=x", "", ""), &k, &hosts).is_err());
        // Port out of range.
        assert!(build_copy_command(&form("u@h", "99999", ""), &k, &hosts).is_err());
        // Alias already exists.
        assert!(build_copy_command(&form("u@h", "", "prod"), &k, &hosts).is_err());
        // Alias with a space.
        assert!(build_copy_command(&form("u@h", "", "bad name"), &k, &hosts).is_err());
        // Existing alias as destination is fine without "Save as".
        assert!(build_copy_command(&form("prod", "", ""), &k, &hosts).is_ok());
    }

    #[test]
    fn alias_block() {
        let cmd =
            build_copy_command(&form("ubuntu@10.0.0.5", "", "web1"), &sample_key(), &[]).unwrap();
        // Pull the HostAlias out of the Option + enum, or fail the test.
        let Some(AfterSuccess::AddHostAlias(a)) = cmd.then else {
            panic!("no alias")
        };
        // The exact text that would be appended to ~/.ssh/config.
        assert_eq!(
            a.to_config_block(),
            "\nHost web1\n  HostName 10.0.0.5\n  User ubuntu\n  IdentityFile /u/.ssh/id_test\n  IdentitiesOnly yes\n"
        );
    }
}
