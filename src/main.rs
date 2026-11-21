//! PKEY MANAGER: a terminal UI for the SSH keys in ~/.ssh.
//!
//! Module layout (each `mod` is roughly a Java package/class file):
//!   keys.rs  scanning ~/.ssh, fingerprints, passphrase detection
//!   ssh.rs   calls to ssh-keygen / ssh-add / pbcopy
//!   app.rs   state + keyboard handling
//!   ui.rs    drawing

mod app;
mod keys;
mod ssh;
mod ui;

use std::io::{self, Write};
use std::time::Duration;

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use app::{Action, App};

fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("pkeymanager {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // ratatui::init() switches to raw mode + the alternate screen and installs a
    // panic hook that restores the terminal, so a crash never leaves it garbled.
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

/// `&mut DefaultTerminal`: we *borrow* the terminal mutably instead of taking
/// ownership, so `main` still owns it and can restore it afterwards.
fn run(terminal: &mut DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Ignore key-release events (sent by some terminals).
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match app.on_key(key) {
            Action::None => {}
            Action::Quit => return Ok(()),
            Action::RunInteractive(cmd) => {
                let result = with_terminal_suspended(terminal, || cmd.run());
                app.after_interactive(&cmd, result);
            }
        }
    }
}

/// Leave the TUI, hand the real terminal to `f` (so ssh-keygen/ssh-add can
/// prompt for a passphrase), then come back.
///
/// `F: FnOnce() -> Result<bool>` is a trait bound: "any closure that can be
/// called once and returns Result<bool>". Similar to `Supplier<T>` in Java,
/// but resolved at compile time with no boxing.
fn with_terminal_suspended<F>(terminal: &mut DefaultTerminal, f: F) -> Result<bool>
where
    F: FnOnce() -> Result<bool>,
{
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    let result = f();

    print!("\nPress Enter to return to PKEY MANAGER...");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()?;
    result
}
