//! PKEY MANAGER: a terminal UI for the SSH keys in ~/.ssh.
//!
//! Comments starting with `//!` describe the whole file (module docs).
//! Comments starting with `///` describe the item right below them (like Javadoc).
//! Comments starting with `//` are ordinary comments.
//!
//! Module layout (each `mod` is roughly a Java package/class file):
//!   keys.rs  scanning ~/.ssh, fingerprints, passphrase detection
//!   ssh.rs   calls to ssh-keygen / ssh-add / ssh-copy-id / pbcopy
//!   app.rs   state + keyboard handling
//!   ui.rs    drawing
//!
//! Quick Rust vocabulary used in the comments:
//!   - ownership: every value has exactly one owner variable. When the owner goes
//!     out of scope the value is freed automatically (no garbage collector, no free()).
//!   - borrow (`&x` / `&mut x`): lend a value without giving away ownership.
//!     `&x` = read-only loan (many allowed), `&mut x` = writable loan (only one at a time).
//!   - `Result<T, E>`: either `Ok(value)` or `Err(error)`. Rust has no exceptions;
//!     errors are normal return values. The `?` operator means
//!     "if this is an Err, return it from my function right now" (like re-throwing).
//!   - `Option<T>`: either `Some(value)` or `None`. Rust's replacement for null.

// `mod x;` tells the compiler "there is a file src/x.rs, include it as module x".
// Unlike Java, files are not picked up automatically; each must be declared once here.
mod app;
// Scanning ~/.ssh and reading key files.
mod keys;
// Running external ssh tools.
mod ssh;
// Drawing the screen.
mod ui;

// `use` is like Java `import`: it brings names into scope so we can write
// `Duration` instead of `std::time::Duration`.
// `io::{self, Write}` imports the module `io` itself and the `Write` trait.
// A trait is like a Java interface; its methods (here `flush`) are only callable
// when the trait is imported.
use std::io::{self, Write};
// `Duration` is a span of time, like java.time.Duration.
use std::time::Duration;

// `anyhow::Result<T>` is shorthand for `Result<T, anyhow::Error>`: a result whose
// error can be any kind of error (similar to declaring `throws Exception`).
use anyhow::Result;
// The terminal type ratatui gives us after `ratatui::init()`.
use ratatui::DefaultTerminal;
// Keyboard/mouse event types from crossterm (re-exported by ratatui).
use ratatui::crossterm::event::{self, Event, KeyEventKind};
// `execute!` is a macro (the `!` marks a macro) that sends terminal commands.
use ratatui::crossterm::execute;
// Functions to switch the terminal between "normal" and "full-screen app" modes.
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

// Bring our own types from app.rs into scope.
use app::{Action, App};

// `fn main()` is the program entry point, like `public static void main`.
// Returning `Result<()>` lets us use `?` inside main; if an error comes back,
// Rust prints it and exits with a non-zero code. `()` is the "unit" type,
// Rust's equivalent of `void`.
fn main() -> Result<()> {
    // `std::env::args()` is an iterator over command-line arguments.
    // `.any(|a| ...)` returns true if the closure returns true for any item.
    // `|a| a == "--version"` is a closure (lambda), like `a -> a.equals("--version")` in Java.
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        // `println!` is a macro that prints with a newline; `{}` is a placeholder.
        // `env!("CARGO_PKG_VERSION")` is filled in at compile time from Cargo.toml.
        println!("pkeymanager {}", env!("CARGO_PKG_VERSION"));
        // `Ok(())` means "success, nothing to return".
        return Ok(());
    }

    // ratatui::init() switches to raw mode + the alternate screen and installs a
    // panic hook that restores the terminal, so a crash never leaves it garbled.
    // `let mut` declares a variable that can be changed. Plain `let` is
    // immutable by default (like `final` in Java).
    let mut terminal = ratatui::init();
    // `&mut terminal` lends the terminal to `run` with write access;
    // `main` still owns it afterwards.
    let result = run(&mut terminal);
    // Put the terminal back to normal before exiting, whatever happened.
    ratatui::restore();
    // The last expression without a `;` is the return value of the function.
    result
}

/// The main loop: draw the screen, wait for a key, react to it, repeat.
///
/// `&mut DefaultTerminal`: we *borrow* the terminal mutably instead of taking
/// ownership, so `main` still owns it and can restore it afterwards.
fn run(terminal: &mut DefaultTerminal) -> Result<()> {
    // Create the app state (scans ~/.ssh). `App::new()` is like a static factory method.
    let mut app = App::new();
    // `loop` is an endless loop, like `while (true)`.
    loop {
        // Redraw the whole screen. `|f| ui::draw(f, &mut app)` is a closure that
        // ratatui calls with a Frame `f` to draw on. The trailing `?` returns
        // early from `run` if drawing failed.
        terminal.draw(|f| ui::draw(f, &mut app))?;

        // Wait up to 250 ms for input. If nothing arrived, go round the loop again.
        // `!` is boolean NOT.
        if !event::poll(Duration::from_millis(250))? {
            // `continue` jumps to the next loop iteration, same as Java.
            continue;
        }
        // `let PATTERN = value else { ... }` means: if the value matches the
        // pattern, bind the variables; otherwise run the else block (which must
        // leave, e.g. `continue`/`return`). Here we only care about key events,
        // and ignore mouse/resize events.
        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Ignore key-release events (sent by some terminals).
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // `match` is like a `switch` that must cover every case. `app.on_key`
        // returns an `Action` enum telling us what to do next.
        match app.on_key(key) {
            // Nothing special: `{}` is an empty block.
            Action::None => {}
            // User pressed q: leave `run` successfully, which ends the program.
            Action::Quit => return Ok(()),
            // The app wants to run ssh-keygen / ssh-add / ssh-copy-id.
            // `cmd` is the value stored inside this enum variant.
            Action::RunInteractive(cmd) => {
                // Hand the terminal to the command. `|| cmd.run()` is a closure
                // with no parameters.
                let result = with_terminal_suspended(terminal, || cmd.run());
                // Tell the app how it went. `&cmd` lends cmd instead of moving it.
                app.after_interactive(&cmd, result);
            }
        }
    }
}

/// Leave the TUI, hand the real terminal to `f` (so ssh-keygen/ssh-add can
/// prompt for a passphrase), then come back.
///
/// `<F>` makes this a generic function, like `<F> boolean run(F f)` in Java.
/// `F: FnOnce() -> Result<bool>` is a trait bound: "any closure that can be
/// called once and returns Result<bool>". Similar to `Supplier<T>` in Java,
/// but resolved at compile time with no boxing.
fn with_terminal_suspended<F>(terminal: &mut DefaultTerminal, f: F) -> Result<bool>
// `where` lists the requirements on the generic type F.
where
    F: FnOnce() -> Result<bool>,
{
    // Turn off raw mode so typed characters echo normally and Enter works.
    disable_raw_mode()?;
    // Switch back from the full-screen app view to the normal scrolling terminal.
    execute!(io::stdout(), LeaveAlternateScreen)?;
    // Make the text cursor visible again.
    terminal.show_cursor()?;

    // Run the command (e.g. ssh-keygen). We keep its result for later
    // instead of using `?`, so we always restore the TUI even if it failed.
    let result = f();

    // `print!` prints without a newline; `\n` is a newline character.
    print!("\nPress Enter to return to PKEY MANAGER...");
    // stdout is buffered; flush so the text appears before we wait for input.
    io::stdout().flush()?;
    // `String::new()` creates an empty, growable string (like `new StringBuilder()`).
    let mut buf = String::new();
    // Wait until the user presses Enter. `&mut buf` lets read_line write into buf.
    io::stdin().read_line(&mut buf)?;

    // Go back to the full-screen app view.
    execute!(io::stdout(), EnterAlternateScreen)?;
    // Raw mode: keys are delivered one by one without echo, which a TUI needs.
    enable_raw_mode()?;
    // Wipe the screen so the next draw starts clean.
    terminal.clear()?;
    // Return the command's result to the caller.
    result
}
