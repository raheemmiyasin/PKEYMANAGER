//! Drawing. Every frame is redrawn from `App` state (immediate-mode UI, a bit
//! like a React render function: state in, widgets out).
//!
//! ratatui basics:
//!   - `Frame` is the canvas for one screen refresh.
//!   - `Rect` is a rectangle on screen (x, y, width, height in character cells).
//!   - `Layout` splits a Rect into smaller Rects (rows or columns), like CSS flexbox.
//!   - Widgets (`Paragraph`, `Table`, `Block`...) are built fresh each frame and
//!     "rendered" into a Rect. Nothing is kept between frames except App state.

// The drawing surface for one frame.
use ratatui::Frame;
// Screen-splitting tools.
use ratatui::layout::{Constraint, Layout, Rect};
// Colours and text styles. `Stylize` is a trait that adds shortcut methods such as
// `.green()`, `.bold()`, `.on_cyan()` to strings, spans and widgets.
use ratatui::style::{Color, Modifier, Style, Stylize};
// `Line` = one line of text, made of `Span`s (pieces with their own style).
use ratatui::text::{Line, Span};
// The widgets we use.
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, Wrap};

// Our own types.
use crate::app::{App, Mode, ServerForm};
use crate::keys::{KeyInfo, Protection};

/// Draw the whole screen. Called once per loop iteration from main.rs.
///
/// `app: &mut App` is mutable only because the table widget updates its scroll
/// position inside `app.table`.
pub fn draw(f: &mut Frame, app: &mut App) {
    // Split the screen into 3 rows: header (1 line), body (rest, at least 5), footer (2 lines).
    // `.areas(...)` returns a fixed-size array, which we destructure into 3 variables.
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(f.area());

    // Top line.
    draw_header(f, header, app);

    // Split the body: 45% for the key table, 55% for the details panel.
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);
    // Draw each part into its rectangle.
    draw_table(f, table_area, app);
    draw_details(f, detail_area, app);
    draw_footer(f, footer, app);

    // Popups are drawn last so they appear on top.
    match &app.mode {
        // No popup on the main screen.
        Mode::Normal => {}
        Mode::ViewKey => draw_view_key(f, app),
        Mode::Help => draw_help(f),
        Mode::Generate(_) => draw_generate(f, app),
        Mode::CopyToServer(_) => draw_copy_to_server(f, app),
    }
}

/// Top line: app name, folder, agent status.
fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    // A Line made of 3 styled pieces. `vec![...]` builds the list.
    let line = Line::from(vec![
        // Black text on a cyan background, bold.
        " PKEY MANAGER ".black().on_cyan().bold(),
        // A plain piece; `.into()` converts the String into a Span.
        format!("  {}  ", app.ssh_dir.display()).into(),
        // Grey text. `.clone()` because the Span needs its own String.
        app.agent_note.clone().dark_gray(),
    ]);
    // Paint it into the header rectangle.
    f.render_widget(Paragraph::new(line), area);
}

/// The table of keys.
fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    // Column titles in bold cyan.
    let header = Row::new(["Name", "Type", "Comment", "Private", "Agent"])
        .style(Style::new().bold().fg(Color::Cyan));

    // Turn each KeyInfo into a table Row (like `keys.stream().map(...).toList()`).
    let rows: Vec<Row> = app
        .keys
        .iter()
        .map(|k| {
            // Coloured "Private" cell depending on passphrase status.
            let private = match &k.protection {
                Protection::NoPrivateKey => Cell::from("—").dark_gray(),
                Protection::Encrypted(_) => Cell::from("🔒 yes").green(),
                Protection::Unencrypted => Cell::from("⚠ no pass").yellow(),
                Protection::Unknown => Cell::from("? yes").gray(),
            };
            // "Agent" cell. `if` is an expression, so it produces the cell directly.
            let agent = if k.in_agent {
                Cell::from("● loaded").green()
            } else {
                Cell::from("—").dark_gray()
            };
            // One row with 5 cells, in the same order as the header.
            Row::new(vec![
                Cell::from(k.name.clone()),
                Cell::from(k.short_type()),
                Cell::from(k.comment.clone()),
                private,
                agent,
            ])
        })
        .collect();

    // Border title, e.g. " Keys (3) ".
    let title = format!(" Keys ({}) ", app.keys.len());
    // Build the table with column widths.
    let table = Table::new(
        rows,
        [
            // Name: a quarter of the width.
            Constraint::Percentage(25),
            // Type: 11 characters.
            Constraint::Length(11),
            // Comment: whatever space is left.
            Constraint::Fill(1),
            // Private and Agent: fixed widths.
            Constraint::Length(11),
            Constraint::Length(9),
        ],
    )
    // Builder-style chained calls, like a Java builder.
    .header(header)
    // `title.clone()` because `title` is used again below; without the clone the
    // String would be moved here and unusable later (compile error "use of moved value").
    .block(Block::bordered().title(title.clone()))
    // Selected row is drawn with inverted colours.
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
    // Arrow in front of the selected row.
    .highlight_symbol("▶ ");

    if app.keys.is_empty() {
        // No keys: show a hint instead of an empty table.
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from("  No *.pub keys found."),
            Line::from("  Press n to generate a new ed25519 key."),
        ])
        // `title` is moved here (last use), so no clone needed.
        .block(Block::bordered().title(title));
        f.render_widget(msg, area);
    } else {
        // A "stateful" widget also needs the selection state (which row is highlighted).
        f.render_stateful_widget(table, area, &mut app.table);
    }
}

/// One "Label       value" line for the details panel.
///
/// `value: impl Into<String>` accepts anything convertible to a String
/// (a &str or a String), similar to a generic parameter with a bound.
/// `Line<'static>` means the Line owns all its text (it borrows nothing).
fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        // `{label:<12}` pads the label to 12 characters, left-aligned (like %-12s).
        Span::styled(format!("{label:<12}"), Style::new().fg(Color::Cyan)),
        Span::raw(value.into()),
    ])
}

/// All the lines of the details panel for one key.
fn detail_lines(k: &KeyInfo) -> Vec<Line<'static>> {
    // Start with the simple fields.
    let mut lines = vec![
        kv("Fingerprint", k.fingerprint.clone()),
        kv("Type", k.key_type.clone()),
        kv(
            "Comment",
            // Show "(none)" for an empty comment.
            if k.comment.is_empty() {
                "(none)".into()
            } else {
                k.comment.clone()
            },
        ),
        kv("Public", k.pub_path.display().to_string()),
    ];

    // Private key line, depending on whether it exists.
    match &k.priv_path {
        Some(p) => {
            // e.g. "  mode 600". `{m:03o}` prints m in octal, padded to 3 digits.
            let mode = k
                .priv_mode
                .map(|m| format!("  mode {m:03o}"))
                .unwrap_or_default();
            lines.push(kv("Private", format!("{}{mode}", p.display())));
            // Red warning if the permissions are too open.
            if k.perms_too_open() {
                lines.push(Line::from(
                    format!(
                        "            ⚠ too open, ssh will refuse it: chmod 600 {}",
                        p.display()
                    )
                    .red(),
                ));
            }
        }
        None => lines.push(kv("Private", "not in this folder (public key only)")),
    }

    // Passphrase line, coloured yellow (none) or green (has one).
    let prot = Line::from(vec![
        Span::styled(
            format!("{:<12}", "Passphrase"),
            Style::new().fg(Color::Cyan),
        ),
        // A `match` used as a value inside the vec.
        match &k.protection {
            Protection::Unencrypted => Span::raw(k.protection.label()).yellow(),
            Protection::Encrypted(_) => Span::raw(k.protection.label()).green(),
            _ => Span::raw(k.protection.label()),
        },
    ]);
    lines.push(prot);
    // Rust has no `?:` ternary; `if a { x } else { y }` does the same job.
    lines.push(kv("In agent", if k.in_agent { "yes" } else { "no" }));

    // Blank line, then the "Used by" section.
    lines.push(Line::from(""));
    lines.push(Line::from("Used by".cyan().bold()));
    if k.usages.is_empty() {
        lines.push(Line::from(
            "  nothing in ~/.ssh/config or authorized_keys".dark_gray(),
        ));
    } else {
        // `&k.usages` loops over borrowed items (no copying).
        for u in &k.usages {
            lines.push(Line::from(format!("  {}  {}", u.source, u.detail)));
        }
    }
    // Return the finished list.
    lines
}

/// The details panel under the table.
fn draw_details(f: &mut Frame, area: Rect, app: &App) {
    // A box with a border and a title.
    let block = Block::bordered().title(" Details ");
    // Lines for the selected key, or a hint if nothing is selected.
    let content = match app.selected() {
        Some(k) => detail_lines(k),
        None => vec![Line::from("Select a key".dark_gray())],
    };
    f.render_widget(
        Paragraph::new(content)
            .block(block)
            // Wrap long lines instead of cutting them off.
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Bottom 2 lines: status message and keyboard shortcuts.
fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    // Shortcut "buttons": key in black on grey, then its description.
    let keys = Line::from(vec![
        " ↑↓ ".black().on_gray(),
        " move  ".into(),
        " v ".black().on_gray(),
        " view  ".into(),
        " c ".black().on_gray(),
        " copy  ".into(),
        " n ".black().on_gray(),
        " new key  ".into(),
        " a ".black().on_gray(),
        " add to agent  ".into(),
        " s ".black().on_gray(),
        " to server  ".into(),
        " d ".black().on_gray(),
        " remove from agent  ".into(),
        " r ".black().on_gray(),
        " refresh  ".into(),
        " ? ".black().on_gray(),
        " help  ".into(),
        " q ".black().on_gray(),
        " quit".into(),
    ]);
    // The status message in yellow.
    let status = Line::from(format!(" {}", app.status)).yellow();
    // Two lines: status first, shortcuts second.
    f.render_widget(Paragraph::new(vec![status, keys]), area);
}

/// A centered rectangle `pct_x`% wide and `height` rows tall.
fn popup_area(area: Rect, pct_x: u16, height: u16) -> Rect {
    // Vertically: flexible space, the popup, flexible space -> centred.
    // `_` discards the top and bottom areas. `height.min(...)` caps it at the screen height.
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height.min(area.height)),
        Constraint::Fill(1),
    ])
    .areas(area);
    // Horizontally: equal margins left and right.
    let [_, center, _] = Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .areas(mid);
    center
}

/// Popup showing the full public key line.
fn draw_view_key(f: &mut Frame, app: &App) {
    // Nothing selected: draw nothing.
    let Some(k) = app.selected() else { return };
    let area = popup_area(f.area(), 80, 12);
    // `Clear` erases whatever was drawn underneath, so the popup isn't see-through.
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(k.public_line()),
        Line::from(""),
        Line::from("c copy to clipboard · any other key closes".dark_gray()),
    ];
    // Paragraph inside a cyan-bordered box titled with the file name.
    let p = Paragraph::new(text).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title(format!(" {}.pub ", k.name))
            .border_style(Style::new().cyan()),
    );
    f.render_widget(p, area);
}

/// Help popup listing all shortcuts.
fn draw_help(f: &mut Frame) {
    let area = popup_area(f.area(), 70, 18);
    f.render_widget(Clear, area);
    // An array of (key, description) tuples.
    let rows = [
        ("↑ ↓ / j k", "Move selection"),
        ("Enter / v", "Show full public key"),
        ("c", "Copy public key to clipboard (pbcopy)"),
        (
            "n",
            "Generate a new ed25519 key (ssh-keygen asks for passphrase)",
        ),
        ("a", "Add key to ssh-agent + macOS Keychain"),
        ("d", "Remove key from ssh-agent (files are not touched)"),
        ("s", "Copy key to a server's authorized_keys (ssh-copy-id)"),
        ("r", "Rescan ~/.ssh and the agent"),
        ("q / Esc", "Quit"),
    ];
    // Turn each tuple into a Line. `|(k, d)|` destructures the tuple in the closure parameter.
    // `*d` copies the &str out of the reference the iterator gives us.
    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(format!("  {k:<12}"), Style::new().cyan()),
                Span::raw(*d),
            ])
        })
        .collect();
    // Insert an extra row at position 3 (0-based) for Ctrl+U.
    lines.insert(
        3,
        Line::from(vec![
            Span::styled(format!("  {:<12}", "Ctrl+U"), Style::new().cyan()),
            Span::raw("Clear field (in the new-key form)"),
        ]),
    );
    // Safety notes at the bottom.
    lines.push(Line::from(""));
    lines.push(Line::from(
        "  Private keys are never displayed, copied or moved.".dark_gray(),
    ));
    lines.push(Line::from(
        "  Passphrases are typed straight into ssh-keygen / ssh-add.".dark_gray(),
    ));
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Help ")
                .border_style(Style::new().cyan()),
        ),
        area,
    );
}

/// "New ed25519 key" form popup.
fn draw_generate(f: &mut Frame, app: &App) {
    // Get the form out of the current mode (read-only borrow).
    let Mode::Generate(form) = &app.mode else {
        return;
    };
    let area = popup_area(f.area(), 70, 11);
    f.render_widget(Clear, area);

    // A closure that draws one input field. Defined inside the function because
    // only this function uses it.
    let field = |label: &str, value: &str, focused: bool| {
        // Highlight the field being edited.
        let style = if focused {
            Style::new().black().on_cyan()
        } else {
            Style::new()
        };
        // A block character as a fake cursor.
        let cursor = if focused { "█" } else { "" };
        Line::from(vec![
            Span::styled(format!("  {label:<10}"), Style::new().cyan()),
            Span::styled(format!(" {value}{cursor} "), style),
        ])
    };

    let mut lines = vec![
        Line::from(""),
        // Field 0: filename.
        field("Filename", &form.filename, form.focus == 0),
        // Grey preview of the full path that will be created.
        Line::from(
            format!(
                "  {:<10} {}",
                "",
                app.ssh_dir.join(form.filename.trim()).display()
            )
            .dark_gray(),
        ),
        // Field 1: comment.
        field("Comment", &form.comment, form.focus == 1),
        Line::from(""),
    ];
    // Bottom line: the error in red, or the key hints in grey.
    match &form.error {
        Some(e) => lines.push(Line::from(format!("  {e}")).red()),
        None => lines.push(Line::from(
            "  Enter create · Tab switch · Ctrl+U clear · Esc cancel".dark_gray(),
        )),
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(" New ed25519 key ")
                .border_style(Style::new().cyan()),
        ),
        area,
    );
}

/// "Copy key to a server" form popup.
fn draw_copy_to_server(f: &mut Frame, app: &App) {
    let Mode::CopyToServer(form) = &app.mode else {
        return;
    };
    // Need the selected key for the title.
    let Some(k) = app.selected() else { return };
    let area = popup_area(f.area(), 76, 14);
    f.render_widget(Clear, area);

    // Start with a blank line, then add each field below.
    let mut lines = vec![Line::from("")];
    // Loop over the 3 labels with their index i (0, 1, 2).
    for (i, label) in ServerForm::LABELS.iter().enumerate() {
        // Is this the field being edited?
        let focused = form.focus == i;
        let style = if focused {
            Style::new().black().on_cyan()
        } else {
            Style::new()
        };
        let cursor = if focused { "█" } else { "" };
        // The label and the current text of the field.
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<9}"), Style::new().cyan()),
            Span::styled(format!(" {}{cursor} ", form.fields[i]), style),
        ]));
        // A grey hint under the field.
        lines.push(Line::from(
            format!("  {:<9} {}", "", ServerForm::HINTS[i]).dark_gray(),
        ));
    }
    lines.push(Line::from(""));
    // Error in red, or key hints in grey.
    match &form.error {
        Some(e) => lines.push(Line::from(format!("  {e}")).red()),
        None => lines.push(Line::from(
            "  Enter run ssh-copy-id · Tab next field · Ctrl+U clear · Esc cancel".dark_gray(),
        )),
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(format!(" Copy {}.pub to a server ", k.name))
                .border_style(Style::new().cyan()),
        ),
        area,
    );
}
