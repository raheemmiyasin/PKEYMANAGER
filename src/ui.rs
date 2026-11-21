//! Drawing. Every frame is redrawn from `App` state (immediate-mode UI, a bit
//! like a React render function: state in, widgets out).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::app::{App, Mode, ServerForm};
use crate::keys::{KeyInfo, Protection};

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(f.area());

    draw_header(f, header, app);

    let [table_area, detail_area] =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);
    draw_table(f, table_area, app);
    draw_details(f, detail_area, app);
    draw_footer(f, footer, app);

    match &app.mode {
        Mode::Normal => {}
        Mode::ViewKey => draw_view_key(f, app),
        Mode::Help => draw_help(f),
        Mode::Generate(_) => draw_generate(f, app),
        Mode::CopyToServer(_) => draw_copy_to_server(f, app),
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        " PKEY MANAGER ".black().on_cyan().bold(),
        format!("  {}  ", app.ssh_dir.display()).into(),
        app.agent_note.clone().dark_gray(),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(["Name", "Type", "Comment", "Private", "Agent"])
        .style(Style::new().bold().fg(Color::Cyan));

    let rows: Vec<Row> = app
        .keys
        .iter()
        .map(|k| {
            let private = match &k.protection {
                Protection::NoPrivateKey => Cell::from("—").dark_gray(),
                Protection::Encrypted(_) => Cell::from("🔒 yes").green(),
                Protection::Unencrypted => Cell::from("⚠ no pass").yellow(),
                Protection::Unknown => Cell::from("? yes").gray(),
            };
            let agent = if k.in_agent {
                Cell::from("● loaded").green()
            } else {
                Cell::from("—").dark_gray()
            };
            Row::new(vec![
                Cell::from(k.name.clone()),
                Cell::from(k.short_type()),
                Cell::from(k.comment.clone()),
                private,
                agent,
            ])
        })
        .collect();

    let title = format!(" Keys ({}) ", app.keys.len());
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Length(11),
            Constraint::Fill(1),
            Constraint::Length(11),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .block(Block::bordered().title(title.clone()))
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
    .highlight_symbol("▶ ");

    if app.keys.is_empty() {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from("  No *.pub keys found."),
            Line::from("  Press n to generate a new ed25519 key."),
        ])
        .block(Block::bordered().title(title));
        f.render_widget(msg, area);
    } else {
        f.render_stateful_widget(table, area, &mut app.table);
    }
}

fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::new().fg(Color::Cyan)),
        Span::raw(value.into()),
    ])
}

fn detail_lines(k: &KeyInfo) -> Vec<Line<'static>> {
    let mut lines = vec![
        kv("Fingerprint", k.fingerprint.clone()),
        kv("Type", k.key_type.clone()),
        kv(
            "Comment",
            if k.comment.is_empty() {
                "(none)".into()
            } else {
                k.comment.clone()
            },
        ),
        kv("Public", k.pub_path.display().to_string()),
    ];

    match &k.priv_path {
        Some(p) => {
            let mode = k
                .priv_mode
                .map(|m| format!("  mode {m:03o}"))
                .unwrap_or_default();
            lines.push(kv("Private", format!("{}{mode}", p.display())));
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

    let prot = Line::from(vec![
        Span::styled(
            format!("{:<12}", "Passphrase"),
            Style::new().fg(Color::Cyan),
        ),
        match &k.protection {
            Protection::Unencrypted => Span::raw(k.protection.label()).yellow(),
            Protection::Encrypted(_) => Span::raw(k.protection.label()).green(),
            _ => Span::raw(k.protection.label()),
        },
    ]);
    lines.push(prot);
    lines.push(kv("In agent", if k.in_agent { "yes" } else { "no" }));

    lines.push(Line::from(""));
    lines.push(Line::from("Used by".cyan().bold()));
    if k.usages.is_empty() {
        lines.push(Line::from(
            "  nothing in ~/.ssh/config or authorized_keys".dark_gray(),
        ));
    } else {
        for u in &k.usages {
            lines.push(Line::from(format!("  {}  {}", u.source, u.detail)));
        }
    }
    lines
}

fn draw_details(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" Details ");
    let content = match app.selected() {
        Some(k) => detail_lines(k),
        None => vec![Line::from("Select a key".dark_gray())],
    };
    f.render_widget(
        Paragraph::new(content)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
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
    let status = Line::from(format!(" {}", app.status)).yellow();
    f.render_widget(Paragraph::new(vec![status, keys]), area);
}

/// A centered rectangle `pct_x`% wide and `height` rows tall.
fn popup_area(area: Rect, pct_x: u16, height: u16) -> Rect {
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height.min(area.height)),
        Constraint::Fill(1),
    ])
    .areas(area);
    let [_, center, _] = Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .areas(mid);
    center
}

fn draw_view_key(f: &mut Frame, app: &App) {
    let Some(k) = app.selected() else { return };
    let area = popup_area(f.area(), 80, 12);
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(k.public_line()),
        Line::from(""),
        Line::from("c copy to clipboard · any other key closes".dark_gray()),
    ];
    let p = Paragraph::new(text).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title(format!(" {}.pub ", k.name))
            .border_style(Style::new().cyan()),
    );
    f.render_widget(p, area);
}

fn draw_help(f: &mut Frame) {
    let area = popup_area(f.area(), 70, 18);
    f.render_widget(Clear, area);
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
    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(format!("  {k:<12}"), Style::new().cyan()),
                Span::raw(*d),
            ])
        })
        .collect();
    lines.insert(
        3,
        Line::from(vec![
            Span::styled(format!("  {:<12}", "Ctrl+U"), Style::new().cyan()),
            Span::raw("Clear field (in the new-key form)"),
        ]),
    );
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

fn draw_generate(f: &mut Frame, app: &App) {
    let Mode::Generate(form) = &app.mode else {
        return;
    };
    let area = popup_area(f.area(), 70, 11);
    f.render_widget(Clear, area);

    let field = |label: &str, value: &str, focused: bool| {
        let style = if focused {
            Style::new().black().on_cyan()
        } else {
            Style::new()
        };
        let cursor = if focused { "█" } else { "" };
        Line::from(vec![
            Span::styled(format!("  {label:<10}"), Style::new().cyan()),
            Span::styled(format!(" {value}{cursor} "), style),
        ])
    };

    let mut lines = vec![
        Line::from(""),
        field("Filename", &form.filename, form.focus == 0),
        Line::from(
            format!(
                "  {:<10} {}",
                "",
                app.ssh_dir.join(form.filename.trim()).display()
            )
            .dark_gray(),
        ),
        field("Comment", &form.comment, form.focus == 1),
        Line::from(""),
    ];
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

fn draw_copy_to_server(f: &mut Frame, app: &App) {
    let Mode::CopyToServer(form) = &app.mode else {
        return;
    };
    let Some(k) = app.selected() else { return };
    let area = popup_area(f.area(), 76, 14);
    f.render_widget(Clear, area);

    let mut lines = vec![Line::from("")];
    for (i, label) in ServerForm::LABELS.iter().enumerate() {
        let focused = form.focus == i;
        let style = if focused {
            Style::new().black().on_cyan()
        } else {
            Style::new()
        };
        let cursor = if focused { "█" } else { "" };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<9}"), Style::new().cyan()),
            Span::styled(format!(" {}{cursor} ", form.fields[i]), style),
        ]));
        lines.push(Line::from(
            format!("  {:<9} {}", "", ServerForm::HINTS[i]).dark_gray(),
        ));
    }
    lines.push(Line::from(""));
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
