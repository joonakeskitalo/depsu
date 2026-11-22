use crate::tui::app::{App, VersionRange, Row as AppRow, ScanStatus, Status, scan_key};
use crate::deps::overrides::{self, Compat, Override};
use crate::deps::package::Kind;
use crate::config::pm::Pm;
use crate::deps::tree::{self, Hit};
use crate::tui::view::{Child, GroupBy, Item, Overrides, Release, UNNEEDED};
use crate::security::vuln::{Severity, Source};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph};

fn log_line(l: &str) -> Line<'static> {
    let color = match l.chars().next() {
        Some('✘') | Some('!') => Color::Red,
        Some('⚠') => Color::Yellow,
        Some('✔') => Color::Green,
        _ => Color::Gray,
    };
    Line::from(Span::styled(l.to_string(), Style::new().fg(color)))
}
/// Columns the section content is indented relative to the section titles.
const PAD: u16 = 2;
fn pad(r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let d = PAD.min(r.width);
    ratatui::layout::Rect {
        x: r.x + d,
        width: r.width - d,
        ..r
    }
}
/// Width left for content once the indentation is taken off.
fn inner_width(f: &Frame) -> u16 {
    f.area().width.saturating_sub(PAD)
}

/// A two-line section heading: a horizontal rule, and below it the title of what follows.
fn heading(f: &mut Frame, area: ratatui::layout::Rect, title: impl Into<String>) {
    let [line, text] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    f.render_widget(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::new().fg(Color::DarkGray)),
        line,
    );
    f.render_widget(
        Line::from(Span::styled(
            format!(" {}", title.into()),
            Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        )),
        text,
    );
}
/// Where the keys go: that part of the screen gets a bright border.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    /// The package list.
    List,
    /// A prompt typed in the footer: the filter, a version, the pin type.
    Footer,
    /// A dialog in the middle of the screen.
    Dialog,
    /// The expanded log.
    Log,
}

pub fn focus(app: &App) -> Focus {
    let add_dialog = matches!(
        &app.input,
        Some(i) if matches!(i.purpose, crate::tui::app::InputPurpose::Add { .. })
    );
    if app.peer_prompt.is_some()
        || app.version_edit.is_some()
        || app.peer_fix.is_some()
        || app.delete_prompt.is_some()
        || app.blocked_prompt.is_some()
        || app.commit_prompt.is_some()
        || add_dialog
    {
        Focus::Dialog
    } else if app.log_focus {
        Focus::Log
    } else if app.filter_mode || app.pin_prompt || app.input.is_some() {
        Focus::Footer
    } else {
        Focus::List
    }
}

/// A part of the screen in a box with `title`: bright when it has the keys, grey otherwise.
/// Returns the area inside, with a column of padding on each side.
fn panel(f: &mut Frame, area: Rect, title: impl Into<String>, active: bool) -> Rect {
    let (border, title_style) = if active {
        (
            Style::new().fg(Color::Cyan),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            Style::new().fg(Color::DarkGray),
            Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        )
    };
    let title = title.into();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if active { BorderType::Rounded } else { BorderType::Plain })
        .border_style(border)
        .title(if title.is_empty() {
            Line::default()
        } else {
            Line::from(Span::styled(format!(" {title} "), title_style))
        })
        .padding(ratatui::widgets::Padding::horizontal(1));
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

/// Width inside a panel: the borders and padding take two columns each side.
fn panel_width(f: &Frame) -> u16 {
    f.area().width.saturating_sub(4)
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let log_h = (app.log.len() as u16).clamp(1, 5);
    app.targets = Default::default();
    let focus = focus(app);
    let footer_boxed = focus == Focus::Footer;
    let (footer, footer_hits) = footer_lines(
        app,
        if footer_boxed { panel_width(f) } else { inner_width(f) },
    );
    let (header_lines, header_hits) = header_lines(app, f.area().width);
    // The details panel makes room for the expanded log.
    let info = app.show_info && !app.log_focus;
    let used_by_lines = if info {
        let mut lines = used_by_lines(app, inner_width(f));
        lines.extend(peer_lines(app, inner_width(f)));
        lines
    } else {
        Vec::new()
    };
    let summary_h = if info {
        SUMMARY_LINES
    } else {
        0
    };
    // The package list and a footer prompt are boxed; the border and the title take the rows
    // the heading took.
    let footer_h = footer.len() as u16 + if footer_boxed { 2 } else { 1 };
    // The log is boxed like the list. Expanded, it takes 7/8 of the room, and the list keeps
    // the rest so both can be clicked.
    let collapsed_h = log_h + 2;
    let log_box_h = if app.log_focus {
        let room = f.area().height.saturating_sub(header_lines.len() as u16 + footer_h);
        (room * 7 / 8).clamp(collapsed_h, room.saturating_sub(7).max(collapsed_h))
    } else {
        collapsed_h
    };
    let [header, list_area, info_rule, used_by, summary, log_area, keys_area] =
        Layout::vertical([
            Constraint::Length(header_lines.len() as u16),
            Constraint::Min(5),
            Constraint::Length(if info { 2 } else { 0 }),
            Constraint::Length(if info { used_by_lines.len().max(1) as u16 } else { 0 }),
            Constraint::Length(summary_h),
            Constraint::Length(log_box_h),
            Constraint::Length(footer_h),
        ])
        .areas(f.area());
    let (used_by, summary) = (pad(used_by), pad(summary));
    f.render_widget(Paragraph::new(header_lines), header);
    // Part of the screen outside the list reacts to the mouse only while the list has the keys:
    // the keys a click stands for would go to a prompt otherwise.
    let clickable = focus == Focus::List;
    if clickable {
        add_targets(header, header_hits, &mut app.targets.keys);
        let full = f.area().width;
        if info {
            let r = Rect { width: full, ..info_rule };
            app.targets.keys.push((r, vec![plain(KeyCode::Char('?'))]));
        }
        // The log: a click opens it.
        app.targets.keys.push((log_area, vec![plain(KeyCode::Tab)]));
    }
    app.targets.list_panel = list_area;
    let body = panel(f, list_area, "packages", focus == Focus::List);

    let grouped = app.group_by != GroupBy::None;
    let indent = if grouped { 2 } else { 0 };
    let name_w = app
        .rows
        .iter()
        .map(|r| r.name.chars().count() + indent)
        .max()
        .unwrap_or(0)
        .clamp(16, 48);

    let items: Vec<ListItem> = app
        .view
        .iter()
        .map(|item| match item {
            Item::Header { label, members } => ListItem::new(header_line(app, label, members)),
            Item::Row { idx, .. } => ListItem::new(row_line(app, &app.rows[*idx], indent, name_w, body.width as usize)),
            Item::Removed { name } => ListItem::new(removed_line(app, name)),
            Item::Override { key } => {
                ListItem::new(Text::from(orphan_lines(app, key, body.width as usize)))
            }
            Item::Detail {
                idx, child, last, ..
            } => ListItem::new(Text::from(detail_lines(
                app,
                &app.rows[*idx],
                *child,
                *last,
                indent,
                body.width as usize,
            ))),
        })
        .collect();
    let heights: Vec<u16> = items.iter().map(|i| i.height() as u16).collect();
    let list = List::new(items)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    app.list_page = body.height as usize;
    f.render_stateful_widget(list, body, &mut app.table);
    // Which item each row of the list shows, for the mouse.
    app.targets.list = body;
    let mut top = 0u16;
    for (i, h) in heights.iter().enumerate().skip(app.table.offset()) {
        if top >= body.height {
            break;
        }
        app.targets.items.push((top, *h, i));
        top += h;
    }
    let info_title = match app.cursor_item() {
        Some(Item::Row { idx, .. }) => format!("selected: {}", app.rows[*idx].name),
        Some(Item::Removed { name }) => format!("selected: {name}"),
        _ => "selected".to_string(),
    };
    if info {
        heading(f, info_rule, info_title);
        f.render_widget(Paragraph::new(used_by_lines), used_by);
    }
    if summary_h > 0 {
        f.render_widget(
            Paragraph::new(summary_lines(app, summary.width as usize)),
            summary,
        );
    }

    let title = if app.log_focus && app.log_scroll > 0 {
        format!("log (↑{} older)", app.log_scroll)
    } else {
        "log".to_string()
    };
    let log_body = panel(f, log_area, title, focus == Focus::Log);
    let h = (log_body.height as usize).max(1);
    app.log_page = h;
    if app.log_focus {
        app.log_scroll = app.log_scroll.min(app.log.len().saturating_sub(h));
    }
    let scroll = if app.log_focus { app.log_scroll } else { 0 };
    let end = app.log.len() - scroll;
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = app.log[start..end].iter().map(|l| log_line(l)).collect();
    f.render_widget(Paragraph::new(lines), log_body);
    if footer_boxed {
        let inner = panel(f, keys_area, "", true);
        add_targets(inner, footer_hits, &mut app.targets.keys);
        f.render_widget(Paragraph::new(footer), inner);
    } else {
        let [rule, help] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(keys_area);
        f.render_widget(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::new().fg(Color::DarkGray)),
            rule,
        );
        add_targets(pad(help), footer_hits, &mut app.targets.keys);
        f.render_widget(Paragraph::new(footer), pad(help));
    }
    // A dialog has the keys: what's behind it is dimmed, so only the dialog stands out.
    if focus == Focus::Dialog {
        let area = f.area();
        f.buffer_mut().set_style(area, Style::new().add_modifier(Modifier::DIM));
    }
    if let Some(p) = &app.peer_prompt {
        draw_peer_prompt(f, p);
    }
    if let Some(p) = &app.peer_fix {
        draw_peer_fix(f, p, &mut app.targets.keys);
    }
    if let Some(p) = &app.delete_prompt {
        draw_delete_prompt(f, app, p);
    }
    if let Some(p) = &app.blocked_prompt {
        draw_blocked_prompt(f, p);
    }
    if let Some(p) = &app.commit_prompt {
        draw_commit_dialog(f, p);
    }
    if let Some(e) = &app.version_edit {
        draw_version_edit(f, app, e);
    }
    if let Some(input) = &app.input
        && let crate::tui::app::InputPurpose::Add { add_as } = &input.purpose
    {
        let clicks = draw_add_dialog(f, app, input, *add_as);
        app.targets.keys.extend(clicks);
    }
}

/// The lines of `field` as spans, with the cursor shown when `active`: the character under
/// it reversed, or a block at the end of a line.
fn field_lines(field: &crate::tui::textfield::TextField, active: bool, style: Style) -> Vec<Vec<Span<'static>>> {
    let (text, cursor) = (field.text(), field.cursor());
    let mut out = Vec::new();
    let mut start = 0;
    for line in text.split('\n') {
        let end = start + line.len();
        let mut spans = Vec::new();
        if active && (start..=end).contains(&cursor) {
            let (before, rest) = line.split_at(cursor - start);
            if !before.is_empty() {
                spans.push(Span::styled(before.to_string(), style));
            }
            match rest.chars().next() {
                Some(c) => {
                    spans.push(Span::styled(c.to_string(), style.add_modifier(Modifier::REVERSED)));
                    let after = &rest[c.len_utf8()..];
                    if !after.is_empty() {
                        spans.push(Span::styled(after.to_string(), style));
                    }
                }
                None => spans.push(Span::styled("█", Style::new().fg(Color::Cyan))),
            }
        } else if !line.is_empty() {
            spans.push(Span::styled(line.to_string(), style));
        }
        out.push(spans);
        start = end + 1;
    }
    out
}

/// The version of a package being edited (`e`): what it has now, the version as typed, and
/// whether that version is published.
fn draw_version_edit(f: &mut Frame, app: &App, e: &crate::tui::app::VersionEdit) {
    use crate::tui::app::VersionCheck;
    let width = f.area().width.saturating_sub(4).min(80);
    let inner = (width as usize).saturating_sub(4);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);
    let label = |t: &str| Span::styled(format!("{t:<14}"), bold);
    let indent = || Span::raw(" ".repeat(14));
    let row = app.rows.iter().find(|r| r.name == e.name);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(r) = row {
        lines.push(Line::from(vec![label("package.json"), Span::raw(format!("{}{}", r.prefix, r.current))]));
        lines.push(Line::from(vec![
            label("installed"),
            match &r.installed {
                Some(v) => Span::raw(v.to_string()),
                None => Span::styled("not installed", dim),
            },
        ]));
        lines.push(Line::from(vec![
            label("latest"),
            if r.loading {
                Span::styled("checking…", dim)
            } else {
                Span::raw(r.latest.to_string())
            },
        ]));
        lines.push(Line::default());
    }
    let typed = field_lines(&e.field, true, bold).into_iter().next().unwrap_or_default();
    lines.extend(wrap(
        Span::styled(format!("{:<14}", "Version"), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        indent(),
        typed,
        inner,
    ));
    lines.extend(wrap(
        indent(),
        indent(),
        vec![Span::styled("^ minor and patch · ~ patch only · >= anything newer · none: exact", dim)],
        inner,
    ));
    let (text, style) = match e.check() {
        VersionCheck::NotAVersion => ("✘ not a version like 1.2.3".to_string(), Style::new().fg(Color::Red)),
        VersionCheck::LookingUp => ("looking up the published versions…".to_string(), dim),
        VersionCheck::LookupFailed(err) => (format!("✘ could not look up {}: {err}", e.name), Style::new().fg(Color::Red)),
        VersionCheck::NotPublished(msg) => (format!("✘ {msg}"), Style::new().fg(Color::Red)),
        VersionCheck::Published { prefix, version } => {
            let now = row.is_some_and(|r| {
                r.installed.as_ref().unwrap_or(&r.current) == &version && r.current == version
            });
            let same_pin = row.is_some_and(|r| r.prefix == prefix);
            let note = match (now, same_pin) {
                (true, true) => format!(", and is what {} has now", e.name),
                (true, false) => ", only the pin type changes".to_string(),
                _ => String::new(),
            };
            (format!("✔ {version} is published{note}"), Style::new().fg(Color::Green))
        }
    };
    lines.extend(wrap(indent(), indent(), vec![Span::styled(text, style)], inner));
    lines.push(Line::default());
    if let Some(err) = &e.error {
        lines.extend(wrap(
            Span::raw(""),
            Span::raw("  "),
            vec![Span::styled(err.clone(), Style::new().fg(Color::Red))],
            inner,
        ));
        lines.push(Line::default());
    }
    let key = |k: &str, t: &str| {
        vec![
            Span::styled(k.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {t}   ")),
        ]
    };
    let mut keys = key("enter", "install");
    keys.extend(key("esc", "cancel"));
    lines.push(Line::from(keys));
    draw_dialog(f, &format!("Version of {}", e.name), lines, width);
}

/// The commit `c` proposes: its title and body to edit, and which files.
fn draw_commit_dialog(f: &mut Frame, p: &crate::tui::app::CommitPrompt) {
    use crate::tui::app::CommitField;
    let width = f.area().width.saturating_sub(4).min(90);
    let inner = (width as usize).saturating_sub(4);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);
    let cyan_bold = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let indent = || Span::raw("       ");
    // The field that takes the keys has its label in cyan and shows the cursor.
    let label = |t: &str, focused: bool| {
        Span::styled(format!("{t:<7}"), if focused { cyan_bold } else { bold })
    };
    let title_focused = p.field == CommitField::Title && !p.busy;
    let body_focused = p.field == CommitField::Body && !p.busy;
    let mut lines: Vec<Line<'static>> = Vec::new();

    let title = field_lines(&p.title, title_focused, bold).into_iter().next().unwrap_or_default();
    lines.extend(wrap(label("Title", title_focused), indent(), title, inner));
    let n = p.title.text().trim().chars().count();
    lines.push(Line::from(vec![
        indent(),
        Span::styled(
            format!("a conventional commit, edit as you like ({n} characters)"),
            if n > 72 { Style::new().fg(Color::Yellow) } else { dim },
        ),
    ]));
    lines.push(Line::default());

    // The body, as it will be committed. Until it is edited it leaves out what the title says.
    if p.body.text().is_empty() {
        let why = if p.body_edited {
            "(empty: the commit gets no body)"
        } else if p.plan.body.is_empty() {
            "(none: no dependency changes found, only other edits to these files)"
        } else {
            "(none: the title says it all)"
        };
        let mut spans = vec![label("Body", body_focused)];
        if body_focused {
            spans.push(Span::styled("█ ", Style::new().fg(Color::Cyan)));
        }
        spans.push(Span::styled(why, dim));
        lines.push(Line::from(spans));
    } else {
        let body = field_lines(&p.body, body_focused, Style::new());
        // Long bodies show a window of lines around the cursor.
        let room = (f.area().height as usize).saturating_sub(20).max(3);
        let total = body.len();
        let start = if total > room {
            p.body.cursor_line().saturating_sub(room - 1).min(total - room)
        } else {
            0
        };
        let mut first = true;
        let mut lead = |lines: &mut Vec<Line<'static>>, rest: Vec<Span<'static>>| {
            let head = if first { label("Body", body_focused) } else { indent() };
            first = false;
            if rest.is_empty() {
                lines.push(Line::from(head));
            } else {
                lines.extend(wrap(head, indent(), rest, inner));
            }
        };
        if start > 0 {
            lead(&mut lines, vec![Span::styled(format!("… {start} lines above"), dim)]);
        }
        for l in body.into_iter().skip(start).take(room) {
            lead(&mut lines, l);
        }
        if start + room < total {
            lead(
                &mut lines,
                vec![Span::styled(format!("… {} more lines", total - start - room), dim)],
            );
        }
    }
    lines.push(Line::default());
    lines.extend(wrap(
        Span::styled("Files  ", bold),
        indent(),
        vec![
            Span::raw(p.plan.files.join(", ")),
            Span::styled(format!("   on {}", p.plan.branch), dim),
        ],
        inner,
    ));
    if !p.plan.other_staged.is_empty() {
        lines.extend(wrap(
            indent(),
            indent(),
            vec![Span::styled(
                format!(
                    "Also staged, left out of this commit: {}",
                    p.plan.other_staged.join(", ")
                ),
                Style::new().fg(Color::Yellow),
            )],
            inner,
        ));
    }
    lines.push(Line::default());
    if let Some(e) = p.error.as_ref().filter(|_| !p.busy) {
        for l in e.lines() {
            lines.extend(wrap(
                Span::raw(""),
                Span::raw("  "),
                vec![Span::styled(l.to_string(), Style::new().fg(Color::Red))],
                inner,
            ));
        }
        lines.push(Line::default());
    }
    let key = |k: &str, t: &str| {
        vec![
            Span::styled(k.to_string(), cyan_bold),
            Span::raw(format!(" {t}   ")),
        ]
    };
    // While git runs, the status takes the keys' place, so the dialog keeps its size.
    if p.busy {
        lines.push(Line::from(Span::styled("Committing… (git hooks may take a while)", dim)));
    } else {
        let mut keys = Vec::new();
        match p.field {
            CommitField::Title => {
                keys.extend(key("enter", "commit"));
                keys.extend(key("tab", "body"));
            }
            CommitField::Body => {
                keys.extend(key("ctrl+s", "commit"));
                keys.extend(key("enter", "new line"));
                keys.extend(key("tab", "title"));
            }
        }
        keys.extend(key("esc", "cancel"));
        lines.push(Line::from(keys));
    }
    draw_dialog(f, "Commit to git", lines, width);
}

/// Versions the registry refuses to hand out, and what it hands out instead.
fn draw_blocked_prompt(f: &mut Frame, p: &crate::tui::app::BlockedPrompt) {
    let width = f.area().width.saturating_sub(4).min(84);
    let inner = (width as usize).saturating_sub(4);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);
    let key = |k: &str| Span::styled(format!("{k:<3}"), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let mut lines: Vec<Line<'static>> = Vec::new();
    for b in &p.blocked {
        lines.extend(wrap(
            Span::styled("✘ ", Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("   "),
            vec![
                Span::styled(format!("{} {}", b.name, b.version), bold),
                Span::raw(" can't be downloaded: the registry refuses it (403 Forbidden)."),
            ],
            inner,
        ));
        lines.extend(wrap(
            Span::raw("   "),
            Span::raw("   "),
            match &b.alternative {
                Some(a) => vec![
                    Span::raw("The newest version it hands out is "),
                    Span::styled(a.to_string(), Style::new().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::raw("."),
                ],
                None => vec![Span::styled(
                    "No older version could be downloaded either.",
                    Style::new().fg(Color::Yellow),
                )],
            },
            inner,
        ));
    }
    lines.push(Line::default());
    let found: Vec<&crate::registry::blocked::Blocked> =
        p.blocked.iter().filter(|b| b.alternative.is_some()).collect();
    if !found.is_empty() {
        let what: Vec<String> = found
            .iter()
            .map(|b| {
                let alt = b.alternative.as_ref().unwrap();
                if p.after_failure && !b.direct {
                    format!("override {} to {alt}", b.name)
                } else {
                    format!("install {} {alt} instead", b.name)
                }
            })
            .collect();
        lines.extend(wrap(key("y"), Span::raw("   "), vec![Span::raw(what.join(", "))], inner));
        let b = found[0];
        lines.extend(wrap(
            Span::raw("   "),
            Span::raw("   "),
            vec![Span::styled(
                format!(
                    "Pinned exactly: a range like ^{} would pick {} again.",
                    b.alternative.as_ref().unwrap(),
                    b.version
                ),
                dim,
            )],
            inner,
        ));
    }
    if !p.after_failure && p.has_others() {
        lines.extend(wrap(key("n"), Span::raw("   "), vec![Span::raw("install the others only")], inner));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled("any other key cancels", dim)));
    draw_dialog(f, "Blocked by the registry", lines, width);
}

/// What `d` is about to delete, to confirm.
fn draw_delete_prompt(f: &mut Frame, app: &App, p: &crate::tui::app::DeletePrompt) {
    let width = f.area().width.saturating_sub(4).min(80);
    let inner = (width as usize).saturating_sub(4);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let red = Style::new().fg(Color::Red);
    let yellow = Style::new().fg(Color::Yellow);
    let dim = Style::new().fg(Color::DarkGray);
    let s = |n: usize| if n == 1 { "" } else { "s" };

    // Each section: a title (if any), and its items already wrapped to the dialog's width.
    struct Section {
        title: Option<String>,
        items: Vec<Vec<Line<'static>>>,
        /// What the "… and N more" line counts.
        noun: &'static str,
    }
    let item = |prefix: Span<'static>, text: String, style: Style| {
        wrap(prefix, Span::raw("    "), vec![Span::styled(text, style)], inner)
    };
    let packages: Vec<String> = p
        .packages
        .iter()
        .map(|n| match app.rows.iter().find(|r| r.name == *n) {
            Some(r) => format!("{n} {}{}  ({})", r.prefix, r.current, r.kind.label()),
            None => n.clone(),
        })
        .collect();
    let mut sections = vec![
        Section {
            title: Some(format!("Uninstall {} package{}:", packages.len(), s(packages.len()))),
            items: packages
                .into_iter()
                .map(|t| item(Span::styled("  ✂ ", red), t, Style::new()))
                .collect(),
            noun: "",
        },
        Section {
            title: Some(format!(
                "Remove {} override{} from package.json:",
                p.overrides.len(),
                s(p.overrides.len())
            )),
            items: p
                .overrides
                .iter()
                .map(|o| item(Span::styled("  ✂ ", red), o.describe(), Style::new()))
                .collect(),
            noun: "",
        },
        Section {
            title: None,
            items: p
                .warnings
                .iter()
                .map(|w| {
                    wrap(
                        Span::styled("⚠ ", yellow),
                        Span::raw("  "),
                        vec![Span::styled(w.clone(), yellow)],
                        inner,
                    )
                })
                .collect(),
            noun: " warnings",
        },
    ];
    sections.retain(|sec| !sec.items.is_empty());

    // Fit the screen: the border and padding take 4 rows, the keys line 1, and each section
    // its title and a blank line after it. The longest section is shortened first; a
    // shortened one ends with "… and N more".
    let budget = (f.area().height as usize).saturating_sub(4);
    let fixed: usize = 1 + sections
        .iter()
        .map(|sec| sec.title.is_some() as usize + 1)
        .sum::<usize>();
    let mut shown: Vec<usize> = sections.iter().map(|sec| sec.items.len()).collect();
    let height = |shown: &[usize]| -> usize {
        fixed
            + sections
                .iter()
                .zip(shown)
                .map(|(sec, &n)| {
                    sec.items[..n].iter().map(Vec::len).sum::<usize>()
                        + (n < sec.items.len()) as usize
                })
                .sum::<usize>()
    };
    while height(&shown) > budget {
        // The section using the most rows gives one item up, keeping at least one.
        let rows = |i: usize| sections[i].items[..shown[i]].iter().map(Vec::len).sum::<usize>();
        let Some(i) = (0..sections.len()).filter(|&i| shown[i] > 1).max_by_key(|&i| rows(i)) else {
            break;
        };
        shown[i] -= 1;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (sec, n) in sections.into_iter().zip(shown) {
        if let Some(t) = sec.title {
            lines.push(Line::from(Span::styled(t, bold)));
        }
        let more = sec.items.len() - n;
        for it in sec.items.into_iter().take(n) {
            lines.extend(it);
        }
        if more > 0 {
            lines.push(Line::from(Span::styled(format!("    … and {more} more{}", sec.noun), dim)));
        }
        lines.push(Line::default());
    }
    lines.push(Line::from(vec![
        Span::styled("y", Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" / "),
        Span::styled("enter", Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" delete   "),
        Span::styled("any other key cancels", dim),
    ]));
    let n = p.packages.len() + p.overrides.len();
    draw_dialog(f, &format!("Delete {n} item{}", s(n)), lines, width);
}

/// The ways to fix a package's unmet peers (`f`), to pick from.
fn draw_peer_fix(f: &mut Frame, p: &crate::tui::app::PeerFix, clicks: &mut Vec<(Rect, Vec<KeyEvent>)>) {
    let width = f.area().width.saturating_sub(4).min(80);
    let inner = (width as usize).saturating_sub(4);
    let dim = Style::new().fg(Color::DarkGray);
    let mut lines: Vec<Line<'static>> = Vec::new();
    for u in &p.unmet {
        lines.extend(wrap(
            Span::raw(""),
            Span::raw("  "),
            vec![
                Span::raw(format!("{} needs ", p.name)),
                Span::styled(format!("{} {}", u.name, u.range), Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(", but "),
                Span::styled(u.installed.to_string(), Style::new().fg(Color::Yellow)),
                Span::raw(" is installed."),
            ],
            inner,
        ));
    }
    lines.push(Line::default());
    // Lines each option takes, to make them clickable.
    let mut option_lines = Vec::new();
    for (i, o) in p.options.iter().enumerate() {
        let first = lines.len();
        let chosen = i == p.choice;
        let style = if chosen {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::new()
        };
        lines.extend(wrap(
            Span::styled(if chosen { "› " } else { "  " }, Style::new().fg(Color::Cyan)),
            Span::raw("     "),
            vec![Span::styled(format!("{} {}", i + 1, o.label), style)],
            inner,
        ));
        option_lines.push((first, lines.len() - first));
    }
    for n in &p.notes {
        lines.extend(wrap(
            Span::raw("  "),
            Span::raw("  "),
            vec![Span::styled(format!("({n})"), dim)],
            inner,
        ));
    }
    lines.push(Line::default());
    lines.extend(wrap(
        Span::raw(""),
        Span::raw(""),
        vec![Span::styled(
            "The install checks peer dependencies again and asks if more has to change.",
            dim,
        )],
        inner,
    ));
    lines.push(Line::default());
    let key = |k: &str, t: &str| {
        vec![
            Span::styled(k.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {t}   ")),
        ]
    };
    let mut keys = key("enter", "fix");
    keys.extend(key("↑↓", "choose"));
    keys.extend(key("esc", "cancel"));
    lines.push(Line::from(keys));
    let (rect, cut) = draw_dialog(f, &format!("Fix the peers of {}", p.name), lines, width);
    if !cut {
        for (i, (first, n)) in option_lines.into_iter().enumerate().take(9) {
            let r = Rect {
                x: rect.x + 2,
                y: rect.y + 2 + first as u16,
                width: rect.width.saturating_sub(4),
                height: n as u16,
            };
            clicks.push((r, vec![plain(KeyCode::Char((b'1' + i as u8) as char))]));
        }
    }
}

/// A box in the middle of the screen with `lines` and `title`, at most `max_width` wide.
fn draw_dialog(f: &mut Frame, title: &str, mut lines: Vec<Line<'static>>, width: u16) -> (Rect, bool) {
    let area = f.area();
    // Taller than the screen: cut the middle, keeping the last line, which says which keys
    // to press.
    let room = (area.height as usize).saturating_sub(4);
    let cut = lines.len() > room && room >= 2;
    if cut {
        let last = lines.pop().unwrap_or_default();
        lines.truncate(room - 2);
        lines.push(Line::from(Span::styled("…", Style::new().fg(Color::DarkGray))));
        lines.push(last);
    }
    let height = (lines.len() as u16 + 4).min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Cyan))
                .title(Span::styled(
                    format!(" {title} "),
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ))
                .padding(ratatui::widgets::Padding::uniform(1)),
        ),
        rect,
    );
    (rect, cut)
}

/// The dialog for adding a package (`+`): its name and what to add it as.
fn draw_add_dialog(
    f: &mut Frame,
    app: &App,
    input: &crate::tui::app::Input,
    add_as: crate::tui::app::AddAs,
) -> Vec<(Rect, Vec<KeyEvent>)> {
    use crate::tui::app::AddAs;
    let width = f.area().width.saturating_sub(4).min(72);
    let inner = (width as usize).saturating_sub(4);
    let dim = Style::new().fg(Color::DarkGray);
    let label = |t: &str| Span::styled(format!("{t:<9}"), Style::new().add_modifier(Modifier::BOLD));
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        label("Package"),
        Span::raw(input.text.clone()),
        Span::styled("█", Style::new().fg(Color::Cyan)),
    ]));
    lines.push(Line::from(vec![
        Span::raw(" ".repeat(9)),
        Span::styled("name, or name@1.2.3 for a version (latest otherwise)", dim),
    ]));
    lines.push(Line::default());
    let overrides_in = match app.pm {
        crate::config::pm::Pm::Yarn => "resolutions",
        crate::config::pm::Pm::Pnpm => "pnpm.overrides",
        _ => "overrides",
    };
    for (i, a) in AddAs::ALL.iter().enumerate() {
        let chosen = *a == add_as;
        let note = match a {
            AddAs::Dependency => "dependencies",
            AddAs::Dev => "devDependencies",
            AddAs::Override => overrides_in,
        };
        let style = if chosen {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        lines.push(Line::from(vec![
            if i == 0 { label("Add as") } else { Span::raw(" ".repeat(9)) },
            Span::styled(if chosen { "● " } else { "○ " }, style),
            Span::styled(format!("{:<16}", a.label()), style),
            Span::styled(note.to_string(), dim),
        ]));
    }
    lines.push(Line::default());
    if let Some(name) = &input.looking_up {
        lines.push(Line::from(Span::styled(format!("Looking up {name}…"), dim)));
        lines.push(Line::default());
    } else if let Some(e) = &input.error {
        lines.extend(wrap(
            Span::raw(""),
            Span::raw(""),
            vec![Span::styled(e.clone(), Style::new().fg(Color::Red))],
            inner,
        ));
        lines.push(Line::default());
    }
    let key = |k: &str, t: &str| {
        vec![
            Span::styled(k.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {t}   ")),
        ]
    };
    let mut keys = key("enter", "add");
    keys.extend(key("tab ↑↓", "choose"));
    keys.extend(key("esc", "cancel"));
    lines.push(Line::from(keys));
    let (rect, cut) = draw_dialog(f, "Add a package", lines, width);
    let mut clicks = Vec::new();
    if !cut {
        // The three choices follow the name, a line of help and a blank line. Each is reached
        // by moving down from the chosen one.
        let at = AddAs::ALL.iter().position(|a| *a == add_as).unwrap_or(0);
        for i in 0..AddAs::ALL.len() {
            let r = Rect {
                x: rect.x + 2,
                y: rect.y + 2 + 3 + i as u16,
                width: rect.width.saturating_sub(4),
                height: 1,
            };
            let down = (i + AddAs::ALL.len() - at) % AddAs::ALL.len();
            clicks.push((r, vec![plain(KeyCode::Down); down]));
        }
    }
    clicks
}

/// The question about other packages an install needs changed, in a box in the middle of the
/// screen.
fn draw_peer_prompt(f: &mut Frame, p: &crate::tui::app::PeerPrompt) {
    let area = f.area();
    let width = area.width.saturating_sub(4).min(90);
    // Inside the border and one column of padding on each side.
    let inner = (width as usize).saturating_sub(4);
    let dim = Style::new().fg(Color::DarkGray);
    let list = |v: &[(String, semver::Version)]| {
        v.iter()
            .map(|(n, ver)| format!("{n} {ver}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.extend(wrap(
        Span::raw(""),
        Span::raw(""),
        vec![Span::raw(format!(
            "Installing {} needs other packages to change:",
            list(&p.plan)
        ))],
        inner,
    ));
    lines.push(Line::default());
    for (n, fixable) in &p.needs {
        let head = match (&n.to, fixable) {
            (Some(to), true) => vec![
                Span::styled(n.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(format!(" {} → ", n.from)),
                Span::styled(to.to_string(), Style::new().fg(Color::Green)),
            ],
            _ => vec![
                Span::styled(
                    format!("! {} {}", n.name, n.from),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(": depsu can't update it to a version that fits", Style::new().fg(Color::Yellow)),
            ],
        };
        lines.extend(wrap(Span::raw("  "), Span::raw("    "), head, inner));
        lines.extend(wrap(
            Span::raw("    "),
            Span::raw("    "),
            vec![Span::styled(n.why.clone(), dim)],
            inner,
        ));
    }
    lines.push(Line::default());
    let key = |k: &str, text: String| {
        vec![
            Span::styled(format!("{k:<3}"), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(text),
        ]
    };
    let mut keys = Vec::new();
    if p.extra.is_empty() {
        keys.push(key("y", "install anyway".to_string()));
    } else {
        keys.push(key("y", format!("also update {}", list(&p.extra))));
        keys.push(key("n", format!("install only {}", list(&p.plan))));
    }
    keys.push(vec![Span::styled("any other key cancels", dim)]);
    for k in keys {
        lines.extend(wrap(Span::raw(""), Span::raw("   "), k, inner));
    }

    let height = (lines.len() as u16 + 4).min(area.height);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Cyan))
                .title(Span::styled(
                    " Other packages must change ",
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ))
                .padding(ratatui::widgets::Padding::uniform(1)),
        ),
        rect,
    );
}

/// The header, and what a click on each of its parts does.
fn header_lines(app: &App, width: u16) -> (Vec<Line<'static>>, Vec<Placed>) {
    let outdated_total = app.rows.iter().filter(|r| r.outdated).count();
    let mut state = if app.loading() {
        format!("checking {}/{}…", app.total - app.pending, app.total)
    } else if outdated_total == 0 {
        "all dependencies are up to date".to_string()
    } else if app.shown() != outdated_total {
        format!("{} of {outdated_total} outdated", app.shown())
    } else {
        format!("{outdated_total} outdated")
    };
    if outdated_total > 0 && app.shown_up_to_date() > 0 {
        state.push_str(&format!(" · {} up to date", app.shown_up_to_date()));
    }
    // Each part and the key a click on it presses.
    let mut info: Vec<(String, Option<char>)> = vec![
        (
            match app.git_branch() {
                Some(b) => format!("{} ({b})", app.project_name()),
                None => app.project_name(),
            },
            None,
        ),
        (app.pm.name().to_string(), None),
        (app.registry.clone(), None),
        (state, None),
    ];
    if app.group_by != GroupBy::None {
        info.push((format!("group: {}", app.group_by.label()), Some('g')));
    }
    if !app.show_vulns {
        info.push(("vulns hidden".to_string(), Some('v')));
    }
    if app.show_overrides != Overrides::Off {
        info.push((format!("overrides: {}", app.show_overrides.label()), Some('o')));
    }
    if !app.show_uptodate {
        info.push(("up-to-date hidden".to_string(), None));
    }
    let audit_source = app.audit_source();
    for (source, scan) in [(Source::Snyk, &app.snyk), (audit_source, &app.audit)] {
        let label = source.label();
        match scan.status {
            ScanStatus::NotRun => {}
            ScanStatus::Running => info.push((format!("{label}: scanning…"), None)),
            ScanStatus::Failed => {
                info.push((format!("{label}: failed (see log)"), Some(scan_key(source))))
            }
            ScanStatus::Done { total: 0, .. } => info.push((format!("{label}: clean"), None)),
            ScanStatus::Done { total, severe } => info.push((
                format!("{label}: {total} vulnerabilities ({severe} high+)"),
                Some('v'),
            )),
        }
        if scan.stale {
            info.push((
                format!("{label} results outdated, press {}", scan_key(source)),
                Some(scan_key(source)),
            ));
        }
    }
    let badge = format!(" depsu {} ", env!("CARGO_PKG_VERSION"))
        .black()
        .on_cyan()
        .bold();
    let mut atoms: Vec<Atom> = info
        .into_iter()
        .map(|(i, key)| (vec![Span::raw(i)], key.map(|c| plain(KeyCode::Char(c)))))
        .collect();
    atoms[0].0.insert(0, Span::raw(" "));
    atoms[0].0.insert(0, badge);
    wrap_atoms(Vec::new(), atoms, " · ", width)
}

/// A hint or label on screen that a click turns into key presses: where it starts (line and
/// column, relative to the area the lines are drawn in), its width and the keys.
pub struct Placed {
    line: usize,
    x: u16,
    w: u16,
    keys: Vec<KeyEvent>,
}
/// A group of spans laid out as a unit, with the key a click on it stands for.
type Atom = (Vec<Span<'static>>, Option<KeyEvent>);
fn plain(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
/// The key a hint such as `i install` or `esc cancel` names, if it names one.
fn hint_key(atom: &[Span]) -> Option<KeyEvent> {
    let text: String = atom.iter().map(|s| s.content.as_ref()).collect();
    let word = text.split_whitespace().next()?;
    match word {
        "enter" => Some(plain(KeyCode::Enter)),
        // "any other key cancels" is answered by a key that is none of the options.
        "esc" | "any" => Some(plain(KeyCode::Esc)),
        "tab" => Some(plain(KeyCode::Tab)),
        "ctrl+s" => Some(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
        w if w.chars().count() == 1 && w != "," && w != "." => {
            w.chars().next().map(|c| plain(KeyCode::Char(c)))
        }
        _ => None,
    }
}
/// Lays out hint items (each a group of spans) over as many lines as the width needs.
fn wrap_hints(
    prefix: Vec<Span<'static>>,
    atoms: Vec<Vec<Span<'static>>>,
    sep: &str,
    width: u16,
) -> Vec<Line<'static>> {
    wrap_atoms(prefix, atoms.into_iter().map(|a| (a, None)).collect(), sep, width).0
}
/// `wrap_hints` for hints that start with the key they stand for: also says where a click
/// on each of them lands.
fn wrap_keys(
    prefix: Vec<Span<'static>>,
    atoms: Vec<Vec<Span<'static>>>,
    sep: &str,
    width: u16,
) -> (Vec<Line<'static>>, Vec<Placed>) {
    let atoms = atoms
        .into_iter()
        .map(|a| {
            let key = hint_key(&a);
            (a, key)
        })
        .collect();
    wrap_atoms(prefix, atoms, sep, width)
}
fn wrap_atoms(
    prefix: Vec<Span<'static>>,
    atoms: Vec<Atom>,
    sep: &str,
    width: u16,
) -> (Vec<Line<'static>>, Vec<Placed>) {
    let width = width as usize;
    let mut lines = Vec::new();
    let mut placed = Vec::new();
    let mut cur = vec![Span::raw(" ")];
    let mut cur_w = 1;
    let mut first = true;
    let mut push = |(atom, key): Atom,
                    sep: &str,
                    lines: &mut Vec<Line<'static>>,
                    placed: &mut Vec<Placed>| {
        let w: usize = atom.iter().map(|s| s.width()).sum();
        if !first && cur_w + sep.chars().count() + w > width && cur_w > 1 {
            lines.push(Line::from(std::mem::replace(&mut cur, vec![Span::raw(" ")])));
            cur_w = 1;
            first = true;
        }
        if !first {
            cur.push(Span::raw(sep.to_string()));
            cur_w += sep.chars().count();
        }
        if let Some(key) = key {
            placed.push(Placed {
                line: lines.len(),
                x: cur_w as u16,
                w: w as u16,
                keys: vec![key],
            });
        }
        cur_w += w;
        cur.extend(atom);
        first = false;
    };
    if !prefix.is_empty() {
        push((prefix, None), "", &mut lines, &mut placed);
    }
    for atom in atoms {
        push(atom, sep, &mut lines, &mut placed);
    }
    lines.push(Line::from(cur));
    (lines, placed)
}
/// Adds the clicks of hints laid out in `area` to `out`.
fn add_targets(area: Rect, placed: Vec<Placed>, out: &mut Vec<(Rect, Vec<KeyEvent>)>) {
    for p in placed {
        let y = area.y + p.line as u16;
        let x = area.x + p.x;
        if y >= area.y + area.height || x >= area.x + area.width {
            continue;
        }
        let w = p.w.min(area.x + area.width - x);
        out.push((Rect { x, y, width: w, height: 1 }, p.keys));
    }
}
fn footer_lines(app: &App, width: u16) -> (Vec<Line<'static>>, Vec<Placed>) {
    let hint = |t: &str| vec![t.to_string().dark_gray()];
    if app.log_focus {
        let hint = |t: &str, key: Option<KeyCode>| (vec![t.to_string().dark_gray()], key.map(plain));
        return wrap_atoms(
            Vec::new(),
            vec![
                hint("↑/↓ scroll", None),
                hint(", . page", None),
                hint("Home/End oldest/newest", None),
                hint("tab or esc back to list", Some(KeyCode::Tab)),
                hint("q quit", Some(KeyCode::Char('q'))),
            ],
            "   ",
            width,
        );
    }
    if app.input.is_some() {
        return wrap_keys(
            vec!["Add a package:".cyan().bold()],
            vec![hint("see the dialog above"), hint("enter add"), hint("esc cancel")],
            "   ",
            width,
        );
    }
    if app.version_edit.is_some() {
        return wrap_keys(
            vec!["Edit the version:".cyan().bold()],
            vec![hint("← → home end move"), hint("enter install"), hint("esc cancel")],
            "   ",
            width,
        );
    }
    if let Some(p) = &app.commit_prompt {
        let keys = match p.field {
            crate::tui::app::CommitField::Title => {
                vec![hint("editing the title"), hint("enter commit"), hint("tab body")]
            }
            crate::tui::app::CommitField::Body => vec![
                hint("editing the body"),
                hint("ctrl+s commit"),
                hint("enter new line"),
                hint("tab title"),
            ],
        };
        let mut keys = keys;
        keys.push(hint("← → ↑ ↓ home end move"));
        keys.push(hint("esc cancel"));
        return wrap_keys(vec!["Commit:".cyan().bold()], keys, "   ", width);
    }
    if let Some(p) = &app.blocked_prompt {
        let mut keys = Vec::new();
        if p.has_alternatives() {
            keys.push(hint("y use the version it hands out"));
        }
        if !p.after_failure && p.has_others() {
            keys.push(hint("n install the others only"));
        }
        keys.push(hint("any other key cancels"));
        return wrap_keys(vec!["Answer the dialog above:".cyan().bold()], keys, "   ", width);
    }
    if app.delete_prompt.is_some() {
        return wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y or enter delete"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.peer_fix.is_some() {
        return wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("↑↓ choose"), hint("enter or 1-9 fix"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.peer_prompt.is_some() {
        return wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y"), hint("n"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.pin_prompt {
        let opt = |k: &str, d: &str| vec![k.to_string().bold(), d.to_string().into()];
        return wrap_keys(
            vec!["Pin type:".cyan().bold()],
            vec![
                opt("e", " exact"),
                opt("c", " caret ^ (minor)"),
                opt("t", " tilde ~ (patch)"),
                opt("m", " at least >="),
                hint("any other key cancels"),
            ],
            "   ",
            width,
        );
    }
    if app.filter_mode {
        return wrap_keys(
            vec!["/".cyan().bold(), app.filter.clone().into(), "█".cyan()],
            vec![hint("enter keep"), hint("esc clear")],
            "   ",
            width,
        );
    }
    let (item, scan, mut global) = app.hints();
    let mut prefix = vec!["all:".cyan().bold()];
    if !app.filter.is_empty() {
        prefix.push(format!(" filter: {}", app.filter).cyan());
        if let Some(pos) = global.iter().position(|h| h == "/ filter") {
            global[pos] = "/ edit".to_string();
            global.insert(pos + 1, "esc clear".to_string());
        }
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut placed: Vec<Placed> = Vec::new();
    let mut add = |(l, p): (Vec<Line<'static>>, Vec<Placed>)| {
        placed.extend(p.into_iter().map(|mut p| {
            p.line += lines.len();
            p
        }));
        lines.extend(l);
    };
    if !item.is_empty() {
        add(wrap_keys(
            vec!["item:".cyan().bold()],
            item.iter().map(|h| hint(h)).collect(),
            "   ",
            width,
        ));
    }
    if !scan.is_empty() {
        add(wrap_keys(
            vec!["scan:".cyan().bold()],
            scan.iter().map(|h| hint(h)).collect(),
            "   ",
            width,
        ));
    }
    add(wrap_keys(
        prefix,
        global.iter().map(|h| hint(h)).collect(),
        "   ",
        width,
    ));
    (lines, placed)
}

fn removed_line(app: &App, name: &str) -> Line<'static> {
    let Some(p) = app.removed_pkg(name) else {
        return Line::from(name.to_string());
    };
    let note = match p.status {
        Status::Queued => "restoring…".to_string(),
        Status::Installing => "restoring…".to_string(),
        Status::Failed => "restore failed, press r to retry".to_string(),
        Status::Idle => "press r to restore".to_string(),
    };
    Line::from(format!(
        "↩ {name}  was {}{}  {note}",
        p.spec,
        if p.spec == p.row.current.to_string() {
            String::new()
        } else {
            format!(" (installed {})", p.row.current)
        }
    ))
    .style(Style::new().fg(Color::Magenta))
}

fn header_line(app: &App, label: &str, members: &[usize]) -> Line<'static> {
    if label == crate::tui::view::REMOVED && members.is_empty() {
        return Line::from(format!("✂ {label} ({})", app.removed.len()))
            .style(Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD));
    }
    if label == UNNEEDED && members.is_empty() {
        let n = app
            .view
            .iter()
            .filter(|i| matches!(i, Item::Override { .. }))
            .count();
        return Line::from(format!("✂ {label} ({n}), press d to remove"))
            .style(Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD));
    }
    let sel = members.iter().filter(|&&i| app.rows[i].selected).count();
    let mark = if sel == 0 {
        "○"
    } else if sel == members.len() {
        "●"
    } else {
        "◐"
    };
    let color = match label {
        "Patch" => Color::Green,
        "Minor" => Color::Yellow,
        "Major" => Color::Red,
        crate::tui::view::UP_TO_DATE => Color::DarkGray,
        _ => Color::Cyan,
    };
    Line::from(format!("{mark} {label} ({})", members.len()))
        .style(Style::new().fg(color).add_modifier(Modifier::BOLD))
}

fn row_line(app: &App, r: &AppRow, indent: usize, name_w: usize, width: usize) -> Line<'static> {
    let mark = match r.status {
        Status::Queued => "…",
        Status::Installing => "⟳",
        Status::Failed => "✘",
        Status::Idle if r.selected => "●",
        Status::Idle if !r.outdated => "·",
        Status::Idle => "○",
    };
    let color = match r.release() {
        Release::Major => Color::Red,
        Release::Minor => Color::Yellow,
        Release::Patch => Color::Green,
    };
    let (marker, marker_w) = override_marker(r);
    let mut spans = vec![Span::raw(format!(
        "{mark} {}{:<w$} ",
        " ".repeat(indent),
        r.name,
        w = name_w - indent
    ))];
    spans.extend(marker);
    spans.push(Span::raw(" ".repeat(4usize.saturating_sub(marker_w) + 1)));
    spans.push(Span::styled(
        format!("{:<4}", r.kind.label()),
        Style::new().fg(Color::DarkGray),
    ));
    // The range prefix is highlighted, so it is clear at a glance how the version is pinned.
    let version = r.current.to_string();
    let prefix_color = match r.range() {
        VersionRange::Exact => Color::Reset,
        VersionRange::Tilde => Color::Cyan,
        VersionRange::Caret => Color::Yellow,
        VersionRange::AtLeast => Color::Red,
    };
    spans.push(Span::styled(
        r.prefix,
        Style::new().fg(prefix_color).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(format!(
        "{:<w$}",
        version,
        w = 14usize.saturating_sub(r.prefix.chars().count())
    )));
    if r.loading {
        spans.push(Span::styled("checking…", Style::new().fg(Color::DarkGray)));
    } else if r.latest_failed {
        spans.push(Span::styled("? latest unknown", Style::new().fg(Color::Red)));
    } else if r.outdated {
        spans.push(Span::raw("→ "));
        spans.push(Span::styled(r.new_spec(), Style::new().fg(color)));
    } else {
        spans.push(Span::styled("✓ up to date", Style::new().fg(Color::Green)));
    }
    for (label, fix) in [("snyk", &r.snyk_fix), ("audit", &r.audit_fix)] {
        if let Some(fix) = fix {
            spans.push(Span::styled(
                format!("   {label} fix: {}{fix}", r.prefix),
                Style::new().fg(Color::Magenta),
            ));
        }
    }
    // A scanner with results hasn't looked at the version installed now.
    if r.scan_outdated() {
        spans.push(Span::styled(
            format!("   {}", unscanned_label(&r.unscanned)),
            Style::new().fg(Color::Yellow),
        ));
    }
    if let Some(from) = &r.changed_from {
        let verb = if *from < r.current { "upgraded" } else { "downgraded" };
        spans.push(Span::styled(
            format!("   {verb} from {from} to {} in this session", r.current),
            Style::new().fg(Color::Cyan),
        ));
    }
    let users = app.dependents_of(&r.name);
    if !users.is_empty() {
        let used: usize = spans.iter().map(|s| s.width()).sum();
        let mut names: Vec<String> = users
            .iter()
            .map(|d| {
                if d.direct == d.name {
                    d.name.clone()
                } else {
                    format!("{} (via {})", d.name, d.direct)
                }
            })
            .collect();
        names.sort();
        names.dedup();
        let with_names = format!("   used by {}", names.join(", "));
        let text = if used + with_names.chars().count() < width {
            with_names
        } else {
            format!("   used by {}", names.len())
        };
        spans.push(Span::styled(text, Style::new().fg(Color::Cyan)));
    }
    // Peers are listed in the details panel; the list only flags the ones that don't fit.
    let unmet: Vec<String> = r
        .peers
        .iter()
        .filter(|p| p.met() == Some(false))
        .map(|p| {
            let have = p.installed.as_ref().map(|v| v.to_string()).unwrap_or_default();
            format!("{} {} (has {have})", p.name, p.range)
        })
        .collect();
    if !unmet.is_empty() {
        let used: usize = spans.iter().map(|s| s.width()).sum();
        let s = if unmet.len() == 1 { "" } else { "s" };
        let full = format!("   ⚠ unmet peer{s}: {}", unmet.join(", "));
        let text = if used + full.chars().count() < width {
            full
        } else {
            format!("   ⚠ {} unmet peer{s}", unmet.len())
        };
        spans.push(Span::styled(
            text,
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    let line = Line::from(spans);
    if r.busy() || !r.outdated {
        line.style(Style::new().add_modifier(Modifier::DIM))
    } else {
        line
    }
}

/// E.g. `↻ npm audit hasn't scanned this version (n)`, naming the scanners and their keys.
pub fn unscanned_label(sources: &[Source]) -> String {
    let names: Vec<String> = sources
        .iter()
        .map(|s| format!("{} ({})", s.label(), scan_key(*s)))
        .collect();
    let verb = if sources.len() == 1 { "hasn't" } else { "haven't" };
    format!("↻ {} {verb} scanned this version", names.join(" and "))
}

fn severity_color(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::Magenta,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
    }
}

fn compat_color(c: Compat) -> Color {
    match c {
        Compat::Ok => Color::Cyan,
        Compat::Unknown => Color::Yellow,
        Compat::Conflict => Color::Red,
    }
}

fn compat_symbol(c: Compat) -> &'static str {
    match c {
        Compat::Ok => "⚑",
        Compat::Unknown => "?",
        Compat::Conflict => "⚠",
    }
}

/// Compact marker next to the name, visible even when the nested lists are hidden:
/// ⚑/?/⚠ for overrides on the package itself, ↳ for overrides in its dependency tree
/// (yellow when one forces a version outside what its parent declared).
fn override_marker(r: &AppRow) -> (Vec<Span<'static>>, usize) {
    let mut spans = Vec::new();
    let mut width = 0;
    if !r.overrides.is_empty() && r.lists_own_overrides() {
        spans.push(Span::styled(
            compat_symbol(r.compat),
            Style::new().fg(compat_color(r.compat)),
        ));
        width += 1;
    }
    if !r.tree_hits.is_empty() {
        let risky = r.tree_hits.iter().any(|h| h.risk == Compat::Conflict);
        let color = if risky { Color::Yellow } else { Color::Cyan };
        spans.push(Span::styled("↳", Style::new().fg(color)));
        width += 1;
    }
    // ✱: Snyk found vulnerabilities, coloured by the worst severity.
    if let Some(sev) = r.worst_severity() {
        spans.push(Span::styled(
            "✱",
            Style::new()
                .fg(severity_color(sev))
                .add_modifier(Modifier::BOLD),
        ));
        width += 1;
    }
    (spans, width)
}

/// An override line nested under its package.
fn detail_lines(
    app: &App,
    r: &AppRow,
    child: Child,
    last: bool,
    indent: usize,
    width: usize,
) -> Vec<Line<'static>> {
    let branch = if last { "└─" } else { "├─" };
    let prefix = format!("  {}   {branch} ", " ".repeat(indent));

    let o = match child {
        Child::Own(i) => r.overrides.get(i),
        Child::Tree(i) => r.tree_hits.get(i).map(|h| &h.over),
        Child::Vuln(_) => None,
    };
    let update = o.and_then(|o| app.update_target(o));
    // Selection mark, only on override lines that can be updated.
    let unneeded = o.and_then(|o| app.unneeded(o).map(|u| u.reason(o)));
    let actionable = update.is_some() || unneeded.is_some();
    let mark = match o {
        Some(o) if actionable && app.override_busy(o) => "⟳ ",
        Some(o) if actionable && app.override_selected(o) => "● ",
        Some(_) if actionable => "○ ",
        _ => "",
    };
    let new_value = update.as_ref().map(|u| {
        let color = match u.release {
            Release::Major => Color::Red,
            Release::Minor => Color::Yellow,
            Release::Patch => Color::Green,
        };
        Span::styled(format!("  ⇢ {}", u.value), Style::new().fg(color))
    });

    let (text, tail, color) = match child {
        Child::Own(i) => {
            let o = &r.overrides[i];
            let (c, note) = own_override_note(app, r, o);
            let tail = if note.is_empty() {
                String::new()
            } else {
                format!("  ({note})")
            };
            (
                format!("{} {}", compat_symbol(c), o.describe()),
                tail,
                compat_color(c),
            )
        }
        Child::Tree(i) => {
            let h = &r.tree_hits[i];
            let color = if h.risk == Compat::Conflict {
                Color::Yellow
            } else {
                Color::Cyan
            };
            // Would the new override value still satisfy the parent's declared range?
            let mut tail = String::new();
            if let Some(u) = &update {
                let mut moved = h.over.clone();
                moved.value = u.value.clone();
                if tree::risk(&moved, &h.requested) == Compat::Conflict {
                    tail = format!("  ⚠ outside {} wanted by the parent", h.requested);
                }
            }
            (format!("↳ {}", hit_text(h)), tail, color)
        }
        Child::Vuln(i) => {
            let v = &r.vulns[i];
            let mut t = format!(
                "✱ {:<8} [{}] {}  {}",
                v.severity.label(),
                v.source.label(),
                v.id,
                v.title
            );
            t.push_str(&format!("  · {}@{}", v.package, v.version));
            if let Some(range) = &v.range {
                t.push_str(&format!(" (affected {range})"));
            }
            if v.path.len() > 1 {
                t.push_str(&format!(" via {}", v.path[..v.path.len() - 1].join(" > ")));
            }
            if let Some(cve) = v.cve.first() {
                t.push_str(&format!("  · {cve}"));
            }
            (t, String::new(), severity_color(v.severity))
        }
    };

    // The new value goes right after the override itself, before via/notes.
    let (head, rest) = match child {
        Child::Tree(i) => {
            let h = &r.tree_hits[i];
            let head = format!("↳ {} → {}", h.over.name, h.over.value);
            let rest = text[head.len().min(text.len())..].to_string();
            (head, rest)
        }
        _ => (text, String::new()),
    };
    let mut spans = vec![
        Span::styled(mark.to_string(), Style::new().fg(Color::White)),
        Span::styled(head, Style::new().fg(color)),
    ];
    spans.extend(new_value);
    spans.push(Span::styled(
        format!("{rest}{tail}"),
        Style::new().fg(color),
    ));
    if let Child::Vuln(i) = child {
        spans.extend(fix_spans(app, r, &r.vulns[i]));
    }
    if let Some(reason) = unneeded {
        spans.push(Span::styled(
            format!("  ✂ may be removed: {reason}"),
            Style::new().fg(Color::Magenta),
        ));
    }

    // Wrapped lines continue the tree guide and line up under the text, after the mark.
    let guide = Style::new().fg(Color::DarkGray);
    let lead = format!("  {}   ", " ".repeat(indent));
    let cont = format!(
        "{lead}{}{}",
        if last { "   " } else { "│  " },
        " ".repeat(mark.chars().count())
    );
    wrap(
        Span::styled(prefix, guide),
        Span::styled(cont, guide),
        spans,
        width,
    )
}

/// What fixes a finding. Fixes a key can apply stand out in green with the key to press;
/// fixes depsu can't apply, or no fix at all, stay grey.
fn fix_spans(app: &App, r: &AppRow, v: &crate::security::vuln::Vuln) -> Vec<Span<'static>> {
    let fixable = Style::new().fg(Color::Green).add_modifier(Modifier::BOLD);
    if let Some(to) = app.vuln_install_fix(r, v) {
        return vec![
            Span::raw("  "),
            Span::styled(format!("⬆ fix: i installs {} {}{to}", r.name, r.prefix), fixable),
            Span::styled(format!("  ({})", v.fix_summary()), Style::new().fg(Color::DarkGray)),
        ];
    }
    if let Some(to) = app.vuln_pin_fix(v) {
        return vec![
            Span::raw("  "),
            Span::styled(format!("⬆ fix: p overrides {} to ^{to}", v.package), fixable),
            Span::styled(
                format!("  (upgrading {} doesn't bring it in)", r.name),
                Style::new().fg(Color::DarkGray),
            ),
        ];
    }
    vec![Span::styled(
        format!("  · {}", v.fix_summary()),
        Style::new().fg(Color::DarkGray),
    )]
}

/// Word-wraps `spans` to `width` columns. The first line starts with `first`, the following
/// ones with `cont`. Words longer than a whole line are split.
fn wrap(
    first: Span<'static>,
    cont: Span<'static>,
    spans: Vec<Span<'static>>,
    width: usize,
) -> Vec<Line<'static>> {
    let avail = width
        .saturating_sub(first.width().max(cont.width()))
        .max(10);

    // Words, each keeping its trailing spaces and its style.
    let mut tokens: Vec<(String, Style)> = Vec::new();
    for sp in spans {
        let mut cur = String::new();
        let mut in_space = false;
        for ch in sp.content.chars() {
            if ch == ' ' {
                in_space = true;
            } else if in_space {
                tokens.push((std::mem::take(&mut cur), sp.style));
                in_space = false;
            }
            cur.push(ch);
        }
        if !cur.is_empty() {
            tokens.push((cur, sp.style));
        }
    }

    let mut lines: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0;
    for (tok, style) in tokens {
        let word_w = Span::raw(tok.trim_end().to_string()).width();
        if used > 0 && used + word_w > avail {
            lines.push(Vec::new());
            used = 0;
        }
        if used == 0 && tok.trim().is_empty() {
            continue; // no leading spaces on a continuation line
        }
        if word_w <= avail {
            used += Span::raw(tok.clone()).width();
            lines.last_mut().unwrap().push(Span::styled(tok, style));
            continue;
        }
        // A single word wider than the line: break it by characters.
        let mut chunk = String::new();
        let mut chunk_w = 0;
        for ch in tok.chars() {
            let w = Span::raw(ch.to_string()).width();
            if used + chunk_w + w > avail && (used + chunk_w) > 0 {
                lines
                    .last_mut()
                    .unwrap()
                    .push(Span::styled(std::mem::take(&mut chunk), style));
                lines.push(Vec::new());
                used = 0;
                chunk_w = 0;
            }
            chunk.push(ch);
            chunk_w += w;
        }
        used += chunk_w;
        lines.last_mut().unwrap().push(Span::styled(chunk, style));
    }

    lines
        .into_iter()
        .enumerate()
        .map(|(i, mut l)| {
            l.insert(0, if i == 0 { first.clone() } else { cont.clone() });
            Line::from(l)
        })
        .collect()
}

/// An override listed on its own in the "unneeded" section.
fn orphan_lines(app: &App, key: &str, width: usize) -> Vec<Line<'static>> {
    let Some(o) = app.override_by_key(key) else {
        return vec![Line::default()];
    };
    let mark = if app.override_busy(o) {
        "⟳ "
    } else if app.override_selected(o) {
        "● "
    } else {
        "○ "
    };
    let reason = app.unneeded(o).map(|u| u.reason(o)).unwrap_or_default();
    let spans = vec![
        Span::raw(mark),
        Span::styled("✂ ", Style::new().fg(Color::Magenta)),
        Span::raw(o.describe()),
        Span::styled(format!("   {reason}"), Style::new().fg(Color::DarkGray)),
    ];
    wrap(Span::raw("  "), Span::raw("      "), spans, width)
}

/// Compatibility of the update of `r` with its own override `o`, and a short explanation.
fn own_override_note(app: &App, r: &AppRow, o: &Override) -> (Compat, String) {
    // Overridden packages aren't dependencies, so there is no dependency spec to clash with.
    if r.kind == Kind::Override {
        let note = if o.path.is_empty() {
            String::new()
        } else {
            "only applies below another package".to_string()
        };
        return (Compat::Ok, note);
    }
    let c = overrides::check(std::slice::from_ref(o), app.pm, &r.new_spec(), &r.latest);
    // Up-to-date packages have no pending update to be compatible with.
    let note = if !o.path.is_empty() {
        "only applies below another package".to_string()
    } else if !r.outdated {
        String::new()
    } else {
        match c {
            Compat::Ok => format!("compatible with {}", r.latest),
            Compat::Unknown => "cannot verify compatibility".to_string(),
            Compat::Conflict if app.pm == Pm::Npm => {
                "must equal the dependency spec (EOVERRIDE), use \"$name\" or update it".to_string()
            }
            Compat::Conflict => format!(
                "{} is outside the override, the update would have no effect",
                r.latest
            ),
        }
    };
    (if r.outdated { c } else { Compat::Ok }, note)
}

/// Lines reserved at the bottom for the override summary while the nested lists are hidden.
const SUMMARY_LINES: u16 = 3;

/// Text summary of the overrides of the highlighted package, wrapped to `width`. Shown in
/// place of the nested lists when those are hidden.
fn summary_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Vec::new();
    };
    let r = &app.rows[*idx];
    let mut spans: Vec<Span<'static>> = Vec::new();
    for o in r.overrides.iter().filter(|_| r.lists_own_overrides()) {
        let (c, note) = own_override_note(app, r, o);
        let mut text = format!("{} {}", compat_symbol(c), o.describe());
        if let Some(u) = app.update_target(o) {
            text.push_str(&format!(" ⇢ {}", u.value));
        }
        if !note.is_empty() {
            text.push_str(&format!(" ({note})"));
        }
        if let Some(u) = app.unneeded(o) {
            text.push_str(&format!(" ✂ may be removed: {}", u.reason(o)));
        }
        text.push_str("   ");
        spans.push(Span::styled(text, Style::new().fg(compat_color(c))));
    }
    if !r.tree_hits.is_empty() {
        // Risky hits come first, so they survive the cut-off.
        let shown: Vec<String> = r
            .tree_hits
            .iter()
            .take(3)
            .map(|h| match app.unneeded(&h.over) {
                Some(u) => format!("{} ✂ may be removed: {}", hit_text(h), u.reason(&h.over)),
                None => hit_text(h),
            })
            .collect();
        let more = r.tree_hits.len().saturating_sub(3);
        let mut text = format!("↳ overrides in dependency tree: {}", shown.join(", "));
        if more > 0 {
            text.push_str(&format!(", +{more} more"));
        }
        let color = if r.tree_hits.iter().any(|h| h.risk == Compat::Conflict) {
            Color::Yellow
        } else {
            Color::Cyan
        };
        spans.push(Span::styled(text, Style::new().fg(color)));
    }
    if spans.is_empty() {
        return Vec::new();
    }

    // Two columns stay free for the " …" shown when the text is cut off.
    let mut lines = wrap(
        Span::raw(" "),
        Span::raw(" "),
        spans,
        width.saturating_sub(2),
    );
    if lines.len() > SUMMARY_LINES as usize {
        lines.truncate(SUMMARY_LINES as usize);
        if let Some(last) = lines.last_mut() {
            last.spans
                .push(Span::styled(" …", Style::new().fg(Color::DarkGray)));
        }
    }
    lines
}

/// For the package under the cursor: the installed packages that depend on it.
fn used_by_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Vec::new();
    };
    let deps = app.dependents_of(&app.rows[*idx].name);
    if deps.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<String> = Vec::new();
    for d in deps {
        let version = d.version.as_ref().map(|v| format!("@{v}")).unwrap_or_default();
        let via = if d.direct == d.name {
            String::new()
        } else {
            format!(" via {}", d.direct)
        };
        parts.push(format!("{}{version} ({}){via}", d.name, d.range));
    }
    parts.sort();
    let cyan = Style::new().fg(Color::Cyan);
    let label = format!("used by {} installed package(s): ", parts.len());
    let mut atoms: Vec<Vec<Span<'static>>> = parts
        .into_iter()
        .map(|p| vec![Span::styled(p, cyan)])
        .collect();
    atoms[0].insert(0, Span::styled(label, cyan));
    let mut lines = wrap_hints(Vec::new(), atoms, ", ", width);
    if lines.len() > MAX_USED_BY_LINES {
        lines.truncate(MAX_USED_BY_LINES);
        if let Some(last) = lines.last_mut() {
            last.spans.push(Span::styled(" …", Style::new().fg(Color::DarkGray)));
        }
    }
    lines
}
/// For the package under the cursor: the peer dependencies its installed copy declares, and
/// the version of each the project has.
fn peer_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Vec::new();
    };
    let peers = &app.rows[*idx].peers;
    if peers.is_empty() {
        return Vec::new();
    }
    let (cyan, yellow) = (Style::new().fg(Color::Cyan), Style::new().fg(Color::Yellow));
    let label = format!(
        "{} peer dependenc{}: ",
        peers.len(),
        if peers.len() == 1 { "y" } else { "ies" }
    );
    let mut atoms: Vec<Vec<Span<'static>>> = peers
        .iter()
        .map(|p| {
            vec![match (p.met(), &p.installed) {
                (Some(false), Some(have)) => Span::styled(
                    format!("{} {}, but {have} is installed", p.name, p.range),
                    yellow,
                ),
                (_, Some(have)) => Span::styled(format!("{} {} ({have})", p.name, p.range), cyan),
                (_, None) => Span::styled(format!("{} {} (not installed)", p.name, p.range), cyan),
            }]
        })
        .collect();
    atoms[0].insert(0, Span::styled(label, cyan));
    let mut lines = wrap_hints(Vec::new(), atoms, ", ", width);
    if lines.len() > MAX_USED_BY_LINES {
        lines.truncate(MAX_USED_BY_LINES);
        if let Some(last) = lines.last_mut() {
            last.spans.push(Span::styled(" …", Style::new().fg(Color::DarkGray)));
        }
    }
    lines
}

/// Most lines the list of dependents takes in the selected section.
const MAX_USED_BY_LINES: usize = 4;

fn hit_text(h: &Hit) -> String {
    let mut t = format!("{} → {}", h.over.name, h.over.value);
    if h.via.len() > 1 {
        t.push_str(&format!(" via {}", h.via.join(" > ")));
    }
    if h.risk == Compat::Conflict {
        t.push_str(&format!(" (wants {}", h.requested));
        if let Some(v) = &h.installed {
            t.push_str(&format!(", installed {v}"));
        }
        t.push(')');
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(l: &Line) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn run(width: usize, body: &str) -> Vec<String> {
        wrap(
            Span::raw("├─ "),
            Span::raw("│  "),
            vec![Span::raw(body.to_string())],
            width,
        )
        .iter()
        .map(text)
        .collect()
    }

    #[test]
    fn short_text_stays_on_one_line() {
        assert_eq!(run(40, "tar → 5.0.0"), ["├─ tar → 5.0.0"]);
    }

    #[test]
    fn wraps_on_words_with_continuation_prefix() {
        let lines = run(20, "one two three four five six");
        assert!(lines.len() > 1);
        assert!(lines[1..].iter().all(|l| l.starts_with("│  ")));
        assert!(
            lines.iter().all(|l| Span::raw(l.clone()).width() <= 20),
            "{lines:?}"
        );
        // no words lost or reordered
        let words: Vec<String> = lines
            .iter()
            .flat_map(|l| {
                let body: String = l.chars().skip(3).collect();
                body.split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(words.join(" "), "one two three four five six");
    }

    #[test]
    fn breaks_words_longer_than_the_line() {
        let lines = run(14, "averyveryverylongpackagename");
        assert!(lines.len() > 1);
        assert!(
            lines.iter().all(|l| Span::raw(l.clone()).width() <= 14),
            "{lines:?}"
        );
        let joined: String = lines
            .iter()
            .map(|l| l.chars().skip(3).collect::<String>())
            .collect();
        assert_eq!(joined, "averyveryverylongpackagename");
    }
}
