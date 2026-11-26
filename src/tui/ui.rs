use crate::tui::app::{App, VersionRange, Row as AppRow, ScanStatus, Status, scan_key};
use crate::deps::overrides::{self, Compat, Override};
use crate::deps::package::Kind;
use crate::config::pm::Pm;
use crate::deps::tree::{self, Hit};
use crate::tui::view::{Child, GroupBy, Item, Overrides, POLICY, Release, UNNEEDED};
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
/// Highlights the text the mouse is selecting and reads it off the screen for copying.
fn draw_selection(f: &mut Frame, app: &mut App) {
    app.selection_text.clear();
    let Some(sel) = app.selection.filter(|s| s.dragged) else {
        return;
    };
    // The panel may have moved or gone (a resize, the log closing), or a new log line moved
    // the text under the highlight.
    if !app.targets.selectable.contains(&sel.area) || sel.log_len != app.log.len() {
        app.selection = None;
        return;
    }
    let buf = f.buffer_mut();
    let mut rows = Vec::new();
    for y in sel.area.y..sel.area.y + sel.area.height {
        let Some(cols) = sel.columns(y) else {
            continue;
        };
        let mut row = String::new();
        let mut skip = 0;
        for x in cols {
            let cell = &mut buf[(x, y)];
            cell.modifier.insert(Modifier::REVERSED);
            // A wide character covers the cell after it, which holds nothing of its own.
            if skip > 0 {
                skip -= 1;
                continue;
            }
            let sym = cell.symbol();
            skip = Span::raw(sym).width().saturating_sub(1);
            row.push_str(sym);
        }
        rows.push(row.trim_end().to_string());
    }
    app.selection_text = rows.join("\n");
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
        || app.ignore_prompt.is_some()
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
    if app.installed_open {
        let header = format!("{} ({})", app.project_name(), app.pm.name());
        app.targets = Default::default();
        app.installed.draw(f, &header);
        return;
    }
    let log_h = (app.log.len() as u16).clamp(1, 5);
    app.targets = Default::default();
    let focus = focus(app);
    let footer_boxed = focus == Focus::Footer;
    let footer_w = if footer_boxed { panel_width(f) } else { inner_width(f) };
    // The item hints change with the cursor. Their section keeps the tallest height it has had
    // at this width, so the screen does not change size as the cursor moves.
    if app.item_rows.footer_w != footer_w {
        app.item_rows = crate::tui::app::ItemSection { footer_w, rows: 1 };
    }
    let (footer, footer_hits, used) = footer_lines(app, footer_w, app.item_rows);
    app.item_rows.rows = app.item_rows.rows.max(used.rows);
    let (header_lines, header_hits) = header_lines(app, f.area().width);
    // The details panel makes room for the expanded log.
    let info = app.show_info && !app.log_focus;
    // Everything about the item under the cursor, in full: the panel scrolls.
    let info_lines = if info {
        let on_package = matches!(app.cursor_item(), Some(Item::Row { .. }));
        let details = app.cursor_info().cloned();
        let mut lines = if on_package {
            package_lines(details.as_ref(), &app.tools, panel_width(f) as usize)
        } else if let Some((idx, v)) = app.cursor_finding() {
            vuln_lines(app, &app.rows[idx], v, panel_width(f) as usize)
        } else {
            Vec::new()
        };
        lines.extend(used_by_lines(app, panel_width(f)));
        lines.extend(peer_lines(app, panel_width(f)));
        lines.extend(summary_lines(app, panel_width(f) as usize));
        // The box pads its contents already: drop the space the wrappers start lines with.
        for l in &mut lines {
            if l.spans.first().is_some_and(|s| s.content == " ") {
                l.spans.remove(0);
            }
        }
        lines
    } else {
        Vec::new()
    };
    // The package list and a footer prompt are boxed; the border and the title take the rows
    // the heading took.
    // A footer prompt is boxed. The hints sit right under the log's box, with no rule.
    let footer_h = footer.len() as u16 + if footer_boxed { 2 } else { 0 };
    // The log is boxed like the list. Expanded, it takes 7/8 of the room, and the list keeps
    // the rest so both can be clicked.
    let collapsed_h = log_h + 2;
    let log_box_h = if app.log_focus {
        let room = f.area().height.saturating_sub(header_lines.len() as u16 + footer_h);
        (room * 7 / 8).clamp(collapsed_h, room.saturating_sub(7).max(collapsed_h))
    } else {
        collapsed_h
    };
    // The details panel is boxed like the list and the log. It has the same height whatever
    // the item, so the screen does not jump as the cursor moves; longer contents scroll. It
    // takes a third of the screen, within limits.
    let info_rows = (f.area().height / 3).clamp(INFO_MIN_LINES, INFO_LINES);
    let info_h = if info { info_rows + 2 } else { 0 };
    let [header, list_area, info_area, log_area, keys_area] = Layout::vertical([
        Constraint::Length(header_lines.len() as u16),
        Constraint::Min(5),
        Constraint::Length(info_h),
        Constraint::Length(log_box_h),
        Constraint::Length(footer_h),
    ])
    .areas(f.area());
    f.render_widget(Paragraph::new(header_lines), header);
    // Part of the screen outside the list reacts to the mouse only while the list has the keys:
    // the keys a click stands for would go to a prompt otherwise.
    let clickable = focus == Focus::List;
    if clickable {
        add_targets(header, header_hits, &mut app.targets.keys);
        app.targets.info_panel = info_area;
        if info {
            // The title row of the details panel hides it.
            let r = Rect { height: 1, ..info_area };
            app.targets.keys.push((r, vec![plain(KeyCode::Char('?'))]));
        }
        // The log: a click opens it.
        app.targets.keys.push((log_area, vec![plain(KeyCode::Tab)]));
    }
    app.targets.list_panel = list_area;
    if focus == Focus::Log {
        // The title of the expanded log closes it.
        let title_row = Rect { height: 1, ..log_area };
        app.targets.keys.push((title_row, vec![plain(KeyCode::Tab)]));
    }
    let body = panel(f, list_area, "packages", focus == Focus::List);

    let grouped = app.group_by != GroupBy::None;
    let indent = if grouped { 2 } else { 0 };
    let name_w = app
        .rows
        .iter()
        .map(|r| display_name(r).chars().count() + indent)
        .max()
        .unwrap_or(0)
        .clamp(16, 48);

    let items: Vec<ListItem> = app
        .view
        .iter()
        .enumerate()
        .map(|(i, item)| (app.is_highlighted(i), item))
        .map(|(lit, item)| (lit, match item {
            Item::Header { label, members } => ListItem::new(header_line(app, label, members)),
            Item::Row { idx, .. } => ListItem::new(row_line(app, &app.rows[*idx], indent, name_w, body.width as usize)),
            Item::Removed { name } => ListItem::new(removed_line(app, name)),
            Item::Policy { id, path } => {
                ListItem::new(Text::from(policy_lines(app, id, path, body.width as usize)))
            }
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
        }))
        // Highlighted items (drag, Shift-click) get a background, unlike checked ones (●).
        .map(|(lit, li)| if lit { li.style(Style::new().bg(Color::DarkGray)) } else { li })
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
        Some(Item::Policy { id, .. }) => format!("selected: {id}"),
        _ => match app.cursor_finding() {
            Some((_, v)) => format!("selected: {} in {}", v.id, v.package),
            None => "selected".to_string(),
        },
    };
    if info {
        // A new item is shown from the top.
        if app.info_for != app.table.selected() {
            app.info_for = app.table.selected();
            app.info_scroll = 0;
        }
        let h = info_area.height.saturating_sub(2) as usize;
        let total = info_lines.len();
        app.info_scroll = app.info_scroll.min(total.saturating_sub(h));
        let title = if total > h {
            format!(
                "{info_title} · {}–{} of {total} · ctrl+↑↓ scroll · ? to hide",
                app.info_scroll + 1,
                (app.info_scroll + h).min(total)
            )
        } else {
            format!("{info_title} · ? to hide")
        };
        let inner = panel(f, info_area, title, false);
        app.targets.selectable.push(inner);
        let lines: Vec<Line> = if info_lines.is_empty() {
            vec![Line::from(Span::styled(
                "nothing more to show for this item",
                Style::new().fg(Color::DarkGray),
            ))]
        } else {
            info_lines.into_iter().skip(app.info_scroll).take(h).collect()
        };
        f.render_widget(Paragraph::new(lines), inner);
    }

    // The title is the toggle: a click on the panel does the same as tab.
    let title = match (app.log_focus, app.log_scroll) {
        (false, _) => "log · tab to expand".to_string(),
        (true, 0) => "log · tab to close".to_string(),
        (true, n) => format!("log (↑{n} older) · tab to close"),
    };
    let log_body = panel(f, log_area, title, focus == Focus::Log);
    app.targets.selectable.push(log_body);
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
        let help = pad(keys_area);
        add_targets(help, footer_hits, &mut app.targets.keys);
        f.render_widget(Paragraph::new(footer), help);
    }
    draw_selection(f, app);
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
    if let Some(p) = &app.ignore_prompt {
        draw_ignore_dialog(f, p);
    }
    if let Some(input) = &app.input
        && let crate::tui::app::InputPurpose::Add { add_as, pin } = &input.purpose
    {
        let clicks = draw_add_dialog(f, app, input, *add_as, pin);
        app.targets.keys.extend(clicks);
    }
    if let Some(menu) = &app.context_menu {
        let (rect, entries) = draw_context_menu(f, menu);
        app.targets.menu_rect = rect;
        app.targets.menu = entries;
    }
}
/// The right-click menu, next to the pointer. Returns its box and where each entry is.
fn draw_context_menu(f: &mut Frame, menu: &crate::tui::app::ContextMenu) -> (Rect, Vec<(Rect, usize)>) {
    let area = f.area();
    let key_name = |k: char| if k == ' ' { "space".to_string() } else { k.to_string() };
    let key_w = menu.entries.iter().map(|(k, _)| key_name(*k).chars().count()).max().unwrap_or(1);
    let text_w = menu
        .entries
        .iter()
        .map(|(_, l)| key_w + 2 + l.chars().count())
        .max()
        .unwrap_or(0);
    let width = ((text_w + 4) as u16).min(area.width);
    let height = (menu.entries.len() as u16 + 2).min(area.height);
    let rect = Rect {
        x: menu.at.0.min(area.x + area.width - width),
        y: menu.at.1.min(area.y + area.height - height),
        width,
        height,
    };
    let lines: Vec<Line<'static>> = menu
        .entries
        .iter()
        .enumerate()
        .map(|(i, (k, label))| {
            let line = Line::from(vec![
                Span::styled(
                    format!("{:<key_w$}", key_name(*k)),
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {label}")),
            ]);
            if i == menu.choice {
                line.style(Style::new().add_modifier(Modifier::REVERSED))
            } else {
                line
            }
        })
        .collect();
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Cyan))
                .padding(ratatui::widgets::Padding::horizontal(1)),
        ),
        rect,
    );
    let entries = (0..menu.entries.len().min(height.saturating_sub(2) as usize))
        .map(|i| {
            (
                Rect { x: rect.x + 1, y: rect.y + 1 + i as u16, width: width.saturating_sub(2), height: 1 },
                i,
            )
        })
        .collect();
    (rect, entries)
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
    let over = e.over.as_ref();
    let row = app.rows.iter().find(|r| r.name == e.name).filter(|_| over.is_none());
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(o) = over {
        lines.extend(wrap(label("override"), indent(), vec![Span::raw(o.describe())], inner));
        lines.push(Line::from(vec![
            label("latest"),
            match app.override_latest(&o.name) {
                Some(v) => Span::raw(v.to_string()),
                None => Span::styled("unknown", dim),
            },
        ]));
        lines.push(Line::default());
    }
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
            // For an override: compared with its value now.
            let (now, same_pin) = match over.and_then(|o| crate::deps::package::parse_spec(&o.value)) {
                Some((p, v)) => (v == version, p == prefix),
                None => (now, same_pin),
            };
            let note = match (now, same_pin) {
                (true, true) if over.is_some() => ", and is what the override has now".to_string(),
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
    let title = if over.is_some() { format!("Override of {}", e.name) } else { format!("Version of {}", e.name) };
    draw_dialog(f, &title, lines, width);
}

/// The ignore `x` adds to `.snyk`: reason, expiry and the paths it covers.
fn draw_ignore_dialog(f: &mut Frame, p: &crate::tui::app::IgnorePrompt) {
    use crate::tui::app::IgnoreField;
    let width = f.area().width.saturating_sub(4).min(80);
    let inner = (width as usize).saturating_sub(4);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);
    let cyan_bold = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let indent = || Span::raw(" ".repeat(10));
    let label = |t: &str, on: bool| Span::styled(format!("{t:<10}"), if on { cyan_bold } else { bold });
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.extend(wrap(label("Finding", false), indent(), vec![Span::raw(format!("{}  {}", p.id, p.title))], inner));
    lines.push(Line::default());
    let on = |f: IgnoreField| p.field == f;
    let reason = field_lines(&p.reason, on(IgnoreField::Reason), bold).into_iter().next().unwrap_or_default();
    lines.extend(wrap(label("Reason", on(IgnoreField::Reason)), indent(), reason, inner));
    let expires = field_lines(&p.expires, on(IgnoreField::Expires), bold).into_iter().next().unwrap_or_default();
    lines.extend(wrap(label("Expires", on(IgnoreField::Expires)), indent(), expires, inner));
    lines.push(Line::from(vec![indent(), Span::styled("YYYY-MM-DD, empty: never", dim)]));
    let path = field_lines(&p.path, on(IgnoreField::Path), bold).into_iter().next().unwrap_or_default();
    lines.extend(wrap(label("Path", on(IgnoreField::Path)), indent(), path, inner));
    lines.push(Line::from(vec![indent(), Span::styled("`*` covers every path", dim)]));
    lines.push(Line::default());
    if let Some(err) = &p.error {
        lines.extend(wrap(Span::raw(""), Span::raw("  "), vec![Span::styled(err.clone(), Style::new().fg(Color::Red))], inner));
        lines.push(Line::default());
    }
    let key = |k: &str, t: &str| {
        vec![
            Span::styled(k.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {t}   ")),
        ]
    };
    let mut keys = key("enter", "save to .snyk");
    keys.extend(key("tab", "next field"));
    if p.editing.is_some() {
        keys.extend(key("ctrl+d", "remove"));
    }
    keys.extend(key("esc", "cancel"));
    lines.push(Line::from(keys));
    let title = if p.editing.is_some() { "Edit ignore in .snyk" } else { "Ignore in .snyk" };
    draw_dialog(f, title, lines, width);
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
    pin: &str,
) -> Vec<(Rect, Vec<KeyEvent>)> {
    use crate::tui::app::{AddAs, PINS};
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
    // How the version is pinned, one choice per option, with each option's column for clicks.
    let mut pin_spans = vec![label("Pin")];
    let mut pin_cols = Vec::new();
    let mut col = 9u16;
    for (prefix, name) in PINS {
        let chosen = prefix == pin;
        let style = if chosen {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        let text = format!("{}{name}   ", if chosen { "● " } else { "○ " });
        pin_cols.push((col, text.chars().count() as u16 - 3));
        col += text.chars().count() as u16;
        pin_spans.push(Span::styled(text, style));
    }
    lines.push(Line::from(pin_spans));
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
    keys.extend(key("←→", "pin"));
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
        // The pin choices are on the line after them, each reached by moving right.
        let at = PINS.iter().position(|(p, _)| *p == pin).unwrap_or(0);
        for (i, (x, w)) in pin_cols.into_iter().enumerate() {
            let r = Rect {
                x: rect.x + 2 + x,
                y: rect.y + 2 + 3 + AddAs::ALL.len() as u16,
                width: w,
                height: 1,
            };
            let right = (i + PINS.len() - at) % PINS.len();
            clicks.push((r, vec![plain(KeyCode::Right); right]));
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
    match crate::registry::registry::cooldown_days() {
        0 => info.push(("cooldown off".to_string(), None)),
        d => info.push((format!("cooldown {d}d"), None)),
    }
    if !app.show_vulns {
        info.push(("vulns hidden".to_string(), Some('v')));
    }
    if app.show_overrides == Overrides::Off {
        info.push(("overrides hidden".to_string(), Some('o')));
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
/// The footer, the clicks of its hints, and how many lines the item hints took. The item hints
/// are given at least the size in `section`.
fn footer_lines(
    app: &App,
    width: u16,
    section: crate::tui::app::ItemSection,
) -> (Vec<Line<'static>>, Vec<Placed>, crate::tui::app::ItemSection) {
    let unused = crate::tui::app::ItemSection { footer_w: width, rows: 0 };
    let prompt = |(l, p): (Vec<Line<'static>>, Vec<Placed>)| (l, p, unused);
    let hint = |t: &str| vec![t.to_string().dark_gray()];
    if app.log_focus {
        let hint = |t: &str, key: Option<KeyCode>| (vec![t.to_string().dark_gray()], key.map(plain));
        return prompt(wrap_atoms(
            Vec::new(),
            vec![
                hint("Home/End oldest/newest", None),
                hint("q quit", Some(KeyCode::Char('q'))),
            ],
            "   ",
            width,
        ));
    }
    if app.input.is_some() {
        return prompt(wrap_keys(
            vec!["Add a package:".cyan().bold()],
            vec![hint("see the dialog above"), hint("enter add"), hint("esc cancel")],
            "   ",
            width,
        ));
    }
    if app.ignore_prompt.is_some() {
        return prompt(wrap_keys(
            vec!["Ignore in .snyk:".cyan().bold()],
            vec![hint("see the dialog above"), hint("enter save"), hint("esc cancel")],
            "   ",
            width,
        ));
    }
    if app.version_edit.is_some() {
        return prompt(wrap_keys(
            vec!["Edit the version:".cyan().bold()],
            vec![hint("← → home end move"), hint("enter install"), hint("esc cancel")],
            "   ",
            width,
        ));
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
        return prompt(wrap_keys(vec!["Commit:".cyan().bold()], keys, "   ", width));
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
        return prompt(wrap_keys(vec!["Answer the dialog above:".cyan().bold()], keys, "   ", width));
    }
    if app.delete_prompt.is_some() {
        return prompt(wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y or enter delete"), hint("any other key cancels")],
            "   ",
            width,
        ));
    }
    if app.peer_fix.is_some() {
        return prompt(wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("↑↓ choose"), hint("enter or 1-9 fix"), hint("any other key cancels")],
            "   ",
            width,
        ));
    }
    if app.peer_prompt.is_some() {
        return prompt(wrap_keys(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y"), hint("n"), hint("any other key cancels")],
            "   ",
            width,
        ));
    }
    if app.pin_prompt {
        let opt = |k: &str, d: &str| vec![k.to_string().bold(), d.to_string().into()];
        return prompt(wrap_keys(
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
        ));
    }
    if app.filter_mode {
        return prompt(wrap_keys(
            vec!["/".cyan().bold(), app.filter.clone().into(), "█".cyan()],
            vec![hint("enter keep"), hint("esc clear")],
            "   ",
            width,
        ));
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
    // The item hints and the scan hints sit side by side. The item hints get a column of a
    // fixed width, so the scan hints stay put as the cursor moves.
    let keyed = |h: &String| {
        let atom = hint(h);
        let key = hint_key(&atom);
        (atom, key)
    };
    let label = |t: &str, on: bool| -> Span<'static> {
        if on { t.to_string().cyan().bold() } else { t.to_string().dark_gray() }
    };
    const SEP: &str = "   ";
    let one_line = |prefix: &str, atoms: &[String]| -> u16 {
        // Leading space, the prefix, then each hint after a separator.
        (1 + prefix.chars().count() + atoms.iter().map(|h| SEP.len() + h.chars().count()).sum::<usize>())
            as u16
    };
    // The scan hints get a column at the right as wide as their longest set (with the `v`
    // toggle, reading "hidden"); the item hints get the rest. Neither depends on the cursor.
    let mut widest_scan = scan.clone();
    widest_scan.retain(|h| !h.starts_with("v "));
    widest_scan.push("v vulns: hidden".to_string());
    let scan_w = one_line("scan:", &widest_scan);
    let item_w = width.saturating_sub(scan_w).max(width / 2);
    let (mut item_lines, item_hits) = wrap_atoms(
        vec![label("item:", !item.is_empty())],
        item.iter().map(keyed).collect(),
        SEP,
        item_w,
    );
    let item_used = item_lines.len();
    let (scan_lines, scan_hits) = if scan.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        wrap_atoms(
            vec![label("scan:", true)],
            scan.iter().map(keyed).collect(),
            SEP,
            width.saturating_sub(item_w),
        )
    };
    let scan_rows = scan_lines.len();
    let rows = item_used.max(scan_rows).max(section.rows);
    item_lines.resize(rows, Line::default());
    for (i, line) in item_lines.iter_mut().enumerate() {
        let w = line.width() as u16;
        if let Some(s) = scan_lines.get(i) {
            line.spans.push(Span::raw(" ".repeat(item_w.saturating_sub(w) as usize)));
            line.spans.extend(s.spans.iter().cloned());
        }
    }
    let mut hits = item_hits;
    hits.extend(scan_hits.into_iter().map(|mut p| {
        p.x += item_w;
        p
    }));
    add((item_lines, hits));
    add(wrap_keys(
        prefix,
        global.iter().map(|h| hint(h)).collect(),
        "   ",
        width,
    ));
    (
        lines,
        placed,
        crate::tui::app::ItemSection { footer_w: width, rows: item_used.max(scan_rows) },
    )
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
    if label == POLICY && members.is_empty() {
        let n = app.ignores.len();
        let unneeded = app
            .ignores
            .iter()
            .filter(|r| app.policy_status(r) == crate::tui::app::PolicyStatus::Unneeded)
            .count();
        let extra = if unneeded > 0 { format!(", {unneeded} no longer needed") } else { String::new() };
        return Line::from(format!("⊘ {label} ({n}{extra}), x edits, d removes"))
            .style(Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD));
    }
    if label == UNNEEDED && members.is_empty() {
        let n = app
            .view
            .iter()
            .filter(|i| matches!(i, Item::Override { .. }))
            .count();
        return Line::from(format!("✂ {label} ({n}), press d to remove"))
            .style(override_style(true));
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

/// The packages the overrides of an overridden package are limited to, when every one of
/// them is limited: `["b"]` for `b > qs`. Empty when one applies everywhere.
fn override_scopes(r: &AppRow) -> Vec<String> {
    if r.kind != Kind::Override || r.overrides.is_empty() || r.overrides.iter().any(|o| o.global()) {
        return Vec::new();
    }
    let mut below: Vec<String> = r.overrides.iter().map(|o| o.path.join(" > ")).collect();
    below.sort();
    below.dedup();
    below
}
/// The name in the list: `b > qs` for a package overridden only below `b`.
fn display_name(r: &AppRow) -> String {
    match override_scopes(r).as_slice() {
        [one] => format!("{one} > {}", r.name),
        _ => r.name.clone(),
    }
}
fn row_line(app: &App, r: &AppRow, indent: usize, name_w: usize, width: usize) -> Line<'static> {
    let mark = match r.status {
        Status::Queued => "…",
        Status::Installing => "⟳",
        Status::Failed if r.selected => "●",
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
    let conflict = r.overrides.iter().any(|o| !app.override_support(o).conflicts.is_empty());
    let (marker, marker_w) = override_marker(r, conflict);
    let mut spans = vec![Span::raw(format!(
        "{mark} {}{:<w$} ",
        " ".repeat(indent),
        display_name(r),
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
    // The installed packages whose declared range the override's version is outside of.
    let mut unsupported: Vec<String> = r
        .overrides
        .iter()
        .flat_map(|o| app.override_support(o).conflicts)
        .collect();
    unsupported.sort();
    unsupported.dedup();
    if !unsupported.is_empty() {
        let used: usize = spans.iter().map(|s| s.width()).sum();
        let full = format!("   ⚠ unsupported by {}", unsupported.join(", "));
        let text = if used + full.chars().count() < width {
            full
        } else {
            format!("   ⚠ unsupported by {} package{}", unsupported.len(), if unsupported.len() == 1 { "" } else { "s" })
        };
        spans.push(Span::styled(text, conflict_style()));
    }
    // An overridden package whose overrides are limited to several other packages: say where.
    // (Limited to one, the name says it: `b > qs`.)
    let below = override_scopes(r);
    if below.len() > 1 {
        spans.push(Span::styled(format!("   only below {}", below.join(", ")), override_style(false)));
    }
    for (label, fix) in [("snyk", &r.snyk_fix), ("audit", &r.audit_fix)] {
        if let Some(fix) = fix {
            spans.push(Span::styled(
                format!("   {label} fix: {}{fix}", r.prefix),
                Style::new().fg(Color::Magenta),
            ));
            spans.extend(rejected_span(&app.upgrade_rejecters(&r.name, fix)));
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
        // An override forcing the peer is the cause, and `f` offers to remove it.
        let forced = if app.peer_culprits(r).is_empty() { "" } else { " (forced by an override, f to fix)" };
        let full = format!("   ⚠ unmet peer{s}: {}{forced}", unmet.join(", "));
        let text = if used + full.chars().count() < width {
            full
        } else {
            format!("   ⚠ {} unmet peer{s}{forced}", unmet.len())
        };
        spans.push(Span::styled(
            text,
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    // Overrides in the tree that force a version outside what the parent asked for. The
    // nested override lines say so when they are shown.
    if app.show_overrides == Overrides::Off {
        let conflicts: Vec<String> = r
            .tree_hits
            .iter()
            .filter(|h| h.risk == Compat::Conflict)
            .map(|h| {
                let parent = match h.via.len() {
                    0 | 1 => r.name.as_str(),
                    n => h.via[n - 2].as_str(),
                };
                let have = match &h.installed {
                    Some(v) => v.to_string(),
                    None => h.over.value.clone(),
                };
                format!("{parent} wants {} {}, has {have}", h.over.name, h.requested)
            })
            .collect();
        if !conflicts.is_empty() {
            let used: usize = spans.iter().map(|s| s.width()).sum();
            let full = format!("   ⚠ {}", conflicts.join(", "));
            let text = if used + full.chars().count() < width {
                full
            } else {
                let n = conflicts.len();
                format!("   ⚠ {n} override{} outside the wanted range", if n == 1 { "" } else { "s" })
            };
            spans.push(Span::styled(text, conflict_style()));
        }
    }
    // A package the lockfile lists without a checksum can't be verified when installed. Shown
    // with the details panel, which says more about it.
    if app.show_info && app.info.get(&r.name).is_some_and(|(_, i)| i.missing_integrity) {
        spans.push(Span::styled(
            "   ⚠ no integrity checksum",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    if app.show_info
        && let Some(o) = app.package_origin(&r.name)
    {
        spans.push(origin_span(o));
    }
    // The engines the installed copy wants and the tools here don't have.
    let engines: Vec<String> = app
        .engine_problems(&r.name)
        .into_iter()
        .map(|p| format!("{} {} (has {})", p.tool, p.range, p.have))
        .collect();
    if !engines.is_empty() {
        let used: usize = spans.iter().map(|s| s.width()).sum();
        let full = format!("   ⚠ needs {}", engines.join(", "));
        let text = if used + full.chars().count() < width {
            full
        } else {
            format!("   ⚠ engine mismatch: {}", engines.len())
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

/// Who committed an item and when, for the list while the details panel is on.
fn origin_span(o: &crate::deps::blame::Origin) -> Span<'static> {
    Span::styled(format!("   {}", o.label()), Style::new().fg(Color::DarkGray))
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

/// Overrides are cyan, so they aren't taken for vulnerabilities (magenta, red, yellow and
/// blue by severity). A conflict is bold, and its symbol (⚠) says it is a problem.
const OVERRIDE: Color = Color::Cyan;
fn override_style(conflict: bool) -> Style {
    let s = Style::new().fg(OVERRIDE);
    if conflict { s.add_modifier(Modifier::BOLD) } else { s }
}
/// A version the packages above don't support: bold bright red. Text colour only, since a
/// background has poor contrast on many terminal themes; the `⚠` in front and the bright
/// shade tell it apart from the plain red of high severity.
fn conflict_style() -> Style {
    // Not dimmed with the rest of an up-to-date row.
    Style::new()
        .fg(Color::LightRed)
        .add_modifier(Modifier::BOLD)
        .remove_modifier(Modifier::DIM)
}
fn compat_style(c: Compat) -> Style {
    override_style(c == Compat::Conflict)
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
fn override_marker(r: &AppRow, conflict: bool) -> (Vec<Span<'static>>, usize) {
    let mut spans = Vec::new();
    let mut width = 0;
    // An override that forces a version outside what its dependents declare is shown even where
    // the override itself isn't listed under the package.
    let c = if conflict { Compat::Conflict } else { r.compat };
    if !r.overrides.is_empty() && (r.lists_own_overrides() || conflict) {
        let style = if c == Compat::Conflict { conflict_style() } else { compat_style(c) };
        spans.push(Span::styled(compat_symbol(c), style));
        width += 1;
    }
    if !r.tree_hits.is_empty() {
        let risky = r.tree_hits.iter().any(|h| h.risk == Compat::Conflict);
        spans.push(Span::styled("↳", if risky { conflict_style() } else { override_style(false) }));
        width += 1;
    }
    // ✗: `npm ls` would report this package or something below it as invalid or missing.
    if !r.invalid.is_empty() {
        spans.push(Span::styled("✗", Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)));
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
        Child::Vuln(_) | Child::Ignored(_) | Child::Invalid(_) => None,
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

    // The parts of the line about a version the packages above don't support.
    let (mut rest_alert, mut tail_alert) = (false, false);
    let (text, tail, color) = match child {
        Child::Own(i) => {
            let o = &r.overrides[i];
            let (c, note) = own_override_note(app, r, o);
            let tail = if note.is_empty() {
                String::new()
            } else {
                format!("  ({note})")
            };
            tail_alert = c == Compat::Conflict;
            (
                format!("{} {}", compat_symbol(c), o.describe()),
                tail,
                compat_style(c),
            )
        }
        Child::Tree(i) => {
            let h = &r.tree_hits[i];
            let color = override_style(h.risk == Compat::Conflict);
            // Would the new override value still satisfy the parent's declared range?
            let mut tail = String::new();
            if let Some(u) = &update {
                let mut moved = h.over.clone();
                moved.value = u.value.clone();
                if tree::risk(&moved, &h.requested) == Compat::Conflict {
                    tail = format!("  ⚠ outside {} wanted by the parent", h.requested);
                }
            }
            (rest_alert, tail_alert) = (h.risk == Compat::Conflict, !tail.is_empty());
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
            // A finding a `.snyk` rule covers is dimmed, even before a scan moves it away.
            let color = if app.ignore_for(v).is_some() { Color::DarkGray } else { severity_color(v.severity) };
            (t, String::new(), Style::new().fg(color))
        }
        Child::Invalid(i) => {
            let inv = &r.invalid[i];
            let peer = if inv.peer { "peer " } else { "" };
            let t = match &inv.installed {
                Some(v) => format!("✗ invalid {peer}dependency: {}@{v} (wants {})", inv.name, inv.range),
                None => format!("✗ missing {peer}dependency: {}@{}", inv.name, inv.range),
            };
            (t, format!("  required by {}", inv.by.join(" > ")), Style::new().fg(Color::Red))
        }
        Child::Ignored(i) => {
            let v = &r.ignored[i];
            let mut t = format!("⊘ {:<8} [{}] {}  {}", v.severity.label(), v.source.label(), v.id, v.title);
            t.push_str(&format!("  · {}@{}", v.package, v.version));
            if v.path.len() > 1 {
                t.push_str(&format!(" via {}", v.path[..v.path.len() - 1].join(" > ")));
            }
            let why = match app.ignores.iter().find(|r| r.covers(v)) {
                Some(rule) => {
                    let until = rule
                        .expires
                        .as_deref()
                        .and_then(|e| e.get(..10))
                        .map(|d| format!(" until {d}"))
                        .unwrap_or_default();
                    let reason = if rule.reason.is_empty() { String::new() } else { format!(": {}", rule.reason) };
                    format!("{until}{reason}")
                }
                None => String::new(),
            };
            (t, format!("  · ignored in .snyk{why}"), Style::new().fg(Color::DarkGray))
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
        Span::styled(head, color),
    ];
    spans.extend(new_value);
    let alert = |on: bool| if on { conflict_style() } else { color };
    spans.push(Span::styled(rest, alert(rest_alert)));
    spans.push(Span::styled(tail, alert(tail_alert)));
    if let Child::Vuln(i) = child {
        spans.extend(ignore_spans(app, &r.vulns[i]));
        spans.extend(override_spans(app, &r.vulns[i]));
        spans.extend(accepted_span(app, &r.vulns[i]));
        spans.extend(fix_spans(app, r, &r.vulns[i]));
    }
    if app.show_info
        && let Some(origin) = o.and_then(|o| app.override_origin(o))
    {
        spans.push(origin_span(origin));
    }
    if let Some(reason) = unneeded {
        spans.push(Span::styled(
            format!("  ✂ may be removed: {reason}"),
            override_style(false),
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
/// An ignore rule of `.snyk` in the list: what it ignores, where, until when and why.
fn policy_lines(app: &App, id: &str, path: &str, width: usize) -> Vec<Line<'static>> {
    let Some(rule) = app.policy_rule(id, path) else {
        return vec![Line::from(id.to_string())];
    };
    let expired = rule.expired(&crate::security::policy::today());
    let color = if expired { Color::DarkGray } else { Color::Magenta };
    let until = match rule.expires.as_deref().and_then(|e| e.get(..10)) {
        Some(d) if expired => format!("expired {d}"),
        Some(d) => format!("until {d}"),
        None => "no expiry".to_string(),
    };
    let reason = if rule.reason.is_empty() { "no reason" } else { &rule.reason };
    let title = app
        .rows
        .iter()
        .flat_map(|r| &r.vulns)
        .find(|v| v.id == id)
        .map(|v| format!("  {}", v.title))
        .unwrap_or_default();
    use crate::tui::app::PolicyStatus;
    let (note, note_style) = match app.policy_status(rule) {
        PolicyStatus::Needed => ("  ✔ still needed", Style::new().fg(Color::Green)),
        PolicyStatus::Unneeded => (
            "  ✂ no longer needed: Snyk finds nothing it covers, press d to remove",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        PolicyStatus::Unknown => ("  ? run Snyk (s) to check", Style::new().fg(Color::DarkGray)),
    };
    let mut spans = vec![
        Span::styled(
            format!("{id}{title}  · on {path}  · {until}  · {reason}"),
            Style::new().fg(color),
        ),
        Span::styled(note, note_style),
    ];
    if app.show_info
        && let Some(o) = app.policy_origin(id, path)
    {
        spans.push(origin_span(o));
    }
    wrap(Span::styled("  ⊘ ", Style::new().fg(color)), Span::raw("    "), spans, width)
}
/// `fixed by override` on a finding whose vulnerable package an override already pins to a
/// fixed version. A scan that still lists it means the override isn't what is installed yet.
fn override_spans(app: &App, v: &crate::security::vuln::Vuln) -> Vec<Span<'static>> {
    let Some(o) = app.vuln_override(v) else {
        return Vec::new();
    };
    let (text, style) = if app.snyk.stale {
        (
            format!("  ✔ fixed by override {} → {}: scan again to confirm", o.name, o.value),
            Style::new().fg(Color::Green),
        )
    } else {
        (
            format!("  ⚠ override {} → {} is set, but the last scan still lists this: reinstall, then scan again", o.name, o.value),
            override_style(true),
        )
    };
    vec![Span::styled(text, style)]
}
/// `ignored in .snyk` on a finding a `.snyk` rule covers.
fn ignore_spans(app: &App, v: &crate::security::vuln::Vuln) -> Vec<Span<'static>> {
    let Some(rule) = app.ignore_for(v) else {
        return Vec::new();
    };
    let until = rule
        .expires
        .as_deref()
        .and_then(|e| e.get(..10))
        .map(|d| format!(" until {d}"))
        .unwrap_or_default();
    vec![Span::styled(
        format!("  ⊘ ignored in .snyk{until}"),
        Style::new().fg(Color::Magenta),
    )]
}
/// `⚠ not accepted by mid@1.0.0 (wants 6.0.0)` after a suggested fix that installed packages
/// declare they don't support. Nothing when there are none.
fn rejected_span(who: &[String]) -> Option<Span<'static>> {
    (!who.is_empty()).then(|| {
        Span::styled(
            format!("  ⚠ not accepted by {}", who.join(", ")),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    })
}
/// `⚠ overrides the range of mid@1.0.0 (wants ~6.7.0)` after an override that is outside what
/// the packages it applies to declare. The override is limited to the package the finding is
/// under (see `pin_where`), so these are the packages it changes, not unrelated ones.
fn pin_conflict_span(who: &[String]) -> Option<Span<'static>> {
    (!who.is_empty()).then(|| {
        Span::styled(
            format!("  ⚠ overrides the range of {}", who.join(", ")),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    })
}
/// `· dependents accept ^5.0.0, ~6.7.0` on a finding in a package that something else brings
/// in: the versions of it that the packages above it declare they work with.
fn accepted_span(app: &App, v: &crate::security::vuln::Vuln) -> Option<Span<'static>> {
    let ranges = app.accepted_ranges(v);
    if ranges.is_empty() {
        return None;
    }
    let shown = match ranges.len() > 4 {
        true => format!("{}, … +{}", ranges[..4].join(", "), ranges.len() - 4),
        false => ranges.join(", "),
    };
    Some(Span::styled(
        format!("  · dependents accept {shown}"),
        Style::new().fg(Color::DarkGray),
    ))
}
fn fix_spans(app: &App, r: &AppRow, v: &crate::security::vuln::Vuln) -> Vec<Span<'static>> {
    let fixable = Style::new().fg(Color::Green).add_modifier(Modifier::BOLD);
    if let Some(to) = app.vuln_install_fix(r, v) {
        let mut spans = vec![
            Span::raw("  "),
            Span::styled(format!("⬆ fix: i installs {} {}{to}", r.name, r.prefix), fixable),
        ];
        spans.extend(rejected_span(&app.upgrade_rejecters(&r.name, &to)));
        spans.push(Span::styled(format!("  ({})", v.fix_summary()), Style::new().fg(Color::DarkGray)));
        return spans;
    }
    if let Some(to) = app.vuln_pin_fix(v) {
        let mut spans = vec![
            Span::raw("  "),
            Span::styled(format!("⬆ fix: p overrides {} to {}{to}{}", v.package, app.default_prefix(), app.pin_where(v)), fixable),
        ];
        spans.extend(pin_conflict_span(&app.pin_fix_rejecters(v)));
        spans.push(Span::styled(
            format!("  (upgrading {} doesn't bring it in)", r.name),
            Style::new().fg(Color::DarkGray),
        ));
        return spans;
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
        Span::styled("✂ ", override_style(false)),
        Span::styled(o.describe(), override_style(false)),
        Span::styled(format!("   {reason}"), Style::new().fg(Color::DarkGray)),
    ];
    let mut spans = spans;
    if app.show_info
        && let Some(origin) = app.override_origin(o)
    {
        spans.push(origin_span(origin));
    }
    wrap(Span::raw("  "), Span::raw("      "), spans, width)
}

/// What the packages an override reaches declare for the overridden package, as a note, and
/// whether the override is outside what some of them declare:
/// `conflicts with body-parser@1.19.0 (wants ~6.7.0); dependents accept ~6.7.0, ^6.0.0`.
fn support_note(app: &App, o: &Override) -> (bool, String) {
    fn some(items: &[String], max: usize) -> String {
        match items.len() > max {
            true => format!("{}, … +{}", items[..max].join(", "), items.len() - max),
            false => items.join(", "),
        }
    }
    let s = app.override_support(o);
    if s.ranges.is_empty() {
        return (false, String::new());
    }
    let accepted = format!("dependents accept {}", some(&s.ranges, 4));
    if s.conflicts.is_empty() {
        (false, accepted)
    } else {
        (true, format!("conflicts with {}; {accepted}", some(&s.conflicts, 3)))
    }
}
/// Compatibility of `o` with what the packages it reaches declare, and of the update of `r`
/// with its own override, with a short explanation of both.
fn own_override_note(app: &App, r: &AppRow, o: &Override) -> (Compat, String) {
    let (mut c, mut note) = update_note(app, r, o);
    let (conflict, support) = support_note(app, o);
    if conflict {
        c = Compat::Conflict;
    }
    if !support.is_empty() {
        if !note.is_empty() {
            note.push_str("; ");
        }
        note.push_str(&support);
    }
    (c, note)
}
fn update_note(app: &App, r: &AppRow, o: &Override) -> (Compat, String) {
    // Overridden packages aren't dependencies, so there is no dependency spec to clash with.
    // `b > qs` already says where it applies.
    if r.kind == Kind::Override {
        return (Compat::Ok, String::new());
    }
    let c = overrides::check(std::slice::from_ref(o), app.pm, &r.new_spec(), &r.latest);
    // Up-to-date packages have no pending update to be compatible with.
    let note = if !o.path.is_empty() {
        format!("only applies below {}", o.path.join(" > "))
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
/// Rows of content the details panel shows at most; more scroll.
const INFO_LINES: u16 = 12;
/// Rows of content the details panel shows on a small screen.
const INFO_MIN_LINES: u16 = 6;

/// Text summary of the overrides of the highlighted package, wrapped to `width`. Shown in
/// place of the nested lists when those are hidden.
fn summary_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Vec::new();
    };
    let r = &app.rows[*idx];
    let mut spans: Vec<Span<'static>> = Vec::new();
    // An override that isn't listed under its package is still told about when the packages it
    // reaches declare something to compare it with.
    for o in r
        .overrides
        .iter()
        .filter(|o| r.lists_own_overrides() || !app.override_support(o).ranges.is_empty())
    {
        let (c, note) = own_override_note(app, r, o);
        let mut text = format!("{} {}", compat_symbol(c), o.describe());
        if let Some(u) = app.update_target(o) {
            text.push_str(&format!(" ⇢ {}", u.value));
        }
        spans.push(Span::styled(text, compat_style(c)));
        if !note.is_empty() {
            let style = if c == Compat::Conflict { conflict_style() } else { compat_style(c) };
            spans.push(Span::styled(format!(" ({note})"), style));
        }
        let mut text = String::new();
        if let Some(u) = app.unneeded(o) {
            text.push_str(&format!(" ✂ may be removed: {}", u.reason(o)));
        }
        text.push_str("   ");
        spans.push(Span::styled(text, compat_style(c)));
    }
    if !r.tree_hits.is_empty() {
        // Risky hits come first.
        let shown: Vec<String> = r
            .tree_hits
            .iter()
            .map(|h| match app.unneeded(&h.over) {
                Some(u) => format!("{} ✂ may be removed: {}", hit_text(h), u.reason(&h.over)),
                None => hit_text(h),
            })
            .collect();
        let text = format!("↳ overrides in dependency tree: {}", shown.join(", "));
        let risky = r.tree_hits.iter().any(|h| h.risk == Compat::Conflict);
        spans.push(Span::styled(text, override_style(risky)));
    }
    if spans.is_empty() {
        return Vec::new();
    }

    let lines = wrap(Span::raw(" "), Span::raw(" "), spans, width);
    lines
}

/// For the package under the cursor: what its installed copy and the lockfile say about it.
/// `None` while it is being read.
fn package_lines(
    info: Option<&crate::deps::info::Info>,
    tools: &std::collections::BTreeMap<String, semver::Version>,
    width: usize,
) -> Vec<Line<'static>> {
    use crate::deps::info::{InstallScripts, human_size};
    let dim = Style::new().fg(Color::DarkGray);
    let (cyan, yellow, red) = (
        Style::new().fg(Color::Cyan),
        Style::new().fg(Color::Yellow),
        Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
    );
    let Some(i) = info else {
        // The rows the details will take, so the rest of the panel doesn't move when they
        // arrive.
        return ["install scripts …", "installed …", "engines … · platform …", "integrity …", "dependencies …"]
            .iter()
            .map(|t| Line::from(Span::styled(t.to_string(), dim)))
            .collect();
    };
    let mut lines = Vec::new();
    let mut add = |spans: Vec<Span<'static>>| {
        lines.extend(wrap(Span::raw(""), Span::raw("  "), spans, width));
    };
    if let Some(msg) = &i.deprecated {
        add(vec![Span::styled("⚠ deprecated: ", red), Span::styled(msg.clone(), red)]);
    }
    match &i.install {
        InstallScripts::Some(scripts) if scripts.is_empty() => add(vec![Span::styled(
            format!("⚠ runs install scripts (says {})", i.lockfile.unwrap_or("the lockfile")),
            yellow,
        )]),
        InstallScripts::Some(scripts) => {
            let list: Vec<String> = scripts.iter().map(|(s, c)| format!("{s}: {c}")).collect();
            add(vec![
                Span::styled("⚠ install scripts: ", yellow),
                Span::styled(list.join(", "), yellow),
            ]);
        }
        InstallScripts::None => add(vec![Span::styled("no install scripts", dim)]),
        InstallScripts::Unknown => add(vec![Span::styled("not installed: nothing to read", dim)]),
    }
    // What it is: version, size, files.
    let mut what = Vec::new();
    if let Some(v) = &i.version {
        what.push(format!("installed {v}"));
    }
    if let Some((bytes, files)) = i.size {
        what.push(format!("{} in {files} file{}", human_size(bytes), if files == 1 { "" } else { "s" }));
    }
    if !what.is_empty() {
        add(vec![Span::styled(what.join(" · "), cyan)]);
    }
    // Where it runs. Each engine is checked against the version installed here; only one that
    // doesn't fit says what is installed.
    let mut runs: Vec<Span<'static>> = Vec::new();
    if !i.engines.is_empty() {
        runs.push(Span::styled("engines: ", cyan));
        for (n, (tool, range)) in i.engines.iter().enumerate() {
            if n > 0 {
                runs.push(Span::styled(", ", cyan));
            }
            let have = tools.get(tool);
            match have.and_then(|v| crate::deps::overrides::satisfies(range, v).map(|ok| (v, ok))) {
                Some((v, false)) => runs.push(Span::styled(
                    format!("⚠ {tool} {range}, but {v} is installed"),
                    yellow.add_modifier(Modifier::BOLD),
                )),
                // A fitting or unchecked engine is just listed.
                _ => runs.push(Span::styled(format!("{tool} {range}"), cyan)),
            }
        }
        runs.push(Span::styled(" · ", cyan));
    }
    if i.platform.is_empty() {
        runs.push(Span::styled("platform: any", cyan));
    } else {
        let p: Vec<String> = i.platform.iter().map(|(k, v)| format!("{k} {}", v.join(", "))).collect();
        runs.push(Span::styled(format!("platform: {}", p.join("; ")), cyan));
    }
    add(runs);
    match (&i.integrity, i.lockfile) {
        (Some(sum), Some(file)) => {
            // `sha512-` and enough of the hash to tell it apart.
            let short: String = match sum.split_once('-') {
                Some((alg, hash)) => format!("{alg}-{}…", hash.chars().take(12).collect::<String>()),
                None => sum.chars().take(20).collect(),
            };
            add(vec![Span::styled(format!("integrity: {short} ({file})"), cyan)]);
        }
        (None, Some(file)) if i.missing_integrity => {
            let fix = if file == "package-lock.json" {
                ", I adds the registry's"
            } else {
                ", `pnpm install --fix-lockfile` adds it"
            };
            add(vec![Span::styled(format!("⚠ no integrity checksum in {file}{fix}"), yellow)])
        }
        (None, Some(file)) => add(vec![Span::styled(format!("integrity: none, not in {file} as a download"), dim)]),
        (_, None) => add(vec![Span::styled("integrity: no npm or pnpm lockfile to read", dim)]),
    }
    if i.dependencies.is_empty() {
        add(vec![Span::styled("no dependencies", dim)]);
    } else {
        let list: Vec<String> = i.dependencies.iter().map(|(n, r)| format!("{n} {r}")).collect();
        add(vec![
            Span::styled(format!("{} dependenc{}: ", list.len(), if list.len() == 1 { "y" } else { "ies" }), cyan),
            Span::styled(list.join(", "), cyan),
        ]);
    }
    if let Some(c) = &i.since_commit {
        let from = c.from.as_ref().map(|v| format!(" ({v} then)")).unwrap_or_default();
        if c.is_empty() {
            add(vec![Span::styled(format!("dependencies unchanged since the last commit{from}"), dim)]);
        } else {
            let mut parts: Vec<Span<'static>> =
                vec![Span::styled(format!("since the last commit{from}: "), cyan)];
            let mut items: Vec<Span<'static>> = Vec::new();
            for (n, r) in &c.added {
                items.push(Span::styled(format!("+ {n} {r}"), Style::new().fg(Color::Green)));
            }
            for (n, _) in &c.removed {
                items.push(Span::styled(format!("− {n}"), Style::new().fg(Color::Red)));
            }
            for (n, o, r) in &c.changed {
                items.push(Span::styled(format!("{n} {o} → {r}"), yellow));
            }
            for (k, it) in items.into_iter().enumerate() {
                if k > 0 {
                    parts.push(Span::raw(", "));
                }
                parts.push(it);
            }
            add(parts);
        }
    }
    lines
}
/// For the vulnerability under the cursor: what it is, where it comes in, and how to fix it.
fn vuln_lines(app: &App, r: &AppRow, v: &crate::security::vuln::Vuln, width: usize) -> Vec<Line<'static>> {
    let cyan = Style::new().fg(Color::Cyan);
    let dim = Style::new().fg(Color::DarkGray);
    let mut lines = Vec::new();
    let mut add = |spans: Vec<Span<'static>>| {
        lines.extend(wrap(Span::raw(""), Span::raw("  "), spans, width));
    };
    add(vec![
        Span::styled(
            format!("✱ {}", v.severity.label()),
            Style::new().fg(severity_color(v.severity)).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {}", v.title)),
        Span::styled(format!("  (found by {})", v.source.label()), dim),
    ]);
    // Where it comes in: the vulnerable package, and the chain from the direct dependency.
    let mut chain = vec![match &v.direct_version {
        Some(dv) => format!("{}@{dv}", v.direct),
        None => v.direct.clone(),
    }];
    chain.extend(v.path.iter().cloned());
    let at = if v.path.is_empty() {
        format!("in {}@{}, a direct dependency", v.package, v.version)
    } else {
        format!("in {}@{} via {}", v.package, v.version, chain.join(" > "))
    };
    add(vec![Span::styled(at, cyan)]);
    let mut facts = Vec::new();
    if let Some(range) = &v.range {
        facts.push(format!("affected: {range}"));
    }
    // For a direct dependency the fix line below says the same.
    let fixes = v.newer_fixes();
    if !v.path.is_empty() && !fixes.is_empty() {
        facts.push(format!("fixed in {} {}", v.package, fixes.join(", ")));
    }
    if !v.cve.is_empty() {
        facts.push(v.cve.join(", "));
    }
    if !facts.is_empty() {
        add(vec![Span::styled(facts.join(" · "), cyan)]);
    }
    if let Some(rule) = app.ignore_for(v) {
        let mut spans = ignore_spans(app, v);
        if let Some(first) = spans.first_mut() {
            first.content = first.content.trim_start().to_string().into();
        }
        let why = if rule.reason.is_empty() { "no reason given".to_string() } else { rule.reason.clone() };
        spans.push(Span::styled(format!(" · on {} · {why}", rule.path), dim));
        add(spans);
    }
    if let Some(o) = app.vuln_override(v) {
        let mut spans = override_spans(app, v);
        if let Some(first) = spans.first_mut() {
            first.content = first.content.trim_start().to_string().into();
        }
        spans.push(Span::styled(format!(" · {}", o.source), dim));
        add(spans);
    }
    // What the keys do about it, as on the finding's line in the list.
    let mut fix = fix_spans(app, r, v);
    if let Some(first) = fix.first_mut() {
        first.content = first.content.trim_start().trim_start_matches("· ").to_string().into();
    }
    fix.retain(|s| !s.content.is_empty());
    add(fix);
    let url = if v.id.starts_with("SNYK-") {
        Some(format!("https://security.snyk.io/vuln/{}", v.id))
    } else if v.id.starts_with("GHSA-") {
        Some(format!("https://github.com/advisories/{}", v.id))
    } else {
        v.cve.first().map(|c| format!("https://nvd.nist.gov/vuln/detail/{c}"))
    };
    match url {
        Some(u) => add(vec![Span::styled(format!("{} · {u}", v.id), dim)]),
        None => add(vec![Span::styled(v.id.clone(), dim)]),
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
    wrap_hints(Vec::new(), atoms, ", ", width)
}
/// For the package under the cursor: the peer dependencies its installed copy declares, and
/// the version of each the project has.
fn peer_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Vec::new();
    };
    let row = &app.rows[*idx];
    let peers = &row.peers;
    if peers.is_empty() {
        return Vec::new();
    }
    let culprits = app.peer_culprits(row);
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
                (Some(false), Some(have)) => {
                    let by = match culprits.iter().find(|o| o.name == p.name) {
                        Some(o) => format!(", forced by {} (f removes it)", o.describe()),
                        None => String::new(),
                    };
                    Span::styled(format!("{} {}, but {have} is installed{by}", p.name, p.range), yellow)
                }
                (_, Some(have)) => Span::styled(format!("{} {} ({have})", p.name, p.range), cyan),
                (_, None) => Span::styled(format!("{} {} (not installed)", p.name, p.range), cyan),
            }]
        })
        .collect();
    atoms[0].insert(0, Span::styled(label, cyan));
    wrap_hints(Vec::new(), atoms, ", ", width)
}


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
