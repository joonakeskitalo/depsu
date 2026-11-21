use crate::app::{App, VersionRange, Row as AppRow, ScanStatus, Status, scan_key};
use crate::overrides::{self, Compat, Override};
use crate::package::Kind;
use crate::pm::Pm;
use crate::tree::{self, Hit};
use crate::view::{Child, GroupBy, Item, Overrides, Release, UNNEEDED};
use crate::vuln::{Severity, Source};
use ratatui::Frame;
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
/// The expanded, scrollable log that replaces the package list.
fn draw_log(f: &mut Frame, app: &mut App) {
    let hint = |t: &str| vec![t.to_string().dark_gray()];
    let footer = wrap_hints(
        Vec::new(),
        vec![
            hint("↑/↓ scroll"),
            hint("PgUp/PgDn page"),
            hint("Home/End oldest/newest"),
            hint("tab or esc back to list"),
            hint("q quit"),
        ],
        "   ",
        inner_width(f),
    );
    let header_lines = header_lines(app, f.area().width);
    let [header, log_rule, body, keys_rule, help] = Layout::vertical([
        Constraint::Length(header_lines.len() as u16),
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(footer.len() as u16),
    ])
    .areas(f.area());
    let (body, help) = (pad(body), pad(help));
    let h = (body.height as usize).max(1);
    app.log_page = h;
    app.log_scroll = app.log_scroll.min(app.log.len().saturating_sub(h));
    let end = app.log.len() - app.log_scroll;
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = app.log[start..end].iter().map(|l| log_line(l)).collect();
    let title = if app.log_scroll > 0 {
        format!("log (↑{} older)", app.log_scroll)
    } else {
        "log".to_string()
    };
    f.render_widget(Paragraph::new(header_lines), header);
    heading(f, log_rule, title);
    f.render_widget(Paragraph::new(lines), body);
    f.render_widget(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::new().fg(Color::DarkGray)),
        keys_rule,
    );
    f.render_widget(Paragraph::new(footer), help);
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
pub fn draw(f: &mut Frame, app: &mut App) {
    let log_h = (app.log.len() as u16).clamp(1, 5);
    if app.log_focus {
        return draw_log(f, app);
    }
    let footer = footer_lines(app, inner_width(f));
    let header_lines = header_lines(app, f.area().width);
    let used_by_lines = if app.show_info {
        let mut lines = used_by_lines(app, inner_width(f));
        lines.extend(peer_lines(app, inner_width(f)));
        lines
    } else {
        Vec::new()
    };
    let summary_h = if app.show_info {
        SUMMARY_LINES
    } else {
        0
    };
    let [header, list_rule, body, info_rule, used_by, summary, log_rule, log, keys_rule, help] =
        Layout::vertical([
        Constraint::Length(header_lines.len() as u16),
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(if app.show_info { 2 } else { 0 }),
        Constraint::Length(if app.show_info { used_by_lines.len().max(1) as u16 } else { 0 }),
        Constraint::Length(summary_h),
        Constraint::Length(2),
        Constraint::Length(log_h),
        Constraint::Length(1),
        Constraint::Length(footer.len() as u16),
    ])
    .areas(f.area());

    let (body, used_by, summary, log, help) = (pad(body), pad(used_by), pad(summary), pad(log), pad(help));
    f.render_widget(Paragraph::new(header_lines), header);
    heading(f, list_rule, "packages");

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
    let list = List::new(items)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, body, &mut app.table);
    let info_title = match app.cursor_item() {
        Some(Item::Row { idx, .. }) => format!("selected: {}", app.rows[*idx].name),
        Some(Item::Removed { name }) => format!("selected: {name}"),
        _ => "selected".to_string(),
    };
    if app.show_info {
        heading(f, info_rule, info_title);
        f.render_widget(Paragraph::new(used_by_lines), used_by);
    }
    if summary_h > 0 {
        f.render_widget(
            Paragraph::new(summary_lines(app, summary.width as usize)),
            summary,
        );
    }

    let lines: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(log_h as usize)
        .rev()
        .map(|l| log_line(l))
        .collect();
    heading(f, log_rule, "log");
    f.render_widget(Paragraph::new(lines), log);
    f.render_widget(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::new().fg(Color::DarkGray)),
        keys_rule,
    );

    f.render_widget(Paragraph::new(footer), help);
    if let Some(p) = &app.peer_prompt {
        draw_peer_prompt(f, p);
    }
    if let Some(p) = &app.peer_fix {
        draw_peer_fix(f, p);
    }
    if let Some(p) = &app.delete_prompt {
        draw_delete_prompt(f, app, p);
    }
    if let Some(p) = &app.blocked_prompt {
        draw_blocked_prompt(f, p);
    }
    if let Some(input) = &app.input
        && let crate::app::InputPurpose::Add { add_as } = &input.purpose
    {
        draw_add_dialog(f, app, input, *add_as);
    }
}

/// Versions the registry refuses to hand out, and what it hands out instead.
fn draw_blocked_prompt(f: &mut Frame, p: &crate::app::BlockedPrompt) {
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
    let found: Vec<&crate::blocked::Blocked> =
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
fn draw_delete_prompt(f: &mut Frame, app: &App, p: &crate::app::DeletePrompt) {
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
fn draw_peer_fix(f: &mut Frame, p: &crate::app::PeerFix) {
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
    for (i, o) in p.options.iter().enumerate() {
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
    draw_dialog(f, &format!("Fix the peers of {}", p.name), lines, width);
}

/// A box in the middle of the screen with `lines` and `title`, at most `max_width` wide.
fn draw_dialog(f: &mut Frame, title: &str, mut lines: Vec<Line<'static>>, width: u16) {
    let area = f.area();
    // Taller than the screen: cut the middle, keeping the last line, which says which keys
    // to press.
    let room = (area.height as usize).saturating_sub(4);
    if lines.len() > room && room >= 2 {
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
}

/// The dialog for adding a package (`+`): its name and what to add it as.
fn draw_add_dialog(f: &mut Frame, app: &App, input: &crate::app::Input, add_as: crate::app::AddAs) {
    use crate::app::AddAs;
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
        crate::pm::Pm::Yarn => "resolutions",
        crate::pm::Pm::Pnpm => "pnpm.overrides",
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
    draw_dialog(f, "Add a package", lines, width);
}

/// The question about other packages an install needs changed, in a box in the middle of the
/// screen.
fn draw_peer_prompt(f: &mut Frame, p: &crate::app::PeerPrompt) {
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

fn header_lines(app: &App, width: u16) -> Vec<Line<'static>> {
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
    let mut info: Vec<String> = vec![
        app.project_name(),
        app.pm.name().to_string(),
        app.registry.clone(),
        state,
    ];
    if app.group_by != GroupBy::None {
        info.push(format!("group: {}", app.group_by.label()));
    }
    if !app.show_vulns {
        info.push("vulns hidden".to_string());
    }
    if app.show_overrides != Overrides::Off {
        info.push(format!("overrides: {}", app.show_overrides.label()));
    }
    if !app.show_uptodate {
        info.push("up-to-date hidden".to_string());
    }
    let audit_source = app.audit_source();
    for (source, scan) in [(Source::Snyk, &app.snyk), (audit_source, &app.audit)] {
        let label = source.label();
        match scan.status {
            ScanStatus::NotRun => {}
            ScanStatus::Running => info.push(format!("{label}: scanning…")),
            ScanStatus::Failed => info.push(format!("{label}: failed (see log)")),
            ScanStatus::Done { total: 0, .. } => info.push(format!("{label}: clean")),
            ScanStatus::Done { total, severe } => info.push(format!(
                "{label}: {total} vulnerabilities ({severe} high+)"
            )),
        }
        if scan.stale {
            info.push(format!(
                "{label} results outdated, press {}",
                scan_key(source)
            ));
        }
    }
    let badge = format!(" depsu {} ", env!("CARGO_PKG_VERSION"))
        .black()
        .on_cyan()
        .bold();
    let mut atoms: Vec<Vec<Span<'static>>> = info.into_iter().map(|i| vec![Span::raw(i)]).collect();
    atoms[0].insert(0, Span::raw(" "));
    atoms[0].insert(0, badge);
    wrap_hints(Vec::new(), atoms, " · ", width)
}

/// Lays out hint items (each a group of spans) over as many lines as the width needs.
fn wrap_hints(
    prefix: Vec<Span<'static>>,
    atoms: Vec<Vec<Span<'static>>>,
    sep: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let width = width as usize;
    let mut lines = Vec::new();
    let mut cur = vec![Span::raw(" ")];
    let mut cur_w = 1;
    let mut first = true;
    let mut push = |atom: Vec<Span<'static>>, sep: &str, lines: &mut Vec<Line<'static>>| {
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
        cur_w += w;
        cur.extend(atom);
        first = false;
    };
    if !prefix.is_empty() {
        push(prefix, "", &mut lines);
    }
    for atom in atoms {
        push(atom, sep, &mut lines);
    }
    lines.push(Line::from(cur));
    lines
}

fn footer_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let hint = |t: &str| vec![t.to_string().dark_gray()];
    if let Some(input) = &app.input {
        let crate::app::InputPurpose::Version { name } = &input.purpose else {
            return wrap_hints(
                vec!["Add a package:".cyan().bold()],
                vec![hint("see the dialog above"), hint("enter add"), hint("esc cancel")],
                "   ",
                width,
            );
        };
        let mut hints = Vec::new();
        if let Some(r) = app.rows.iter().find(|r| r.name == *name) {
            hints.push(format!("now {}{}, latest {}", r.prefix, r.current, r.latest));
        }
        hints.push("enter install".to_string());
        hints.push("esc cancel".to_string());
        let prefix = vec![
            format!("Version of {name}: ").cyan().bold(),
            input.text.clone().into(),
            "█".cyan(),
        ];
        return wrap_hints(prefix, hints.iter().map(|h| hint(h)).collect(), "   ", width);
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
        return wrap_hints(vec!["Answer the dialog above:".cyan().bold()], keys, "   ", width);
    }
    if app.delete_prompt.is_some() {
        return wrap_hints(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y or enter delete"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.peer_fix.is_some() {
        return wrap_hints(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("↑↓ choose"), hint("enter or 1-9 fix"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.peer_prompt.is_some() {
        return wrap_hints(
            vec!["Answer the dialog above:".cyan().bold()],
            vec![hint("y"), hint("n"), hint("any other key cancels")],
            "   ",
            width,
        );
    }
    if app.pin_prompt {
        let opt = |k: &str, d: &str| vec![k.to_string().bold(), d.to_string().into()];
        return wrap_hints(
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
        return wrap_hints(
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
    let mut lines = Vec::new();
    if !item.is_empty() {
        lines.extend(wrap_hints(
            vec!["item:".cyan().bold()],
            item.iter().map(|h| hint(h)).collect(),
            "   ",
            width,
        ));
    }
    if !scan.is_empty() {
        lines.extend(wrap_hints(
            vec!["scan:".cyan().bold()],
            scan.iter().map(|h| hint(h)).collect(),
            "   ",
            width,
        ));
    }
    lines.extend(wrap_hints(
        prefix,
        global.iter().map(|h| hint(h)).collect(),
        "   ",
        width,
    ));
    lines
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
    if label == crate::view::REMOVED && members.is_empty() {
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
        crate::view::UP_TO_DATE => Color::DarkGray,
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
fn fix_spans(app: &App, r: &AppRow, v: &crate::vuln::Vuln) -> Vec<Span<'static>> {
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
