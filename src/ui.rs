use crate::app::{App, Row as AppRow, Status};
use crate::overrides::{self, Compat};
use crate::pm::Pm;
use crate::tree::Hit;
use crate::view::{Child, GroupBy, Item, Overrides, Release};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

pub fn draw(f: &mut Frame, app: &mut App) {
    let log_h = 7.min(app.log.len() as u16 + 2).max(3);
    let [header, body, log, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(log_h),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let state = if app.loading() {
        format!("checking {}/{}…", app.total - app.pending, app.total)
    } else if app.rows.is_empty() {
        "all dependencies are up to date".to_string()
    } else if app.shown() != app.rows.len() {
        format!("{} of {} outdated", app.shown(), app.rows.len())
    } else {
        format!("{} outdated", app.rows.len())
    };
    let mut info = format!(" {} · {} · {}", app.pm.name(), app.registry, state);
    if app.group_by != GroupBy::None {
        info.push_str(&format!(" · group: {}", app.group_by.label()));
    }
    if app.show_overrides != Overrides::Compact {
        info.push_str(&format!(" · overrides: {}", app.show_overrides.label()));
    }
    f.render_widget(
        Line::from(vec![" depsu ".black().on_cyan().bold(), info.into()]),
        header,
    );

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
            Item::Header { label, members } => header_line(app, label, members),
            Item::Row { idx, .. } => row_line(&app.rows[*idx], indent, name_w),
            Item::Detail { idx, child, last } => {
                detail_line(app, &app.rows[*idx], *child, *last, indent)
            }
        })
        .map(ListItem::new)
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::TOP))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, body, &mut app.table);

    let lines: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(log_h as usize - 2)
        .rev()
        .map(|l| {
            let color = match l.chars().next() {
                Some('✘') | Some('!') => Color::Red,
                Some('⚠') => Color::Yellow,
                Some('✔') => Color::Green,
                _ => Color::Gray,
            };
            Line::from(Span::styled(l.clone(), Style::new().fg(color)))
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::TOP).title("log")),
        log,
    );

    let footer: Line = if app.filter_mode {
        Line::from(vec![
            " /".cyan().bold(),
            app.filter.clone().into(),
            "█".cyan(),
            "   enter keep   esc clear".dark_gray(),
        ])
    } else if !app.filter.is_empty() {
        Line::from(vec![
            format!(" filter: {}", app.filter).cyan(),
            "   / edit   esc clear   space select   a all   i install   g group   o overrides"
                .dark_gray(),
        ])
    } else {
        Line::from(
            " ↑/↓ move   space select   a all   i install   / filter   g group   o overrides   q quit"
                .dark_gray(),
        )
    };
    f.render_widget(footer, help);
}

fn header_line(app: &App, label: &str, members: &[usize]) -> Line<'static> {
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
        _ => Color::Cyan,
    };
    Line::from(format!("{mark} {label} ({})", members.len()))
        .style(Style::new().fg(color).add_modifier(Modifier::BOLD))
}

fn row_line(r: &AppRow, indent: usize, name_w: usize) -> Line<'static> {
    let mark = match r.status {
        Status::Queued => "…",
        Status::Installing => "⟳",
        Status::Failed => "✘",
        Status::Idle if r.selected => "●",
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
    spans.push(Span::raw(" ".repeat(3usize.saturating_sub(marker_w) + 1)));
    spans.push(Span::styled(
        format!("{:<4}", r.kind.label()),
        Style::new().fg(Color::DarkGray),
    ));
    spans.push(Span::raw(format!(
        "{:<14}",
        format!("{}{}", r.prefix, r.current)
    )));
    spans.push(Span::raw("→ "));
    spans.push(Span::styled(r.new_spec(), Style::new().fg(color)));
    let line = Line::from(spans);
    if r.busy() {
        line.style(Style::new().add_modifier(Modifier::DIM))
    } else {
        line
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
    if !r.overrides.is_empty() {
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
    (spans, width)
}

/// An override line nested under its package.
fn detail_line(app: &App, r: &AppRow, child: Child, last: bool, indent: usize) -> Line<'static> {
    let branch = if last { "└─" } else { "├─" };
    let prefix = format!("  {}   {branch} ", " ".repeat(indent));
    let (text, color) = match child {
        Child::Own(i) => {
            let o = &r.overrides[i];
            let c = overrides::check(std::slice::from_ref(o), app.pm, &r.new_spec(), &r.latest);
            let note = if !o.path.is_empty() {
                "only applies below another package".to_string()
            } else {
                match c {
                    Compat::Ok => format!("compatible with {}", r.latest),
                    Compat::Unknown => "cannot verify compatibility".to_string(),
                    Compat::Conflict if app.pm == Pm::Npm => {
                        "must equal the dependency spec (EOVERRIDE), use \"$name\" or update it"
                            .to_string()
                    }
                    Compat::Conflict => {
                        format!(
                            "{} is outside the override, the update would have no effect",
                            r.latest
                        )
                    }
                }
            };
            (
                format!("{} {}  ({note})", compat_symbol(c), o.describe()),
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
            (format!("↳ {}", hit_text(h)), color)
        }
        Child::More(n) => (format!("… +{n} more (press o for all)"), Color::DarkGray),
    };
    Line::from(vec![
        Span::styled(prefix, Style::new().fg(Color::DarkGray)),
        Span::styled(text, Style::new().fg(color)),
    ])
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
