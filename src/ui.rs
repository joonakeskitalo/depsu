use crate::app::{App, Row as AppRow, Status};
use crate::overrides::Compat;
use crate::pm::Pm;
use crate::view::{GroupBy, Item, Release};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

pub fn draw(f: &mut Frame, app: &mut App) {
    let log_h = 7.min(app.log.len() as u16 + 2).max(3);
    let [header, body, detail, log, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
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
    f.render_widget(
        Line::from(vec![" depsu ".black().on_cyan().bold(), info.into()]),
        header,
    );

    let grouped = app.group_by != GroupBy::None;
    let rows: Vec<Row> = app
        .view
        .iter()
        .map(|item| match item {
            Item::Header { label, members } => {
                let sel = members.iter().filter(|&&i| app.rows[i].selected).count();
                let mark = if sel == 0 {
                    "○"
                } else if sel == members.len() {
                    "●"
                } else {
                    "◐"
                };
                let color = match label.as_str() {
                    "Patch" => Color::Green,
                    "Minor" => Color::Yellow,
                    "Major" => Color::Red,
                    _ => Color::Cyan,
                };
                Row::new(vec![
                    Cell::from(mark),
                    Cell::from(format!("{label} ({})", members.len())),
                ])
                .style(Style::new().fg(color).add_modifier(Modifier::BOLD))
            }
            Item::Row { idx, .. } => {
                let r = &app.rows[*idx];
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
                let mut style = Style::default();
                if r.busy() {
                    style = style.add_modifier(Modifier::DIM);
                }
                let name = if grouped {
                    format!("  {}", r.name)
                } else {
                    r.name.clone()
                };
                Row::new(vec![
                    Cell::from(mark),
                    Cell::from(name),
                    override_marker(r),
                    Cell::from(r.kind.label()).style(Style::new().fg(Color::DarkGray)),
                    Cell::from(format!("{}{}", r.prefix, r.current)),
                    Cell::from("→"),
                    Cell::from(r.new_spec()).style(Style::new().fg(color)),
                ])
                .style(style)
            }
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Min(20),
            Constraint::Length(2),
            Constraint::Length(4),
            Constraint::Length(14),
            Constraint::Length(2),
            Constraint::Length(14),
        ],
    )
    .block(Block::default().borders(Borders::TOP))
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, body, &mut app.table);

    f.render_widget(detail_line(app), detail);

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
            "   / edit   esc clear   space select   a all   i install   g group".dark_gray(),
        ])
    } else {
        Line::from(
            " ↑/↓ move   space select   a all   i install   / filter   g group   q quit"
                .dark_gray(),
        )
    };
    f.render_widget(footer, help);
}

fn compat_color(c: Compat) -> Color {
    match c {
        Compat::Ok => Color::Cyan,
        Compat::Unknown => Color::Yellow,
        Compat::Conflict => Color::Red,
    }
}

/// Marker column: ⚑ overridden and compatible, ? cannot verify, ⚠ conflicts with the override.
fn override_marker(r: &AppRow) -> Cell<'static> {
    if r.overrides.is_empty() {
        return Cell::from("");
    }
    let sym = match r.compat {
        Compat::Ok => "⚑",
        Compat::Unknown => "?",
        Compat::Conflict => "⚠",
    };
    Cell::from(sym).style(Style::new().fg(compat_color(r.compat)))
}

/// One-line explanation of the overrides affecting the highlighted package.
fn detail_line(app: &App) -> Line<'static> {
    let Some(Item::Row { idx, .. }) = app.cursor_item() else {
        return Line::default();
    };
    let r = &app.rows[*idx];
    if r.overrides.is_empty() {
        return Line::default();
    }
    let list = r
        .overrides
        .iter()
        .map(|o| o.describe())
        .collect::<Vec<_>>()
        .join("; ");
    let text = match r.compat {
        Compat::Ok => format!(" overridden ({list}), compatible with {}", r.latest),
        Compat::Unknown => format!(" overridden ({list}), cannot verify compatibility"),
        Compat::Conflict if app.pm == Pm::Npm => format!(
            " {list}: must equal the dependency spec (EOVERRIDE). Use \"$name\" or update it."
        ),
        Compat::Conflict => format!(
            " {list}: {} is outside the override, so the update would have no effect",
            r.latest
        ),
    };
    Line::from(Span::styled(text, Style::new().fg(compat_color(r.compat))))
}
