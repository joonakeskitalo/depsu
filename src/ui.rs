use crate::app::{App, Status};
use crate::view::{GroupBy, Item, Release};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

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
            Constraint::Length(4),
            Constraint::Length(14),
            Constraint::Length(2),
            Constraint::Length(14),
        ],
    )
    .block(Block::default().borders(Borders::TOP))
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, body, &mut app.table);

    let lines: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(log_h as usize - 2)
        .rev()
        .map(|l| {
            let color = match l.chars().next() {
                Some('✘') | Some('!') => Color::Red,
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
