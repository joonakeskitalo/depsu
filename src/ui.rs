use crate::app::{App, Status};
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
    } else {
        format!("{} outdated", app.rows.len())
    };
    f.render_widget(
        Line::from(vec![
            " depsu ".black().on_cyan().bold(),
            format!(" {} · {} · {}", app.pm.name(), app.registry, state).into(),
        ]),
        header,
    );

    let rows: Vec<Row> = app
        .rows
        .iter()
        .map(|r| {
            let mark = match r.status {
                Status::Queued => "…",
                Status::Installing => "⟳",
                Status::Failed => "✘",
                Status::Idle if r.selected => "●",
                Status::Idle => "○",
            };
            let color = if r.latest.major > r.current.major {
                Color::Red
            } else if r.latest.minor > r.current.minor {
                Color::Yellow
            } else {
                Color::Green
            };
            let mut style = Style::default();
            if r.busy() {
                style = style.add_modifier(Modifier::DIM);
            }
            Row::new(vec![
                Cell::from(mark),
                Cell::from(r.name.clone()),
                Cell::from(r.kind.label()).style(Style::new().fg(Color::DarkGray)),
                Cell::from(format!("{}{}", r.prefix, r.current)),
                Cell::from("→"),
                Cell::from(r.new_spec()).style(Style::new().fg(color)),
            ])
            .style(style)
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

    f.render_widget(
        Paragraph::new(" ↑/↓ move   space select   a all   i install   q quit").dark_gray(),
        help,
    );
}
