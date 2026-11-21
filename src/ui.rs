use crate::app::{App, VersionRange, Row as AppRow, ScanStatus, Status, fix_key, scan_key};
use crate::audit;
use crate::overrides::{self, Compat, Override};
use crate::package::Kind;
use crate::pm::Pm;
use crate::tree::{self, Hit};
use crate::view::{Child, GroupBy, Item, Overrides, Release, UNNEEDED};
use crate::vuln::{Severity, Source};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

pub fn draw(f: &mut Frame, app: &mut App) {
    let log_h = 7.min(app.log.len() as u16 + 2).max(3);
    // While the nested override lists are hidden, a text summary takes their place.
    let summary_h = if app.show_overrides == Overrides::Off {
        SUMMARY_LINES
    } else {
        0
    };
    let [header, body, summary, log, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(summary_h),
        Constraint::Length(log_h),
        Constraint::Length(1),
    ])
    .areas(f.area());

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
    let mut info = format!(" {} · {} · {}", app.pm.name(), app.registry, state);
    if app.group_by != GroupBy::None {
        info.push_str(&format!(" · group: {}", app.group_by.label()));
    }
    if app.show_overrides != Overrides::Off {
        info.push_str(&format!(" · overrides: {}", app.show_overrides.label()));
    }
    if !app.show_uptodate {
        info.push_str(" · up-to-date hidden");
    }
    let audit_source = app.audit_source();
    for (source, scan) in [(Source::Snyk, &app.snyk), (audit_source, &app.audit)] {
        let label = source.label();
        match scan.status {
            ScanStatus::NotRun => {}
            ScanStatus::Running => info.push_str(&format!(" · {label}: scanning…")),
            ScanStatus::Failed => info.push_str(&format!(" · {label}: failed (see log)")),
            ScanStatus::Done { total: 0, .. } => info.push_str(&format!(" · {label}: clean")),
            ScanStatus::Done { total, severe } => info.push_str(&format!(
                " · {label}: {total} vulnerabilities ({severe} high+)"
            )),
        }
        if scan.stale {
            info.push_str(&format!(
                " · {label} results outdated, press {}",
                scan_key(source)
            ));
        }
    }
    f.render_widget(
        Line::from(vec![
            format!(" depsu {} ", env!("CARGO_PKG_VERSION"))
                .black()
                .on_cyan()
                .bold(),
            info.into(),
        ]),
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
            Item::Header { label, members } => ListItem::new(header_line(app, label, members)),
            Item::Row { idx, .. } => ListItem::new(row_line(&app.rows[*idx], indent, name_w)),
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
        .block(Block::default().borders(Borders::TOP))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, body, &mut app.table);
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

    // Hints for actions that only exist when there is something to act on.
    let mut remove_hint = String::new();
    if app.has_overrides() {
        remove_hint.push_str("   x remove override");
    }
    for source in [Source::Snyk, app.audit_source()] {
        if app.rows.iter().any(|r| r.fix_of(source).is_some()) {
            remove_hint.push_str(&format!(
                "   {} {} fix",
                fix_key(source),
                if source.is_audit() { "audit" } else { "snyk" }
            ));
        }
    }
    remove_hint.push_str("   P pin type");
    if app.rows.iter().any(|r| !r.vulns.is_empty()) {
        remove_hint.push_str("   p pin fix as override");
    }
    let audit_hint = match audit::source_for(app.pm) {
        Some(src) => format!("   n {}", src.label()),
        None => String::new(),
    };
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
            "   / edit   esc clear   space select   a all   i install   g group   o overrides   u up-to-date"
                .dark_gray(),
        ])
    } else {
        Line::from(
            format!(" ↑/↓ move   space select   a all   i install   / filter   g group   o overrides   u up-to-date   s snyk{audit_hint}{remove_hint}   q quit")
                .dark_gray(),
        )
    };
    f.render_widget(footer, help);
}

fn header_line(app: &App, label: &str, members: &[usize]) -> Line<'static> {
    if label == UNNEEDED && members.is_empty() {
        let n = app
            .view
            .iter()
            .filter(|i| matches!(i, Item::Override { .. }))
            .count();
        return Line::from(format!("✂ {label} ({n}), press x to remove"))
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

fn row_line(r: &AppRow, indent: usize, name_w: usize) -> Line<'static> {
    let mark = match r.status {
        Status::Queued => "…",
        Status::Installing => "⟳",
        Status::Failed => "✘",
        Status::Idle if !r.outdated => "·",
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
    spans.push(Span::raw(" ".repeat(4usize.saturating_sub(marker_w) + 1)));
    spans.push(Span::styled(
        format!("{:<4}", r.kind.label()),
        Style::new().fg(Color::DarkGray),
    ));
    let pin = r.range();
    spans.push(Span::styled(
        format!("{:<8}", pin.label()),
        Style::new().fg(match pin {
            VersionRange::Exact => Color::Green,
            VersionRange::Tilde => Color::Cyan,
            VersionRange::Caret => Color::Yellow,
            VersionRange::AtLeast => Color::Red,
        }),
    ));
    spans.push(Span::raw(format!(
        "{:<14}",
        format!("{}{}", r.prefix, r.current)
    )));
    if r.outdated {
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
    let line = Line::from(spans);
    if r.busy() || !r.outdated {
        line.style(Style::new().add_modifier(Modifier::DIM))
    } else {
        line
    }
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
        Child::More(_) | Child::Vuln(_) | Child::MoreVulns(_) => None,
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
            t.push_str(&format!("  · {}", v.fix_summary()));
            (t, String::new(), severity_color(v.severity))
        }
        Child::MoreVulns(n) => (
            format!("… +{n} more vulnerabilities (press o for all)"),
            String::new(),
            Color::DarkGray,
        ),
        Child::More(n) => (
            format!("… +{n} more (press o for all)"),
            String::new(),
            Color::DarkGray,
        ),
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
