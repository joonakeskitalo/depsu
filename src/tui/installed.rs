//! The "installed" tab: every package in `node_modules` with its size, when it was installed
//! and why it is there. Read from disk and git in a background thread.
use crate::deps::info::{self, human_size};
use crate::security::policy::date_of;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use semver::Version;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub version: Option<Version>,
    /// Bytes on disk, its own `node_modules` left out.
    pub bytes: Option<u64>,
    /// When the package folder was created here (Unix seconds).
    pub installed: Option<i64>,
    /// Why it is installed: a direct dependency, or the packages that require it.
    pub why: String,
}

/// How the packages are ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Name,
    Size,
    Date,
}

impl Sort {
    fn next(self) -> Sort {
        match self {
            Sort::Name => Sort::Size,
            Sort::Size => Sort::Date,
            Sort::Date => Sort::Name,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Sort::Name => "name",
            Sort::Size => "size, largest first",
            Sort::Date => "install date, newest first",
        }
    }
}

/// The state of the tab. `entries` is `None` until the first read finishes.
pub struct View {
    pub entries: Option<Vec<Entry>>,
    pub loading: bool,
    /// The packages changed since `entries` were read.
    pub stale: bool,
    pub sort: Sort,
    pub filter: String,
    pub typing: bool,
    pub table: TableState,
    /// Rows shown at once, for paging.
    page: usize,
}

impl Default for View {
    fn default() -> Self {
        View {
            entries: None,
            loading: false,
            stale: false,
            sort: Sort::Name,
            filter: String::new(),
            typing: false,
            table: TableState::default(),
            page: 10,
        }
    }
}

/// What a key in the tab asks the app to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Close,
    Refresh,
    Quit,
}

impl View {
    /// Indexes into `entries` that pass the filter, in the order shown.
    pub fn visible(&self) -> Vec<usize> {
        let Some(entries) = &self.entries else {
            return Vec::new();
        };
        let needle = self.filter.trim().to_lowercase();
        let mut idx: Vec<usize> = (0..entries.len())
            .filter(|&i| {
                needle.is_empty()
                    || entries[i].name.to_lowercase().contains(&needle)
                    || entries[i].why.to_lowercase().contains(&needle)
            })
            .collect();
        match self.sort {
            Sort::Name => idx.sort_by(|&a, &b| entries[a].name.cmp(&entries[b].name)),
            Sort::Size => idx.sort_by_key(|&i| std::cmp::Reverse(entries[i].bytes.unwrap_or(0))),
            Sort::Date => idx.sort_by_key(|&i| std::cmp::Reverse(entries[i].installed.unwrap_or(i64::MIN))),
        }
        idx
    }

    pub fn set(&mut self, entries: Vec<Entry>) {
        self.entries = Some(entries);
        self.loading = false;
        self.stale = false;
        let n = self.visible().len();
        let sel = self.table.selected().unwrap_or(0).min(n.saturating_sub(1));
        self.table.select((n > 0).then_some(sel));
    }

    fn step(&mut self, by: isize) {
        let n = self.visible().len() as isize;
        if n == 0 {
            return;
        }
        let at = self.table.selected().unwrap_or(0) as isize;
        self.table.select(Some((at + by).clamp(0, n - 1) as usize));
    }

    pub fn scroll(&mut self, up: bool) {
        self.step(if up { -3 } else { 3 });
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        if self.typing {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.typing = false;
                }
                KeyCode::Enter => self.typing = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.table.select((!self.visible().is_empty()).then_some(0));
            return Action::None;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::PageUp | KeyCode::Char(',') => self.step(-(self.page as isize)),
            KeyCode::PageDown | KeyCode::Char('.') => self.step(self.page as isize),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Char('/') => self.typing = true,
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.table.select((!self.visible().is_empty()).then_some(0));
            }
            KeyCode::Char('r') => return Action::Refresh,
            KeyCode::Esc if !self.filter.is_empty() => self.filter.clear(),
            KeyCode::Esc | KeyCode::Char('T') => return Action::Close,
            KeyCode::Char('q') => return Action::Quit,
            _ => {}
        }
        Action::None
    }

    pub fn draw(&mut self, f: &mut Frame, header: &str) {
        let [top, body, detail, hints] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let dim = Style::new().fg(Color::DarkGray);
        let visible = self.visible();
        let (total, count) = match &self.entries {
            Some(e) => (e.iter().map(|e| e.bytes.unwrap_or(0)).sum::<u64>(), e.len()),
            None => (0, 0),
        };
        let mut title = vec![
            Span::styled(format!(" {header} "), Style::new().fg(Color::Black).bg(Color::Gray)),
            Span::styled(
                " Installed ",
                Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
        ];
        let state = if self.loading && self.entries.is_none() {
            "  reading node_modules…".to_string()
        } else {
            let shown = if visible.len() == count { String::new() } else { format!("{} of ", visible.len()) };
            format!(
                "  {shown}{count} packages, {} · sorted by {}{}{}",
                human_size(total),
                self.sort.label(),
                if self.filter.is_empty() { String::new() } else { format!(" · filter: {}", self.filter) },
                if self.loading { " · refreshing…" } else if self.stale { " · changed, r to refresh" } else { "" },
            )
        };
        title.push(Span::styled(state, dim));
        f.render_widget(Paragraph::new(Line::from(title)), top);

        let block = Block::default().borders(Borders::ALL).border_style(Style::new().fg(Color::Cyan));
        let inner = block.inner(body);
        self.page = (inner.height as usize).saturating_sub(1).max(1);
        let rows: Vec<Row> = match &self.entries {
            Some(entries) => visible
                .iter()
                .map(|&i| {
                    let e = &entries[i];
                    Row::new(vec![
                        Cell::from(e.name.clone()),
                        Cell::from(e.version.as_ref().map_or("-".into(), |v| v.to_string())),
                        Cell::from(e.bytes.map_or("-".into(), human_size)),
                        Cell::from(e.installed.map_or("-".into(), date_of)),
                        Cell::from(e.why.clone()),
                    ])
                })
                .collect(),
            None => Vec::new(),
        };
        let head = Row::new(["Package", "Version", "Size", "Installed", "Why"])
            .style(Style::new().add_modifier(Modifier::BOLD).fg(Color::Cyan));
        let table = Table::new(
            rows,
            [
                Constraint::Percentage(25),
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Min(10),
            ],
        )
        .header(head)
        .block(block)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, body, &mut self.table);

        // The row under the cursor in full: the table cuts the long texts.
        let text = self
            .table
            .selected()
            .and_then(|s| visible.get(s))
            .and_then(|&i| self.entries.as_ref()?.get(i))
            .map(|e| {
                format!(
                    "{}{}: {}",
                    e.name,
                    e.version.as_ref().map(|v| format!("@{v}")).unwrap_or_default(),
                    e.why
                )
            })
            .unwrap_or_default();
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).border_style(dim)),
            detail,
        );
        let hint = if self.typing {
            format!(" filter: {}▏  enter keep · esc clear", self.filter)
        } else {
            " ↑↓ move · , . page · / filter · s sort · r refresh · T / esc back · q quit".to_string()
        };
        f.render_widget(Paragraph::new(Span::styled(hint, dim)), hints);
    }
}

/// The names in `node_modules` (scopes opened), skipping dot folders such as `.bin`.
fn installed_names(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir.join("node_modules")) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            if let Ok(inner) = std::fs::read_dir(e.path()) {
                out.extend(inner.flatten().map(|i| format!("{name}/{}", i.file_name().to_string_lossy())));
            }
        } else {
            out.insert(name);
        }
    }
    out
}

/// One package that asks for another: its name and version, what it asks for and how.
#[derive(Clone, Debug)]
pub struct Requirer {
    pub name: String,
    pub version: Option<Version>,
    pub range: String,
    /// `""` for a normal dependency, else `optional ` or `peer `.
    pub kind: &'static str,
}

/// What a package says it needs, from its `package.json`.
fn needs(manifest: &serde_json::Value) -> Vec<(String, String, &'static str)> {
    let mut out = Vec::new();
    for (field, kind) in [("dependencies", ""), ("optionalDependencies", "optional "), ("peerDependencies", "peer ")] {
        if let Some(map) = manifest.get(field).and_then(|v| v.as_object()) {
            out.extend(map.iter().map(|(n, r)| (n.clone(), r.as_str().unwrap_or("").to_string(), kind)));
        }
    }
    out
}

/// Why `name` is there. `direct` maps the project's own dependencies to how it lists them;
/// `via` says which of them lead to each package.
pub fn why(
    name: &str,
    direct: &HashMap<String, String>,
    required_by: &HashMap<String, Vec<Requirer>>,
    via: &HashMap<String, BTreeSet<String>>,
) -> String {
    let mut parts = Vec::new();
    if let Some(d) = direct.get(name) {
        parts.push(format!("direct {d}"));
    }
    let mut who: Vec<String> = required_by
        .get(name)
        .into_iter()
        .flatten()
        .map(|r| {
            let at = r.version.as_ref().map(|v| format!("@{v}")).unwrap_or_default();
            format!("{}{at} ({}{})", r.name, r.kind, r.range)
        })
        .collect();
    who.sort();
    who.dedup();
    if !who.is_empty() {
        let n = who.len();
        who.truncate(3);
        if n > 3 {
            who.push(format!("{} more", n - 3));
        }
        let mut s = format!("required by {}", who.join(", "));
        let leads: Vec<&String> = via.get(name).into_iter().flatten().filter(|d| *d != name).take(3).collect();
        if !leads.is_empty() {
            s.push_str(&format!(" · via {}", leads.into_iter().cloned().collect::<Vec<_>>().join(", ")));
        }
        parts.push(s);
    }
    if parts.is_empty() {
        "nothing installed requires it, and it is not in package.json".into()
    } else {
        parts.join(" · also ")
    }
}

/// Reads every installed package. Slow on big trees (it measures each folder): run it off the
/// UI thread. Who requires what is read from the installed `package.json` files, peer and
/// optional dependencies included, like `npm ls` does.
pub fn collect(dir: &Path, direct: &HashMap<String, String>) -> Vec<Entry> {
    let mut names = installed_names(dir);
    names.extend(direct.keys().cloned());
    struct Found {
        name: String,
        folder: std::path::PathBuf,
        version: Option<Version>,
        needs: Vec<(String, String, &'static str)>,
    }
    let found: Vec<Found> = names
        .into_iter()
        .filter_map(|name| {
            let folder = info::package_dir(dir, &name)?;
            let manifest: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(folder.join("package.json")).ok()?).ok()?;
            Some(Found {
                version: manifest.get("version").and_then(|v| v.as_str()).and_then(|v| Version::parse(v).ok()),
                needs: needs(&manifest),
                name,
                folder,
            })
        })
        .collect();
    let mut required_by: HashMap<String, Vec<Requirer>> = HashMap::new();
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for f in &found {
        for (dep, range, kind) in &f.needs {
            required_by.entry(dep.clone()).or_default().push(Requirer {
                name: f.name.clone(),
                version: f.version.clone(),
                range: range.clone(),
                kind,
            });
            edges.entry(f.name.as_str()).or_default().push(dep.as_str());
        }
    }
    // Which direct dependencies lead to each package.
    let mut via: HashMap<String, BTreeSet<String>> = HashMap::new();
    for root in direct.keys() {
        let mut stack = vec![root.as_str()];
        let mut seen = BTreeSet::new();
        while let Some(n) = stack.pop() {
            if !seen.insert(n) {
                continue;
            }
            via.entry(n.to_string()).or_default().insert(root.clone());
            stack.extend(edges.get(n).into_iter().flatten().copied());
        }
    }
    found
        .into_iter()
        .map(|f| {
            let installed = std::fs::metadata(&f.folder)
                .ok()
                .and_then(|m| m.created().or(m.modified()).ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);
            Entry {
                why: why(&f.name, direct, &required_by, &via),
                bytes: Some(info::dir_size(&f.folder).0),
                version: f.version,
                installed,
                name: f.name,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, json: &str) {
        let p = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("package.json"), json).unwrap();
    }
    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("depsu-installed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn says_why_a_package_is_installed_including_peers_and_the_direct_one_it_comes_through() {
        let dir = tmp("why");
        write(&dir, "a", r#"{"name":"a","version":"1.0.0","dependencies":{"b":"^2"}}"#);
        write(&dir, "b", r#"{"name":"b","version":"2.1.0","peerDependencies":{"c":"^3"}}"#);
        write(&dir, "c", r#"{"name":"c","version":"3.0.0"}"#);
        write(&dir, "d", r#"{"name":"d","version":"1.0.0"}"#);
        let direct = HashMap::from([("a".to_string(), "dependency (^1)".to_string())]);
        let found: HashMap<String, String> = collect(&dir, &direct).into_iter().map(|e| (e.name, e.why)).collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found["a"], "direct dependency (^1)");
        assert_eq!(found["b"], "required by a@1.0.0 (^2) · via a");
        assert_eq!(found["c"], "required by b@2.1.0 (peer ^3) · via a");
        assert!(found["d"].starts_with("nothing installed requires it"), "{}", found["d"]);
    }

    #[test]
    fn sorts_and_filters() {
        let e = |n: &str, b: u64, t: i64| Entry {
            name: n.into(),
            version: None,
            bytes: Some(b),
            installed: Some(t),
            why: String::new(),
        };
        let mut v = View::default();
        v.set(vec![e("b", 10, 1), e("a", 30, 2), e("c", 20, 3)]);
        let names = |v: &View| v.visible().iter().map(|&i| v.entries.as_ref().unwrap()[i].name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&v), ["a", "b", "c"]);
        v.sort = Sort::Size;
        assert_eq!(names(&v), ["a", "c", "b"]);
        v.sort = Sort::Date;
        assert_eq!(names(&v), ["c", "a", "b"]);
        v.filter = "B".into();
        assert_eq!(names(&v), ["b"]);
    }

    #[test]
    fn reads_the_packages_of_a_folder() {
        let dir = std::env::temp_dir().join(format!("depsu-installed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (n, v) in [("a", "1.0.0"), ("@s/b", "2.0.0")] {
            let p = dir.join("node_modules").join(n);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("package.json"), format!(r#"{{"name":"{n}","version":"{v}"}}"#)).unwrap();
        }
        std::fs::create_dir_all(dir.join("node_modules/.bin")).unwrap();
        let direct = HashMap::from([("a".to_string(), "dependency".to_string())]);
        let found = collect(&dir, &direct);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["@s/b", "a"]);
        assert_eq!(found[1].version, Some(Version::new(1, 0, 0)));
        assert!(found[1].bytes.unwrap() > 0);
        assert!(found[1].installed.is_some());
        assert_eq!(found[1].why, "direct dependency");
    }
}
