//! Application state, background workers and key handling.

use crate::npmrc::Npmrc;
use crate::overrides::{self, Compat, Override};
use crate::package::{Dep, Kind, parse_spec};
use crate::pm::Pm;
use crate::registry;
use crate::tree::{Analyzer, Hit};
use crate::view::{self, GroupBy, Item, Overrides, Release};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use semver::Version;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

pub enum Event {
    Fetched {
        name: String,
        result: Result<Version, String>,
    },
    Tree {
        name: String,
        hits: Vec<Hit>,
    },
    InstallStarted(Vec<String>),
    InstallFinished {
        names: Vec<String>,
        result: Result<(), String>,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub enum Status {
    Idle,
    Queued,
    Installing,
    Failed,
}

pub struct Row {
    pub name: String,
    pub kind: Kind,
    pub prefix: &'static str,
    pub current: Version,
    pub latest: Version,
    pub selected: bool,
    pub status: Status,
    /// Overrides targeting this package, and whether the update is compatible with them.
    pub overrides: Vec<Override>,
    pub compat: Compat,
    /// Overrides applying anywhere in the installed dependency tree of this package.
    pub tree_hits: Vec<Hit>,
}

impl Row {
    pub fn new_spec(&self) -> String {
        format!("{}{}", self.prefix, self.latest)
    }
    pub fn release(&self) -> Release {
        Release::of(&self.current, &self.latest)
    }
    pub fn busy(&self) -> bool {
        matches!(self.status, Status::Queued | Status::Installing)
    }
}

struct Job {
    /// (name, spec, kind, exact)
    items: Vec<(String, String, Kind, bool)>,
}

pub struct App {
    pub pm: Pm,
    pub rows: Vec<Row>,
    pub table: ListState,
    pub show_overrides: Overrides,
    pub view: Vec<Item>,
    pub group_by: GroupBy,
    pub filter: String,
    pub filter_mode: bool,
    pub log: Vec<String>,
    pub pending: usize,
    pub total: usize,
    pub registry: String,
    pub quit: bool,
    current: HashMap<String, (Kind, &'static str, Version)>,
    overrides: Vec<Override>,
    tree_tx: Option<Sender<String>>,
    confirm_conflicts: bool,
    quit_warned: bool,
    rx: Receiver<Event>,
    jobs: Sender<Job>,
}

impl App {
    pub fn start(dir: PathBuf, pm: Pm, deps: Vec<Dep>, rc: Npmrc, overrides: Vec<Override>) -> App {
        let (tx, rx) = mpsc::channel();
        let (jobs, job_rx) = mpsc::channel::<Job>();

        let mut current = HashMap::new();
        let mut names = VecDeque::new();
        for d in deps {
            if let Some((prefix, v)) = parse_spec(&d.spec) {
                names.push_back(d.name.clone());
                current.insert(d.name, (d.kind, prefix, v));
            }
        }
        let total = names.len();
        let registry = rc.registry_for("x");

        let queue = Arc::new(Mutex::new(names));
        let rc = Arc::new(rc);
        let agent = registry::agent();
        for _ in 0..registry::CONCURRENCY.min(total) {
            let (queue, rc, agent, tx) = (queue.clone(), rc.clone(), agent.clone(), tx.clone());
            thread::spawn(move || {
                while let Some(name) = queue.lock().unwrap().pop_front() {
                    let result = registry::latest_version(&rc, &agent, &name);
                    if tx.send(Event::Fetched { name, result }).is_err() {
                        break;
                    }
                }
            });
        }

        // One install worker: package managers don't tolerate parallel installs.
        // Dependency tree analysis is only needed when the project defines overrides.
        let tree_tx = if overrides.is_empty() {
            None
        } else {
            let (name_tx, name_rx) = mpsc::channel::<String>();
            let (dir, ev_tx, ovr) = (dir.clone(), tx.clone(), overrides.clone());
            thread::spawn(move || {
                let mut analyzer = Analyzer::new(dir, ovr);
                while let Ok(name) = name_rx.recv() {
                    let hits = analyzer.analyze(&name);
                    if ev_tx.send(Event::Tree { name, hits }).is_err() {
                        break;
                    }
                }
            });
            Some(name_tx)
        };
        thread::spawn(move || install_worker(dir, pm, job_rx, tx));

        App {
            pm,
            rows: Vec::new(),
            table: ListState::default(),
            show_overrides: Overrides::Compact,
            view: Vec::new(),
            group_by: GroupBy::None,
            filter: String::new(),
            filter_mode: false,
            log: Vec::new(),
            pending: total,
            total,
            registry,
            quit: false,
            current,
            overrides,
            tree_tx,
            confirm_conflicts: false,
            quit_warned: false,
            rx,
            jobs,
        }
    }

    pub fn loading(&self) -> bool {
        self.pending > 0
    }

    pub fn installing(&self) -> bool {
        self.rows.iter().any(Row::busy)
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }

    /// Applies all events produced by background threads.
    pub fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Fetched { name, result } => {
                    self.pending = self.pending.saturating_sub(1);
                    match result {
                        Ok(latest) => {
                            if let Some((kind, prefix, cur)) = self.current.get(&name).cloned()
                                && latest > cur
                                && latest.pre.is_empty()
                            {
                                let overrides: Vec<Override> = self
                                    .overrides
                                    .iter()
                                    .filter(|o| o.name == name)
                                    .cloned()
                                    .collect();
                                let compat = overrides::check(
                                    &overrides,
                                    self.pm,
                                    &format!("{prefix}{latest}"),
                                    &latest,
                                );
                                if let Some(tx) = &self.tree_tx {
                                    let _ = tx.send(name.clone());
                                }
                                self.insert_row(Row {
                                    name,
                                    kind,
                                    prefix,
                                    current: cur,
                                    latest,
                                    selected: false,
                                    status: Status::Idle,
                                    overrides,
                                    compat,
                                    tree_hits: Vec::new(),
                                });
                            }
                        }
                        Err(e) => self.push_log(format!("! {name}: {e}")),
                    }
                }
                Event::Tree { name, hits } => {
                    if let Some(r) = self.rows.iter_mut().find(|r| r.name == name) {
                        // Risky hits first, so they survive the compact view's cut-off.
                        let mut hits = hits;
                        hits.sort_by_key(|h| std::cmp::Reverse(h.risk));
                        r.tree_hits = hits;
                        self.rebuild_view();
                    }
                }
                Event::InstallStarted(names) => {
                    for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                        r.status = Status::Installing;
                    }
                }
                Event::InstallFinished { names, result } => match result {
                    Ok(()) => {
                        self.push_log(format!("✔ installed {}", names.join(", ")));
                        // Installed packages are now up to date: drop them from the list.
                        self.rows.retain(|r| !names.contains(&r.name));
                        self.rebuild_view();
                    }
                    Err(e) => {
                        for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                            r.status = Status::Failed;
                        }
                        self.push_log(format!("✘ failed {}:", names.join(", ")));
                        for line in e
                            .lines()
                            .rev()
                            .take(6)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                        {
                            self.push_log(format!("  {line}"));
                        }
                    }
                },
            }
        }
    }

    fn insert_row(&mut self, row: Row) {
        // Keep rows sorted by (kind, name) so late arrivals don't shuffle randomly.
        let key = |r: &Row| (r.kind.label(), r.name.clone());
        let pos = self.rows.partition_point(|r| key(r) < key(&row));
        self.rows.insert(pos, row);
        self.rebuild_view();
    }

    /// Recomputes the displayed list, keeping the cursor on the same item when it still exists.
    fn rebuild_view(&mut self) {
        let anchor = self.cursor_item().map(anchor_of);
        let prev = self.table.selected().unwrap_or(0);
        self.view = view::build(&self.rows, self.group_by, &self.filter, self.show_overrides);
        let pos = anchor.and_then(|a| self.view.iter().position(|it| anchor_of(it) == a));
        let mut sel = pos.unwrap_or_else(|| prev.min(self.view.len().saturating_sub(1)));
        // Override lines can't be selected: fall back to the package they belong to.
        while sel > 0 && matches!(self.view.get(sel), Some(Item::Detail { .. })) {
            sel -= 1;
        }
        self.table.select((!self.view.is_empty()).then_some(sel));
    }

    pub fn cursor_item(&self) -> Option<&Item> {
        self.table.selected().and_then(|i| self.view.get(i))
    }

    /// Number of rows currently shown (excluding group headers).
    pub fn shown(&self) -> usize {
        self.view
            .iter()
            .filter(|i| matches!(i, Item::Row { .. }))
            .count()
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.filter_mode {
            self.on_filter_key(key);
            return;
        }
        if !matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
            self.quit_warned = false;
        }
        if !matches!(key.code, KeyCode::Char('i') | KeyCode::Enter) {
            self.confirm_conflicts = false;
        }
        match key.code {
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.rebuild_view();
            }
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.installing() && !self.quit_warned {
                    self.quit_warned = true;
                    self.push_log("Install in progress. Press q again to quit anyway.");
                } else {
                    self.quit = true;
                }
            }
            KeyCode::Char('/') => self.filter_mode = true,
            KeyCode::Char('o') => {
                self.show_overrides = self.show_overrides.next();
                self.rebuild_view();
            }
            KeyCode::Char('g') => {
                self.group_by = self.group_by.next();
                self.rebuild_view();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Home => self.table.select((!self.view.is_empty()).then_some(0)),
            KeyCode::End => {
                let last = self
                    .view
                    .iter()
                    .rposition(|i| !matches!(i, Item::Detail { .. }));
                self.table.select(last);
            }
            KeyCode::Char(' ') => self.toggle_cursor(),
            KeyCode::Char('a') => {
                let visible = self.visible_rows();
                let all = visible
                    .iter()
                    .filter(|&&i| !self.rows[i].busy())
                    .all(|&i| self.rows[i].selected);
                for i in visible {
                    if !self.rows[i].busy() {
                        self.rows[i].selected = !all;
                    }
                }
            }
            KeyCode::Char('i') | KeyCode::Enter => self.install_selected(),
            _ => {}
        }
    }

    fn on_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.filter_mode = false;
                self.rebuild_view();
            }
            KeyCode::Enter => self.filter_mode = false,
            KeyCode::Backspace => {
                self.filter.pop();
                self.rebuild_view();
            }
            KeyCode::Down => self.move_cursor(1),
            KeyCode::Up => self.move_cursor(-1),
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.push(c);
                self.rebuild_view();
            }
            _ => {}
        }
    }

    /// Indices (into `rows`) of the rows currently shown.
    fn visible_rows(&self) -> Vec<usize> {
        self.view
            .iter()
            .filter_map(|it| match it {
                Item::Row { idx, .. } => Some(*idx),
                Item::Header { .. } | Item::Detail { .. } => None,
            })
            .collect()
    }

    /// Space on a row toggles it and moves down; on a group header it toggles the whole group.
    fn toggle_cursor(&mut self) {
        match self.cursor_item().cloned() {
            Some(Item::Row { idx, .. }) => {
                if !self.rows[idx].busy() {
                    self.rows[idx].selected = !self.rows[idx].selected;
                }
                self.move_cursor(1);
            }
            Some(Item::Header { members, .. }) => {
                let all = members
                    .iter()
                    .filter(|&&i| !self.rows[i].busy())
                    .all(|&i| self.rows[i].selected);
                for i in members {
                    if !self.rows[i].busy() {
                        self.rows[i].selected = !all;
                    }
                }
            }
            None | Some(Item::Detail { .. }) => {}
        }
    }

    /// Moves to the next selectable item in the direction of `delta`, skipping override lines.
    fn move_cursor(&mut self, delta: isize) {
        let len = self.view.len() as isize;
        let step = delta.signum();
        let mut i = self.table.selected().unwrap_or(0) as isize;
        let mut remaining = delta.abs();
        while remaining > 0 {
            let mut next = i + step;
            while (0..len).contains(&next)
                && matches!(self.view[next as usize], Item::Detail { .. })
            {
                next += step;
            }
            if !(0..len).contains(&next) {
                break;
            }
            i = next;
            remaining -= 1;
        }
        if len > 0 {
            self.table.select(Some(i.clamp(0, len - 1) as usize));
        }
    }

    /// Queues all checked visible rows. If none are checked, queues the row under the cursor,
    /// or every row of the group when the cursor is on a group header.
    fn install_selected(&mut self) {
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && !self.rows[i].busy())
            .collect();
        if idx.is_empty() {
            match self.cursor_item() {
                Some(Item::Row { idx: i, .. }) => idx.push(*i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                None | Some(Item::Detail { .. }) => {}
            }
            idx.retain(|&i| !self.rows[i].busy());
        }
        if idx.is_empty() {
            return;
        }
        // Updates that clash with an override need an explicit second press.
        let conflicts: Vec<&str> = idx
            .iter()
            .filter(|&&i| self.rows[i].compat == Compat::Conflict)
            .map(|&i| self.rows[i].name.as_str())
            .collect();
        if !conflicts.is_empty() && !self.confirm_conflicts {
            let msg = format!(
                "⚠ conflicts with overrides: {}. Press i again to install anyway, any other key cancels.",
                conflicts.join(", ")
            );
            self.confirm_conflicts = true;
            self.push_log(msg);
            return;
        }
        self.confirm_conflicts = false;
        let mut items = Vec::new();
        for i in idx {
            let r = &mut self.rows[i];
            r.selected = false;
            r.status = Status::Queued;
            items.push((r.name.clone(), r.new_spec(), r.kind, r.prefix.is_empty()));
        }
        let names: Vec<_> = items.iter().map(|i| i.0.as_str()).collect();
        let msg = format!("… queued {}", names.join(", "));
        self.push_log(msg);
        let _ = self.jobs.send(Job { items });
    }
}

/// Identity of a list item that survives index changes: (is_header, label or name).
fn anchor_of(item: &Item) -> (u8, String) {
    match item {
        Item::Header { label, .. } => (0, label.clone()),
        Item::Row { name, .. } => (1, name.clone()),
        Item::Detail { .. } => (2, String::new()),
    }
}

fn install_worker(dir: PathBuf, pm: Pm, jobs: Receiver<Job>, tx: Sender<Event>) {
    while let Ok(job) = jobs.recv() {
        let all: Vec<String> = job.items.iter().map(|i| i.0.clone()).collect();
        let _ = tx.send(Event::InstallStarted(all.clone()));

        // One command per (kind, exact) group.
        let mut groups: Vec<((Kind, bool), Vec<String>)> = Vec::new();
        for (name, spec, kind, exact) in &job.items {
            let arg = format!("{name}@{spec}");
            match groups.iter_mut().find(|(k, _)| *k == (*kind, *exact)) {
                Some((_, v)) => v.push(arg),
                None => groups.push(((*kind, *exact), vec![arg])),
            }
        }

        let mut result = Ok(());
        for ((kind, exact), specs) in groups {
            let args = pm.install_args(&specs, kind, exact);
            let out = Command::new(pm.program())
                .args(&args)
                .current_dir(&dir)
                .output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
                    if text.trim().is_empty() {
                        text = String::from_utf8_lossy(&o.stdout).into_owned();
                    }
                    result = Err(format!(
                        "`{} {}` exited with {}\n{}",
                        pm.name(),
                        args.join(" "),
                        o.status,
                        text.trim()
                    ));
                    break;
                }
                Err(e) => {
                    result = Err(format!("could not run {}: {e}", pm.name()));
                    break;
                }
            }
        }
        if tx
            .send(Event::InstallFinished { names: all, result })
            .is_err()
        {
            break;
        }
    }
}
