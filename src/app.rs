//! Application state, background workers and key handling.

use crate::npmrc::Npmrc;
use crate::overrides::{self, Compat, Override};
use crate::package::{Dep, Kind, installed_dependencies, parse_spec};
use crate::pm::Pm;
use crate::registry;
use crate::view::{self, GroupBy, Item, Release};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
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
    /// Overrides targeting dependencies of the installed package itself.
    pub dep_overrides: Vec<Override>,
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
    pub table: TableState,
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
    dir: PathBuf,
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
        let project_dir = dir.clone();
        thread::spawn(move || install_worker(dir, pm, job_rx, tx));

        App {
            pm,
            rows: Vec::new(),
            table: TableState::default(),
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
            dir: project_dir,
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
                                let dep_overrides = installed_dependencies(&self.dir, &name)
                                    .map(|deps| {
                                        overrides::affecting_dependencies(
                                            &self.overrides,
                                            &name,
                                            &deps,
                                        )
                                    })
                                    .unwrap_or_default();
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
                                    dep_overrides,
                                });
                            }
                        }
                        Err(e) => self.push_log(format!("! {name}: {e}")),
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
        self.view = view::build(&self.rows, self.group_by, &self.filter);
        let pos = anchor.and_then(|a| self.view.iter().position(|it| anchor_of(it) == a));
        let sel = pos.unwrap_or_else(|| prev.min(self.view.len().saturating_sub(1)));
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
            KeyCode::Char('g') => {
                self.group_by = self.group_by.next();
                self.rebuild_view();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Home => self.table.select((!self.view.is_empty()).then_some(0)),
            KeyCode::End => self.table.select(self.view.len().checked_sub(1)),
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
                Item::Header { .. } => None,
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
            None => {}
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        if self.view.is_empty() {
            return;
        }
        let len = self.view.len() as isize;
        let cur = self.table.selected().unwrap_or(0) as isize;
        self.table
            .select(Some((cur + delta).clamp(0, len - 1) as usize));
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
                None => {}
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
fn anchor_of(item: &Item) -> (bool, String) {
    match item {
        Item::Header { label, .. } => (true, label.clone()),
        Item::Row { name, .. } => (false, name.clone()),
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
