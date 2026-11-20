//! Application state, background workers and key handling.

use crate::npmrc::Npmrc;
use crate::package::{Dep, Kind, parse_spec};
use crate::pm::Pm;
use crate::registry;
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
    Fetched { name: String, result: Result<Version, String> },
    InstallStarted(Vec<String>),
    InstallFinished { names: Vec<String>, result: Result<(), String> },
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
}

impl Row {
    pub fn new_spec(&self) -> String {
        format!("{}{}", self.prefix, self.latest)
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
    pub log: Vec<String>,
    pub pending: usize,
    pub total: usize,
    pub registry: String,
    pub quit: bool,
    current: HashMap<String, (Kind, &'static str, Version)>,
    quit_warned: bool,
    rx: Receiver<Event>,
    jobs: Sender<Job>,
}

impl App {
    pub fn start(dir: PathBuf, pm: Pm, deps: Vec<Dep>, rc: Npmrc) -> App {
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
        for _ in 0..16.min(total) {
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
        thread::spawn(move || install_worker(dir, pm, job_rx, tx));

        App {
            pm,
            rows: Vec::new(),
            table: TableState::default(),
            log: Vec::new(),
            pending: total,
            total,
            registry,
            quit: false,
            current,
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
                            if let Some((kind, prefix, cur)) = self.current.get(&name).cloned() {
                                if latest > cur && latest.pre.is_empty() {
                                    self.insert_row(Row {
                                        name,
                                        kind,
                                        prefix,
                                        current: cur,
                                        latest,
                                        selected: false,
                                        status: Status::Idle,
                                    });
                                }
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
                        self.clamp_cursor();
                    }
                    Err(e) => {
                        for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                            r.status = Status::Failed;
                        }
                        self.push_log(format!("✘ failed {}:", names.join(", ")));
                        for line in e.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev() {
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
        if self.table.selected().is_none() {
            self.table.select(Some(0));
        }
    }

    fn clamp_cursor(&mut self) {
        if self.rows.is_empty() {
            self.table.select(None);
        } else {
            let i = self.table.selected().unwrap_or(0).min(self.rows.len() - 1);
            self.table.select(Some(i));
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if !matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
            self.quit_warned = false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.installing() && !self.quit_warned {
                    self.quit_warned = true;
                    self.push_log("Install in progress. Press q again to quit anyway.");
                } else {
                    self.quit = true;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Home | KeyCode::Char('g') => self.table.select((!self.rows.is_empty()).then_some(0)),
            KeyCode::End | KeyCode::Char('G') => {
                self.table.select(self.rows.len().checked_sub(1));
            }
            KeyCode::Char(' ') => {
                if let Some(r) = self.table.selected().and_then(|i| self.rows.get_mut(i)) {
                    if !r.busy() {
                        r.selected = !r.selected;
                    }
                }
                self.move_cursor(1);
            }
            KeyCode::Char('a') => {
                let all = self.rows.iter().filter(|r| !r.busy()).all(|r| r.selected);
                for r in self.rows.iter_mut().filter(|r| !r.busy()) {
                    r.selected = !all;
                }
            }
            KeyCode::Char('i') | KeyCode::Enter => self.install_selected(),
            _ => {}
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let len = self.rows.len() as isize;
        let cur = self.table.selected().unwrap_or(0) as isize;
        self.table.select(Some((cur + delta).clamp(0, len - 1) as usize));
    }

    /// Queues all checked rows, or the row under the cursor if none are checked.
    fn install_selected(&mut self) {
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| self.rows[i].selected && !self.rows[i].busy())
            .collect();
        if idx.is_empty() {
            if let Some(i) = self.table.selected() {
                if self.rows.get(i).is_some_and(|r| !r.busy()) {
                    idx.push(i);
                }
            }
        }
        if idx.is_empty() {
            return;
        }
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
            let out = Command::new(pm.program()).args(&args).current_dir(&dir).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
                    if text.trim().is_empty() {
                        text = String::from_utf8_lossy(&o.stdout).into_owned();
                    }
                    result = Err(format!("`{} {}` exited with {}\n{}", pm.name(), args.join(" "), o.status, text.trim()));
                    break;
                }
                Err(e) => {
                    result = Err(format!("could not run {}: {e}", pm.name()));
                    break;
                }
            }
        }
        if tx.send(Event::InstallFinished { names: all, result }).is_err() {
            break;
        }
    }
}
