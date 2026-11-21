//! Application state, background workers and key handling.

use crate::audit;
use crate::edit::{self, Change};
use crate::npmrc::Npmrc;
use crate::overrides::{self, Compat, Override, Unneeded};
use crate::package::{self, Dep, Kind, parse_spec};
use crate::pm::Pm;
use crate::registry;
use crate::snyk;
use crate::tree::{Analyzer, Hit};
use crate::view::{self, Child, GroupBy, Item, Overrides, REMOVED, Release, UNNEEDED, VulnView};
use crate::vuln::{Report, Severity, Source, Vuln};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use semver::Version;
use std::collections::{HashMap, HashSet, VecDeque};
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
    /// Overrides that look unnecessary, by key. Empty when it can't be determined.
    Unneeded(Vec<(String, Unneeded)>),
    Scan {
        source: Source,
        result: Result<Report, String>,
    },
    InstallStarted {
        names: Vec<String>,
    },
    InstallFinished {
        names: Vec<String>,
        keys: Vec<String>,
        result: Result<(), String>,
    },
}

/// Messages for the dependency tree analysis thread.
enum TreeMsg {
    Analyze(String),
    SetOverrides(Vec<Override>),
    /// Check which overrides no longer matter, given the project's own (name, range) deps.
    FindUnneeded(Vec<(String, String)>),
    /// `node_modules` changed: forget everything read from disk so far.
    Reset,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Status {
    Idle,
    Queued,
    Installing,
    Failed,
}

/// How a dependency's version range is constrained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionRange {
    /// Exactly this version.
    Exact,
    /// Patch releases only (~).
    Tilde,
    /// Minor and patch releases (^).
    Caret,
    /// Anything newer (>=).
    AtLeast,
}
/// A package uninstalled in this session, kept so it can be restored.
pub struct RemovedPkg {
    pub row: Row,
    /// The range it had in `package.json`.
    pub spec: String,
    pub status: Status,
}
pub struct Row {
    pub name: String,
    pub kind: Kind,
    pub prefix: &'static str,
    pub current: Version,
    pub latest: Version,
    /// False for packages listed only because they have overrides.
    pub outdated: bool,
    pub selected: bool,
    pub status: Status,
    /// Overrides targeting this package, and whether the update is compatible with them.
    pub overrides: Vec<Override>,
    pub compat: Compat,
    /// Overrides applying anywhere in the installed dependency tree of this package.
    pub tree_hits: Vec<Hit>,
    /// Vulnerabilities (Snyk, npm audit, bun audit) in this dependency or anything it brings
    /// in, worst first.
    pub vulns: Vec<Vuln>,
    /// The version Snyk suggests to fix them.
    pub snyk_fix: Option<Version>,
    /// The version `npm audit` / `bun audit` suggests to fix them.
    pub audit_fix: Option<Version>,
    /// The version this package had when the session started, if an install in this session
    /// changed it. Kept in memory only, so the change can be reverted.
    pub changed_from: Option<Version>,
}

impl Row {
    pub fn new_spec(&self) -> String {
        format!("{}{}", self.prefix, self.latest)
    }

    pub fn release(&self) -> Release {
        Release::of(&self.current, &self.latest)
    }

    /// Whether the row's own overrides are listed apart from the row. The row of an overridden
    /// package already shows its single plain override, so repeating it would be noise.
    pub fn lists_own_overrides(&self) -> bool {
        self.kind != Kind::Override
            || self.overrides.len() > 1
            || self.overrides.iter().any(|o| !o.global() || o.range.is_some())
    }
    /// How the version is pinned, from the prefix of its spec.
    pub fn range(&self) -> VersionRange {
        match self.prefix {
            "^" => VersionRange::Caret,
            "~" => VersionRange::Tilde,
            ">=" => VersionRange::AtLeast,
            _ => VersionRange::Exact,
        }
    }
    pub fn busy(&self) -> bool {
        matches!(self.status, Status::Queued | Status::Installing)
    }

    /// Can be installed at its latest version.
    pub fn actionable(&self) -> bool {
        self.outdated && !self.busy()
    }

    /// Can be checked with `space`: there is a newer version or a security fix to install.
    pub fn can_select(&self) -> bool {
        !self.busy() && (self.outdated || self.snyk_fix.is_some() || self.audit_fix.is_some())
    }

    /// The version a vulnerability scanner suggests installing.
    pub fn fix_of(&self, source: Source) -> Option<&Version> {
        if source.is_audit() {
            self.audit_fix.as_ref()
        } else {
            self.snyk_fix.as_ref()
        }
    }

    pub fn worst_severity(&self) -> Option<Severity> {
        self.vulns.iter().map(|v| v.severity).max()
    }
}

/// A newer value for an override entry.
pub struct Update {
    pub value: String,
    pub release: Release,
}

#[derive(Default)]
struct Job {
    /// Packages to uninstall, before anything else runs.
    uninstall: Vec<String>,
    /// (name, spec, kind, exact)
    items: Vec<(String, String, Kind, bool)>,
    edits: Vec<Change>,
    /// Keys of the overrides being edited.
    keys: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanStatus {
    #[default]
    NotRun,
    Running,
    Done {
        total: usize,
        severe: usize,
    },
    Failed,
}

/// State of one vulnerability scanner.
#[derive(Default)]
pub struct Scan {
    pub status: ScanStatus,
    /// An install finished since the last scan: the findings may be out of date.
    pub stale: bool,
    report: Option<Report>,
}

pub struct App {
    pub pm: Pm,
    pub rows: Vec<Row>,
    pub table: ListState,
    pub show_overrides: Overrides,
    pub show_uptodate: bool,
    pub vuln_view: VulnView,
    pub snyk: Scan,
    pub audit: Scan,
    pub view: Vec<Item>,
    pub group_by: GroupBy,
    pub filter: String,
    pub filter_mode: bool,
    /// Waiting for the user to choose the pin type for the packages `P` was pressed on.
    pub pin_prompt: bool,
    pub log: Vec<String>,
    /// The log is expanded to fill the screen and takes the keys (toggled with Tab).
    pub log_focus: bool,
    /// Lines scrolled up from the newest log line.
    pub log_scroll: usize,
    /// Visible log lines while expanded, set by the renderer, used for paging.
    pub log_page: usize,
    pub pending: usize,
    pub total: usize,
    pub registry: String,
    pub quit: bool,
    dir: PathBuf,
    current: HashMap<String, (Kind, &'static str, Version)>,
    /// Names of all direct dependencies, parseable or not.
    direct: HashSet<String>,
    overrides: Vec<Override>,
    /// Latest published version of each overridden package.
    override_latest: HashMap<String, Version>,
    /// Registry settings and HTTP agent, to look up packages that show up after the start.
    rc: Arc<Npmrc>,
    agent: ureq::Agent,
    selected_overrides: HashSet<String>,
    busy_overrides: HashSet<String>,
    /// Overrides that look unnecessary, by key.
    unneeded: HashMap<String, Unneeded>,
    root_deps: Vec<(String, String)>,
    confirm_remove: bool,
    confirm_uninstall: bool,
    /// Packages being reinstalled from the removed section.
    restoring: HashSet<String>,
    pub removed: Vec<RemovedPkg>,
    /// Packages queued for uninstall, whose rows go away when the job succeeds.
    uninstalling: HashSet<String>,
    confirm_pin: bool,
    /// Override keys being added or removed, which call for a rescan.
    changed: HashSet<String>,
    /// False until the first key press: the cursor then stays at the top of the package list.
    cursor_moved: bool,
    tree_tx: Option<Sender<TreeMsg>>,
    events_tx: Sender<Event>,
    /// Target version of each package being installed.
    install_targets: HashMap<String, Version>,
    /// The key (`i` or `f`) that must be pressed again to install despite override conflicts.
    confirm_conflicts: Option<char>,
    quit_warned: bool,
    rx: Receiver<Event>,
    jobs: Sender<Job>,
}

impl App {
    pub fn start(dir: PathBuf, pm: Pm, deps: Vec<Dep>, rc: Npmrc, overrides: Vec<Override>) -> App {
        let (tx, rx) = mpsc::channel();
        let (jobs, job_rx) = mpsc::channel::<Job>();

        let mut current = HashMap::new();
        let mut direct = HashSet::new();
        let mut root_deps = Vec::new();
        let mut names = VecDeque::new();
        for d in deps {
            direct.insert(d.name.clone());
            root_deps.push((d.name.clone(), d.spec.clone()));
            if let Some((prefix, v)) = parse_spec(&d.spec) {
                names.push_back(d.name.clone());
                current.insert(d.name, (d.kind, prefix, v));
            }
        }
        // Overridden packages with a literal version also need their latest version looked up.
        for o in &overrides {
            if parse_spec(&o.value).is_some() && !names.contains(&o.name) {
                names.push_back(o.name.clone());
                if !direct.contains(&o.name)
                    && let Some((prefix, v)) = override_base(&overrides, &o.name)
                {
                    current.insert(o.name.clone(), (Kind::Override, prefix, v));
                }
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

        // Dependency tree analysis is only needed when the project defines overrides.
        let tree_tx = if overrides.is_empty() {
            None
        } else {
            let (msg_tx, msg_rx) = mpsc::channel::<TreeMsg>();
            let (dir, ev_tx, ovr) = (dir.clone(), tx.clone(), overrides.clone());
            thread::spawn(move || {
                let mut analyzer = Analyzer::new(dir, ovr);
                while let Ok(msg) = msg_rx.recv() {
                    match msg {
                        TreeMsg::Reset => analyzer.reset(),
                        TreeMsg::SetOverrides(o) => analyzer.set_overrides(o),
                        TreeMsg::FindUnneeded(roots) => {
                            let found = analyzer.unneeded(&roots);
                            if ev_tx.send(Event::Unneeded(found)).is_err() {
                                break;
                            }
                        }
                        TreeMsg::Analyze(name) => {
                            let hits = analyzer.analyze(&name);
                            if ev_tx.send(Event::Tree { name, hits }).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            let _ = msg_tx.send(TreeMsg::FindUnneeded(root_deps.clone()));
            Some(msg_tx)
        };

        let events_tx = tx.clone();
        // One install worker: package managers don't tolerate parallel installs.
        let worker_dir = dir.clone();
        thread::spawn(move || install_worker(worker_dir, pm, job_rx, tx));

        App {
            pm,
            rows: Vec::new(),
            table: ListState::default(),
            show_overrides: Overrides::Off,
            show_uptodate: true,
            vuln_view: VulnView::All,
            snyk: Scan::default(),
            audit: Scan::default(),
            view: Vec::new(),
            group_by: GroupBy::None,
            filter: String::new(),
            filter_mode: false,
            pin_prompt: false,
            log: Vec::new(),
            log_focus: false,
            log_scroll: 0,
            log_page: 10,
            pending: total,
            total,
            registry,
            quit: false,
            dir,
            current,
            direct,
            overrides,
            override_latest: HashMap::new(),
            rc: rc.clone(),
            agent: agent.clone(),
            selected_overrides: HashSet::new(),
            busy_overrides: HashSet::new(),
            unneeded: HashMap::new(),
            root_deps,
            confirm_remove: false,
            confirm_uninstall: false,
            restoring: HashSet::new(),
            removed: Vec::new(),
            uninstalling: HashSet::new(),
            confirm_pin: false,
            changed: HashSet::new(),
            cursor_moved: false,
            tree_tx,
            events_tx,
            install_targets: HashMap::new(),
            confirm_conflicts: None,
            quit_warned: false,
            rx,
            jobs,
        }
    }

    pub fn loading(&self) -> bool {
        self.pending > 0
    }

    pub fn installing(&self) -> bool {
        !self.busy_overrides.is_empty()
            || self.rows.iter().any(Row::busy)
            || self.removed.iter().any(|p| matches!(p.status, Status::Queued | Status::Installing))
    }

    /// Name of the project directory (the repository name).
    pub fn project_name(&self) -> String {
        self.dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.dir.display().to_string())
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
                        Ok(latest) => self.on_fetched(name, latest),
                        Err(e) => self.push_log(format!("! {name}: {e}")),
                    }
                }
                Event::Tree { name, hits } => self.on_tree(name, hits),
                Event::Scan { source, result } => self.on_scan(source, result),
                Event::Unneeded(found) => {
                    self.unneeded = found.into_iter().collect();
                    self.rebuild_view();
                }
                Event::InstallStarted { names } => {
                    for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                        r.status = Status::Installing;
                    }
                    for p in self.removed.iter_mut().filter(|p| names.contains(&p.row.name)) {
                        p.status = Status::Installing;
                    }
                }
                Event::InstallFinished {
                    names,
                    keys,
                    result,
                } => self.on_install_finished(names, keys, result),
            }
        }
    }

    fn own_overrides(&self, name: &str) -> Vec<Override> {
        self.overrides
            .iter()
            .filter(|o| o.name == name)
            .cloned()
            .collect()
    }

    fn analyze(&self, name: &str) {
        if let Some(tx) = &self.tree_tx {
            let _ = tx.send(TreeMsg::Analyze(name.to_string()));
        }
    }

    fn on_fetched(&mut self, name: String, latest: Version) {
        if self.overrides.iter().any(|o| o.name == name) {
            self.override_latest.insert(name.clone(), latest.clone());
            self.rebuild_view();
        }
        let Some((kind, prefix, cur)) = self.current.get(&name).cloned() else {
            return;
        };
        let own = self.own_overrides(&name);
        let outdated = if kind == Kind::Override {
            own.iter().any(|o| self.update_target(o).is_some())
        } else {
            latest > cur && latest.pre.is_empty()
        };
        let row = |own: Vec<Override>, compat| Row {
            name: name.clone(),
            kind,
            prefix,
            current: cur.clone(),
            latest: latest.clone(),
            outdated,
            selected: false,
            status: Status::Idle,
            overrides: own,
            compat,
            tree_hits: Vec::new(),
            vulns: Vec::new(),
            snyk_fix: None,
            audit_fix: None,
            changed_from: None,
        };
        // Packages that are already up to date are listed too, so their overrides are visible.
        let compat = if outdated && kind != Kind::Override {
            overrides::check(&own, self.pm, &format!("{prefix}{latest}"), &latest)
        } else {
            Compat::Ok
        };
        if kind != Kind::Override {
            self.analyze(&name);
        }
        let r = row(own, compat);
        self.insert_row(r);
    }

    fn on_tree(&mut self, name: String, mut hits: Vec<Hit>) {
        // Risky hits first, so they survive the compact view's cut-off.
        hits.sort_by_key(|h| std::cmp::Reverse(h.risk));
        if let Some(r) = self.rows.iter_mut().find(|r| r.name == name) {
            r.tree_hits = hits;
            self.rebuild_view();
        }
    }

    fn on_install_finished(
        &mut self,
        names: Vec<String>,
        keys: Vec<String>,
        result: Result<(), String>,
    ) {
        let mut removed = false;
        for k in &keys {
            self.busy_overrides.remove(k);
            removed |= self.changed.remove(k);
        }
        let what: Vec<String> = names
            .iter()
            .cloned()
            .chain(keys.iter().map(|k| override_label(k)))
            .collect();
        let mut names = names;
        let gone: Vec<String> = names
            .iter()
            .filter(|n| self.uninstalling.remove(*n))
            .cloned()
            .collect();
        let restored: Vec<String> = names
            .iter()
            .filter(|n| self.restoring.remove(*n))
            .cloned()
            .collect();
        if result.is_ok() {
            names.retain(|n| !gone.contains(n) && !restored.contains(n));
            let (out, keep): (Vec<Row>, Vec<Row>) = std::mem::take(&mut self.rows)
                .into_iter()
                .partition(|r| gone.contains(&r.name));
            self.rows = keep;
            for mut row in out {
                self.current.remove(&row.name);
                self.direct.remove(&row.name);
                row.selected = false;
                row.status = Status::Idle;
                let spec = self
                    .root_deps
                    .iter()
                    .find(|(n, _)| *n == row.name)
                    .map(|(_, s)| s.clone())
                    .unwrap_or_else(|| format!("{}{}", row.prefix, row.current));
                self.removed.push(RemovedPkg {
                    row,
                    spec,
                    status: Status::Idle,
                });
            }
            for n in &restored {
                if let Some(pos) = self.removed.iter().position(|p| p.row.name == *n) {
                    let mut row = self.removed.remove(pos).row;
                    row.status = Status::Idle;
                    self.current
                        .insert(row.name.clone(), (row.kind, row.prefix, row.current.clone()));
                    self.analyze(&row.name);
                    self.insert_row(row);
                }
            }
            if !gone.is_empty() || !restored.is_empty() {
                for scan in [&mut self.snyk, &mut self.audit] {
                    scan.stale |= scan.report.is_some();
                }
            }
        } else {
            names.retain(|n| !restored.contains(n));
            for p in self.removed.iter_mut().filter(|p| restored.contains(&p.row.name)) {
                p.status = Status::Failed;
            }
        }
        match result {
            Ok(()) => {
                self.push_log(format!("✔ done: {}", what.join(", ")));
                if removed {
                    for scan in [&mut self.snyk, &mut self.audit] {
                        scan.stale |= scan.report.is_some();
                    }
                    self.push_log(format!(
                        "⚠ Overrides in package.json changed: run Snyk ({}) and {} ({}) again to check for new vulnerabilities.",
                        scan_key(Source::Snyk),
                        self.audit_source().label(),
                        scan_key(self.audit_source())
                    ));
                }
                // Updated packages are up to date now; they stay in the list as such.
                for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                    // The target is the latest version, or the one Snyk suggested.
                    let target = self
                        .install_targets
                        .remove(&r.name)
                        .unwrap_or_else(|| r.latest.clone());
                    r.outdated = r.latest > target && r.latest.pre.is_empty();
                    if target != r.current {
                        let from = r.changed_from.take().unwrap_or_else(|| r.current.clone());
                        r.changed_from = (from != target).then_some(from);
                    }
                    r.current = target;
                    r.compat = Compat::Ok;
                    r.status = Status::Idle;
                    // The old findings no longer describe what is installed.
                    r.vulns.clear();
                    r.snyk_fix = None;
                    r.audit_fix = None;
                }
                if !names.is_empty() {
                    for scan in [&mut self.snyk, &mut self.audit] {
                        scan.stale |= scan.report.is_some();
                    }
                }
            }
            Err(e) => {
                for n in &names {
                    self.install_targets.remove(n);
                }
                for r in self.rows.iter_mut().filter(|r| names.contains(&r.name)) {
                    r.status = Status::Failed;
                }
                self.push_log(format!("✘ failed {}:", what.join(", ")));
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
        }
        // An install changes `node_modules` and usually `package.json` (also when it failed
        // halfway), so everything derived from them has to be recomputed.
        self.reload_project();
    }

    /// Re-reads `package.json` and re-runs the override analysis against the current
    /// `node_modules`. Called after every install, since updating a package changes what its
    /// dependents ask for, which overrides still matter and which overrides apply where.
    fn reload_project(&mut self) {
        let manifest = match package::read_manifest(&self.dir.join("package.json")) {
            Ok(m) => m,
            Err(e) => {
                self.push_log(format!("! could not reload package.json: {e:#}"));
                self.rebuild_view();
                return;
            }
        };
        // The analysis starts from the project's own dependency ranges, which an update changes.
        self.root_deps = manifest
            .deps
            .iter()
            .map(|d| (d.name.clone(), d.spec.clone()))
            .collect();
        self.direct = manifest.deps.iter().map(|d| d.name.clone()).collect();
        self.overrides = overrides::collect(&manifest.raw, self.pm);

        // Keep the user's selections that still point at an existing override.
        let existing: HashSet<String> = self.overrides.iter().map(Override::key).collect();
        self.selected_overrides.retain(|k| existing.contains(k));
        // Old verdicts are stale until the new analysis arrives.
        self.unneeded.clear();
        // A range change in `package.json` changes how a row's version is pinned.
        for r in self.rows.iter_mut().filter(|r| r.kind != Kind::Override) {
            if let Some((prefix, _)) = manifest
                .deps
                .iter()
                .find(|d| d.name == r.name)
                .and_then(|d| parse_spec(&d.spec))
            {
                r.prefix = prefix;
            }
        }
        self.sync_override_rows();
        for i in 0..self.rows.len() {
            if self.rows[i].kind == Kind::Override {
                continue;
            }
            let own = self.own_overrides(&self.rows[i].name);
            let r = &mut self.rows[i];
            r.compat = if r.outdated {
                overrides::check(&own, self.pm, &r.new_spec(), &r.latest)
            } else {
                Compat::Ok
            };
            r.overrides = own;
        }
        if let Some(tx) = &self.tree_tx {
            // Messages are handled in order, so the caches are cleared before the new work.
            let _ = tx.send(TreeMsg::Reset);
            let _ = tx.send(TreeMsg::SetOverrides(self.overrides.clone()));
            let _ = tx.send(TreeMsg::FindUnneeded(self.root_deps.clone()));
            for r in self.rows.iter().filter(|r| r.kind != Kind::Override) {
                let _ = tx.send(TreeMsg::Analyze(r.name.clone()));
            }
        }
        self.rebuild_view();
    }

    /// Keeps the rows of overridden packages that are not dependencies of the project in step
    /// with `package.json`: drops rows whose overrides are gone, refreshes the others and
    /// adds rows (looking the latest version up if needed) for new overrides.
    fn sync_override_rows(&mut self) {
        let mut names: Vec<String> = Vec::new();
        for o in &self.overrides {
            if !self.direct.contains(&o.name)
                && !names.contains(&o.name)
                && override_base(&self.overrides, &o.name).is_some()
            {
                names.push(o.name.clone());
            }
        }
        self.rows
            .retain(|r| r.kind != Kind::Override || names.contains(&r.name));
        for name in names {
            let Some((prefix, cur)) = override_base(&self.overrides, &name) else {
                continue;
            };
            let own = self.own_overrides(&name);
            if let Some(i) = self
                .rows
                .iter()
                .position(|r| r.kind == Kind::Override && r.name == name)
            {
                let outdated = own.iter().any(|o| self.update_target(o).is_some());
                let r = &mut self.rows[i];
                r.current = cur;
                r.prefix = prefix;
                r.outdated = outdated;
                r.overrides = own;
            } else if let Some(latest) = self.override_latest.get(&name).cloned() {
                self.current
                    .insert(name.clone(), (Kind::Override, prefix, cur));
                self.on_fetched(name, latest);
            } else {
                self.current
                    .insert(name.clone(), (Kind::Override, prefix, cur));
                let (rc, agent, tx) = (self.rc.clone(), self.agent.clone(), self.events_tx.clone());
                thread::spawn(move || {
                    let result = registry::latest_version(&rc, &agent, &name);
                    let _ = tx.send(Event::Fetched { name, result });
                });
            }
        }
    }
    fn insert_row(&mut self, mut row: Row) {
        for (source, scan) in [
            (Source::Snyk, &self.snyk),
            (self.audit_source(), &self.audit),
        ] {
            if let Some(rep) = &scan.report {
                apply_report(source, rep, &mut row);
            }
        }
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
        self.view = view::build(
            &self.rows,
            self.group_by,
            &self.filter,
            self.show_overrides,
            self.show_uptodate,
            self.vuln_view,
        );
        self.append_unneeded_section();
        self.append_removed_section();
        let pos = if self.cursor_moved {
            anchor.and_then(|a| self.view.iter().position(|it| anchor_of(it) == a))
        } else {
            // Before the user interacts, keep the cursor on the first package (or group), not on
            // whatever happened to arrive first, such as the unneeded-overrides section.
            self.view.iter().position(|it| match it {
                Item::Row { .. } => true,
                Item::Header { label, .. } => label != UNNEEDED,
                _ => false,
            })
        };
        let mut sel = pos.unwrap_or_else(|| prev.min(self.view.len().saturating_sub(1)));
        // Fall back to the nearest selectable item above.
        while sel > 0 && !self.selectable(sel) {
            sel -= 1;
        }
        self.table.select((!self.view.is_empty()).then_some(sel));
    }

    /// Lists the overrides that look unnecessary in a section of their own. This is the only
    /// place overrides nobody depends on can show up, as they belong to no package.
    fn append_unneeded_section(&mut self) {
        let needle = self.filter.trim().to_lowercase();
        let mut found: Vec<&Override> = self
            .overrides
            .iter()
            .filter(|o| self.unneeded.contains_key(&o.key()))
            .filter(|o| needle.is_empty() || o.name.to_lowercase().contains(&needle))
            .collect();
        if found.is_empty() {
            return;
        }
        found.sort_by(|a, b| (&a.name, a.key()).cmp(&(&b.name, b.key())));
        let keys: Vec<String> = found.iter().map(|o| o.key()).collect();
        self.view.push(Item::Header {
            label: UNNEEDED.to_string(),
            members: Vec::new(),
        });
        self.view
            .extend(keys.into_iter().map(|key| Item::Override { key }));
    }

    fn append_removed_section(&mut self) {
        let needle = self.filter.trim().to_lowercase();
        let names: Vec<String> = self
            .removed
            .iter()
            .map(|p| p.row.name.clone())
            .filter(|n| needle.is_empty() || n.to_lowercase().contains(&needle))
            .collect();
        if names.is_empty() {
            return;
        }
        self.view.push(Item::Header {
            label: REMOVED.to_string(),
            members: Vec::new(),
        });
        self.view
            .extend(names.into_iter().map(|name| Item::Removed { name }));
    }

    pub fn removed_pkg(&self, name: &str) -> Option<&RemovedPkg> {
        self.removed.iter().find(|p| p.row.name == name)
    }

    /// Reinstalls a package uninstalled in this session, at its old version and range.
    fn restore_removed(&mut self, name: &str) {
        let Some(p) = self.removed.iter_mut().find(|p| p.row.name == name) else {
            return;
        };
        if matches!(p.status, Status::Queued | Status::Installing) {
            return;
        }
        p.status = Status::Queued;
        let version = p.row.current.to_string();
        let item = (name.to_string(), version.clone(), p.row.kind, true);
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        // Install the exact version, then put the original range back in package.json.
        if p.spec != version {
            let field = match p.row.kind {
                Kind::Optional => "optionalDependencies",
                Kind::Dev => "devDependencies",
                _ => "dependencies",
            };
            let loc = vec![field.to_string(), name.to_string()];
            keys.push(loc.join("\u{1f}"));
            edits.push(Change::Set {
                loc,
                old: version.clone(),
                new: p.spec.clone(),
            });
        }
        for k in &keys {
            self.busy_overrides.insert(k.clone());
        }
        self.restoring.insert(name.to_string());
        self.push_log(format!("… queued restore of {name}@{version}"));
        let _ = self.jobs.send(Job {
            items: vec![item],
            edits,
            keys,
            ..Default::default()
        });
    }

    pub fn cursor_item(&self) -> Option<&Item> {
        self.table.selected().and_then(|i| self.view.get(i))
    }

    /// Number of outdated packages currently shown.
    pub fn shown(&self) -> usize {
        self.visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].outdated)
            .count()
    }

    /// Number of up-to-date packages currently shown.
    pub fn shown_up_to_date(&self) -> usize {
        self.visible_rows()
            .into_iter()
            .filter(|&i| !self.rows[i].outdated)
            .count()
    }

    // ---- overrides -------------------------------------------------------------------

    /// The override an item refers to, if it is an override line.
    fn detail_override<'a>(&'a self, item: &Item) -> Option<&'a Override> {
        if let Item::Override { key } = item {
            return self.overrides.iter().find(|o| o.key() == *key);
        }
        let Item::Detail { idx, child, .. } = item else {
            return None;
        };
        let r = self.rows.get(*idx)?;
        match child {
            Child::Own(i) => r.overrides.get(*i),
            Child::Tree(i) => r.tree_hits.get(*i).map(|h| &h.over),
            Child::More(_) | Child::Vuln(_) | Child::MoreVulns(_) => None,
        }
    }

    /// A newer value for the override, if its value is a plain version or range and a newer
    /// version of the overridden package exists.
    pub fn update_target(&self, o: &Override) -> Option<Update> {
        // npm requires an override on a direct dependency to match the dependency's own spec,
        // so it can only change together with the dependency.
        if self.pm == Pm::Npm && o.global() && self.direct.contains(&o.name) {
            return None;
        }
        let latest = self.override_latest.get(&o.name)?;
        let (prefix, cur) = parse_spec(&o.value)?;
        (*latest > cur && latest.pre.is_empty()).then(|| Update {
            value: format!("{prefix}{latest}"),
            release: Release::of(&cur, latest),
        })
    }

    pub fn override_by_key(&self, key: &str) -> Option<&Override> {
        self.overrides.iter().find(|o| o.key() == key)
    }

    /// Why the override looks unnecessary, if it does.
    pub fn unneeded(&self, o: &Override) -> Option<&Unneeded> {
        self.unneeded.get(&o.key())
    }

    /// Every override line can be selected, since any override can be removed.
    fn override_actionable(&self, _o: &Override) -> bool {
        true
    }

    pub fn override_selected(&self, o: &Override) -> bool {
        self.selected_overrides.contains(&o.key())
    }

    pub fn override_busy(&self, o: &Override) -> bool {
        self.busy_overrides.contains(&o.key())
    }

    /// Whether the cursor may rest on `view[i]`.
    fn selectable(&self, i: usize) -> bool {
        match self.view.get(i) {
            Some(item @ (Item::Detail { .. } | Item::Override { .. })) => self
                .detail_override(item)
                .is_some_and(|o| self.override_actionable(o)),
            Some(_) => true,
            None => false,
        }
    }

    /// Distinct overrides in the visible override lines.
    fn visible_overrides(&self) -> Vec<&Override> {
        let mut seen = HashSet::new();
        self.view
            .iter()
            .filter_map(|it| self.detail_override(it))
            .filter(|o| seen.insert(o.key()))
            .collect()
    }

    // ---- hotkey hints ----------------------------------------------------------------

    /// Rows an action acts on: the checked ones that pass `ok`, else the one under the cursor
    /// (every member of a group header) if it passes.
    fn acting_rows(&self, ok: impl Fn(&Row) -> bool) -> Vec<usize> {
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && ok(&self.rows[i]))
            .collect();
        if idx.is_empty() {
            match self.cursor_item() {
                Some(Item::Row { idx: i, .. }) => idx.push(*i),
                Some(Item::Header { members, .. }) => idx.extend(members.iter().copied()),
                _ => {}
            }
            idx.retain(|&i| ok(&self.rows[i]));
        }
        idx
    }

    /// The override under the cursor, if the cursor is on an override line.
    fn cursor_override(&self) -> Option<&Override> {
        self.cursor_item().and_then(|it| self.detail_override(it))
    }

    /// Hotkey hints for the actions that can be performed on the current selection or cursor
    /// item right now.
    pub fn hints(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut item: Vec<String> = Vec::new();
        let mut global: Vec<String> = Vec::new();
        let mut scan: Vec<String> = Vec::new();
        if !self.view.is_empty() {
            global.push("↑/↓ move".into());
        }
        let cursor_selectable = match self.cursor_item() {
            Some(Item::Row { idx, .. }) => self.rows[*idx].can_select(),
            Some(Item::Header { members, .. }) => {
                members.iter().any(|&i| self.rows[i].can_select())
            }
            Some(it) => self.detail_override(it).is_some(),
            None => false,
        };
        if cursor_selectable {
            item.push("space select".into());
        }
        if self.visible_rows().iter().any(|&i| self.rows[i].can_select()) {
            global.push("a all".into());
        }
        let ovr_updatable = |o: &Override| !self.override_busy(o) && self.update_target(o).is_some();
        let install = self
            .visible_overrides()
            .into_iter()
            .any(|o| self.selected_overrides.contains(&o.key()) && ovr_updatable(o))
            || !self.acting_rows(Row::actionable).is_empty()
            || self
                .cursor_override()
                .is_some_and(|o| ovr_updatable(o));
        if install {
            item.push("i install".into());
        }
        global.push("/ filter".into());
        global.push("g group".into());
        global.push("o overrides".into());
        scan.push("s snyk".into());
        if let Some(src) = audit::source_for(self.pm) {
            scan.push(format!("n {}", src.label()));
        }
        if self.snyk.report.is_some() || self.audit.report.is_some() {
            scan.push(format!("v show: {}", self.vuln_view.label()));
        }
        let remove = self
            .visible_overrides()
            .into_iter()
            .any(|o| self.selected_overrides.contains(&o.key()) && !self.override_busy(o))
            || self.cursor_override().is_some_and(|o| !self.override_busy(o));
        if remove {
            item.push("x remove override".into());
        }
        for source in [Source::Snyk, self.audit_source()] {
            if !self.acting_rows(|r| !r.busy() && r.fix_of(source).is_some()).is_empty() {
                item.push(format!(
                    "{} {} fix",
                    fix_key(source),
                    if source.is_audit() { "audit" } else { "snyk" }
                ));
            }
        }
        if !self.acting_rows(|r| !r.busy()).is_empty() {
            item.push("P pin type".into());
        }
        if !self.acting_rows(|r| !r.busy() && !r.vulns.is_empty()).is_empty() {
            item.push("p pin fix as override".into());
        }
        if !self.acting_rows(|r| !r.busy() && r.kind != Kind::Override).is_empty() {
            item.push("d uninstall".into());
        }
        if !self.acting_rows(|r| !r.busy() && r.changed_from.is_some()).is_empty() {
            item.push("r revert".into());
        }
        if let Some(Item::Removed { name }) = self.cursor_item()
            && self
                .removed_pkg(name)
                .is_some_and(|p| !matches!(p.status, Status::Queued | Status::Installing))
        {
            item.push("r restore".into());
        }
        global.push("y copy md".into());
        global.push("tab log".into());
        global.push("q quit".into());
        (item, scan, global)
    }

    // ---- keys ------------------------------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent) {
        self.cursor_moved = true;
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.filter_mode {
            self.on_filter_key(key);
            return;
        }
        if self.pin_prompt {
            self.pin_prompt = false;
            let prefix = match key.code {
                KeyCode::Char('c') => Some("^"),
                KeyCode::Char('t') => Some("~"),
                KeyCode::Char('e') => Some(""),
                KeyCode::Char('m') => Some(">="),
                _ => None,
            };
            match prefix {
                Some(p) => self.set_range(p),
                None => self.push_log("Pin type unchanged."),
            }
            return;
        }
        if key.code == KeyCode::Tab {
            self.log_focus = !self.log_focus;
            return;
        }
        if self.log_focus {
            self.on_log_key(key);
            return;
        }
        if !matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
            self.quit_warned = false;
        }
        if !matches!(
            key.code,
            KeyCode::Char('i') | KeyCode::Char('f') | KeyCode::Char('F') | KeyCode::Enter
        ) {
            self.confirm_conflicts = None;
        }
        if key.code != KeyCode::Char('x') {
            self.confirm_remove = false;
        }
        if key.code != KeyCode::Char('d') {
            self.confirm_uninstall = false;
        }
        if key.code != KeyCode::Char('p') {
            self.confirm_pin = false;
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
                let last = (0..self.view.len()).rev().find(|&i| self.selectable(i));
                self.table.select(last);
            }
            KeyCode::Char(' ') => self.toggle_cursor(),
            KeyCode::Char('a') => {
                let visible: Vec<usize> = self
                    .visible_rows()
                    .into_iter()
                    .filter(|&i| self.rows[i].can_select())
                    .collect();
                let all = visible.iter().all(|&i| self.rows[i].selected);
                for i in visible {
                    self.rows[i].selected = !all;
                }
            }
            KeyCode::Char('i') | KeyCode::Enter => self.install_selected(),
            KeyCode::Char('x') => self.remove_selected(),
            KeyCode::Char('p') => self.pin_selected(),
            KeyCode::Char('P') => self.ask_pin_type(),
            KeyCode::Char('s') => self.start_scan(Source::Snyk),
            KeyCode::Char('n') => self.start_scan(self.audit_source()),
            KeyCode::Char('f') => self.fix_selected(Source::Snyk),
            KeyCode::Char('F') => self.fix_selected(self.audit_source()),
            KeyCode::Char('r') => self.revert_selected(),
            KeyCode::Char('d') => self.uninstall_selected(),
            KeyCode::Char('y') => {
                let md = crate::export::markdown(self);
                match crate::export::copy(&md) {
                    Ok(()) => self.push_log(format!(
                        "✔ copied Markdown report to clipboard ({} lines)",
                        md.lines().count()
                    )),
                    Err(e) => self.push_log(format!("✘ copy failed: {e}")),
                }
            }
            KeyCode::Char('v') => {
                self.vuln_view = self.vuln_view.next();
                self.rebuild_view();
            }
            _ => {}
        }
    }

    fn on_log_key(&mut self, key: KeyEvent) {
        let max = self.log.len().saturating_sub(1);
        let page = self.log_page.max(1);
        match key.code {
            KeyCode::Esc => self.log_focus = false,
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.log_scroll = (self.log_scroll + 1).min(max),
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll = self.log_scroll.saturating_sub(1)
            }
            KeyCode::PageUp => self.log_scroll = (self.log_scroll + page).min(max),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(page),
            KeyCode::Home | KeyCode::Char('g') => self.log_scroll = max,
            KeyCode::End | KeyCode::Char('G') => self.log_scroll = 0,
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
                _ => None,
            })
            .collect()
    }

    /// Space on a package toggles it and moves down; on a group header it toggles the whole
    /// group; on an updatable override line it toggles that override.
    fn toggle_cursor(&mut self) {
        let Some(item) = self.cursor_item().cloned() else {
            return;
        };
        match item {
            Item::Row { idx, .. } => {
                if self.rows[idx].can_select() {
                    self.rows[idx].selected = !self.rows[idx].selected;
                }
                self.move_cursor(1);
            }
            Item::Header { members, .. } => {
                let members: Vec<usize> = members
                    .into_iter()
                    .filter(|&i| self.rows[i].can_select())
                    .collect();
                let all = members.iter().all(|&i| self.rows[i].selected);
                for i in members {
                    self.rows[i].selected = !all;
                }
            }
            Item::Removed { .. } => {}
            Item::Detail { .. } | Item::Override { .. } => {
                let Some(o) = self.detail_override(&item) else {
                    return;
                };
                let key = o.key();
                if self.override_busy(o) || !self.override_actionable(o) {
                    return;
                }
                if !self.selected_overrides.remove(&key) {
                    self.selected_overrides.insert(key);
                }
                self.move_cursor(1);
            }
        }
    }

    /// Moves to the next selectable item in the direction of `delta`.
    fn move_cursor(&mut self, delta: isize) {
        let len = self.view.len() as isize;
        let step = delta.signum();
        let mut i = self.table.selected().unwrap_or(0) as isize;
        let mut remaining = delta.abs();
        while remaining > 0 {
            let mut next = i + step;
            while (0..len).contains(&next) && !self.selectable(next as usize) {
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

    /// Queues the checked packages and overrides. If nothing is checked, queues the item under
    /// the cursor: a package, every package of a group, or an override.
    fn install_selected(&mut self) {
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && self.rows[i].actionable())
            .collect();
        let mut ovr: Vec<(Override, String)> = self
            .visible_overrides()
            .into_iter()
            .filter(|o| self.selected_overrides.contains(&o.key()) && !self.override_busy(o))
            .filter_map(|o| Some((o.clone(), self.update_target(o)?.value)))
            .collect();

        if idx.is_empty() && ovr.is_empty() {
            match self.cursor_item().cloned() {
                Some(Item::Row { idx: i, .. }) => idx.push(i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                Some(item @ (Item::Detail { .. } | Item::Override { .. })) => {
                    if let Some(o) = self.detail_override(&item)
                        && !self.override_busy(o)
                        && let Some(u) = self.update_target(o)
                    {
                        ovr.push((o.clone(), u.value));
                    }
                }
                Some(Item::Removed { .. }) | None => {}
            }
            idx.retain(|&i| self.rows[i].actionable());
        }
        // Rows of overridden packages are updated by editing their overrides.
        let (over_rows, idx): (Vec<usize>, Vec<usize>) = idx
            .into_iter()
            .partition(|&i| self.rows[i].kind == Kind::Override);
        for &i in &over_rows {
            self.rows[i].selected = false;
        }
        for i in over_rows {
            for o in &self.rows[i].overrides {
                if !self.override_busy(o)
                    && !ovr.iter().any(|(p, _)| p.key() == o.key())
                    && let Some(u) = self.update_target(o)
                {
                    ovr.push((o.clone(), u.value));
                }
            }
        }
        if idx.is_empty() && ovr.is_empty() {
            return;
        }
        let pkgs = idx
            .into_iter()
            .map(|i| (i, self.rows[i].latest.clone()))
            .collect();
        self.dispatch('i', pkgs, ovr);
    }

    /// Uninstalls the checked packages, or the one under the cursor. Asks to press `d` again.
    fn uninstall_selected(&mut self) {
        let can = |a: &App, i: usize| a.rows[i].kind != Kind::Override && !a.rows[i].busy();
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && can(self, i))
            .collect();
        if idx.is_empty() {
            if let Some(Item::Row { idx: i, .. }) = self.cursor_item().cloned() {
                idx.push(i);
            }
            idx.retain(|&i| can(self, i));
        }
        if idx.is_empty() {
            self.push_log("Nothing to uninstall: put the cursor on a package, or select some with space.");
            return;
        }
        let names: Vec<String> = idx.iter().map(|&i| self.rows[i].name.clone()).collect();
        if !self.confirm_uninstall {
            self.confirm_uninstall = true;
            self.push_log(format!(
                "✂ will uninstall: {}. Press d again to confirm, any other key cancels.",
                names.join(", ")
            ));
            return;
        }
        self.confirm_uninstall = false;
        for &i in &idx {
            self.rows[i].selected = false;
            self.rows[i].status = Status::Queued;
        }
        self.uninstalling.extend(names.iter().cloned());
        self.push_log(format!("… queued uninstall of {}", names.join(", ")));
        let _ = self.jobs.send(Job {
            uninstall: names,
            ..Default::default()
        });
    }
    /// Reinstalls the version the checked packages (or the one under the cursor) had when the
    /// session started. Only packages changed in this session can be reverted.
    fn revert_selected(&mut self) {
        if let Some(Item::Removed { name }) = self.cursor_item().cloned() {
            self.restore_removed(&name);
            return;
        }
        let can = |a: &App, i: usize| a.rows[i].changed_from.is_some() && !a.rows[i].busy();
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && can(self, i))
            .collect();
        if idx.is_empty() {
            match self.cursor_item().cloned() {
                Some(Item::Row { idx: i, .. }) => idx.push(i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                _ => {}
            }
            idx.retain(|&i| can(self, i));
        }
        if idx.is_empty() {
            self.push_log("Nothing to revert: put the cursor on a package changed in this session.");
            return;
        }
        let mut items = Vec::new();
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        let mut what = Vec::new();
        for i in idx {
            let r = &mut self.rows[i];
            let Some(from) = r.changed_from.clone() else {
                continue;
            };
            r.selected = false;
            r.status = Status::Queued;
            what.push(format!("{}@{from}", r.name));
            // Install the exact version: a range such as ^1.2.3 would pick the newest match.
            items.push((r.name.clone(), from.to_string(), r.kind, true));
            self.install_targets.insert(r.name.clone(), from.clone());
            // Then restore the original pin type in package.json; the lockfile keeps `from`.
            if !r.prefix.is_empty() && r.kind != Kind::Override {
                let field = match r.kind {
                    Kind::Prod => "dependencies",
                    Kind::Dev => "devDependencies",
                    _ => "optionalDependencies",
                };
                let loc = vec![field.to_string(), r.name.clone()];
                keys.push(loc.join("\u{1f}"));
                edits.push(Change::Set {
                    loc,
                    old: from.to_string(),
                    new: format!("{}{from}", r.prefix),
                });
            }
        }
        for k in &keys {
            self.busy_overrides.insert(k.clone());
        }
        self.push_log(format!("… queued revert to {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            items,
            edits,
            keys,
            ..Default::default()
        });
    }
    /// Installs the version `source` suggests for the checked packages, or for the one under
    /// the cursor (every package of a group when on a group header).
    fn fix_selected(&mut self, source: Source) {
        let has_fix = |a: &App, i: usize| a.rows[i].fix_of(source).is_some() && !a.rows[i].busy();
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && has_fix(self, i))
            .collect();
        if idx.is_empty() {
            match self.cursor_item().cloned() {
                Some(Item::Row { idx: i, .. }) => idx.push(i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                _ => {}
            }
            idx.retain(|&i| has_fix(self, i));
        }
        if idx.is_empty() {
            let (scan_key, name) = (scan_key(source), source.label());
            let msg = if self.scan(source).report.is_none() {
                format!("No {name} data yet. Press {scan_key} to scan.")
            } else {
                format!(
                    "No {name} fix for the selection: put the cursor on a package marked ✱ that has one."
                )
            };
            self.push_log(msg);
            return;
        }
        let pkgs = idx
            .into_iter()
            .filter_map(|i| Some((i, self.rows[i].fix_of(source)?.clone())))
            .collect();
        self.dispatch(fix_key(source), pkgs, Vec::new());
    }

    /// Queues the installs of `pkgs` (row index, version to install) and the override updates.
    /// `key` is the key the user pressed, which must be pressed again to go ahead when an
    /// update clashes with an override.
    fn dispatch(&mut self, key: char, pkgs: Vec<(usize, Version)>, ovr: Vec<(Override, String)>) {
        if pkgs.is_empty() && ovr.is_empty() {
            return;
        }
        // Updates that clash with an override need an explicit second press.
        let conflicts: Vec<&str> = pkgs
            .iter()
            .filter(|(i, target)| {
                let r = &self.rows[*i];
                let spec = format!("{}{target}", r.prefix);
                overrides::check(&r.overrides, self.pm, &spec, target) == Compat::Conflict
            })
            .map(|(i, _)| self.rows[*i].name.as_str())
            .collect();
        if !conflicts.is_empty() && self.confirm_conflicts != Some(key) {
            let msg = format!(
                "⚠ conflicts with overrides: {}. Press {key} again to install anyway, any other key cancels.",
                conflicts.join(", ")
            );
            self.confirm_conflicts = Some(key);
            self.push_log(msg);
            return;
        }
        self.confirm_conflicts = None;

        let mut items = Vec::new();
        for (i, target) in pkgs {
            let r = &mut self.rows[i];
            r.selected = false;
            r.status = Status::Queued;
            items.push((
                r.name.clone(),
                format!("{}{target}", r.prefix),
                r.kind,
                r.prefix.is_empty(),
            ));
            self.install_targets.insert(r.name.clone(), target);
        }
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        for (o, new) in ovr {
            keys.push(o.key());
            self.selected_overrides.remove(&o.key());
            self.busy_overrides.insert(o.key());
            edits.push(Change::Set {
                loc: o.loc.clone(),
                old: o.value.clone(),
                new,
            });
        }
        let mut what: Vec<String> = items.iter().map(|i| format!("{}@{}", i.0, i.1)).collect();
        what.extend(keys.iter().map(|k| override_label(k)));
        self.push_log(format!("… queued {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            items,
            edits,
            keys,
            ..Default::default()
        });
    }

    // ---- vulnerability scans -----------------------------------------------------------

    /// The source the package manager's own audit command reports as.
    pub fn audit_source(&self) -> Source {
        audit::source_for(self.pm).unwrap_or(Source::NpmAudit)
    }

    fn scan(&self, source: Source) -> &Scan {
        if source.is_audit() {
            &self.audit
        } else {
            &self.snyk
        }
    }

    fn scan_mut(&mut self, source: Source) -> &mut Scan {
        if source.is_audit() {
            &mut self.audit
        } else {
            &mut self.snyk
        }
    }

    fn start_scan(&mut self, source: Source) {
        if self.scan(source).status == ScanStatus::Running {
            return;
        }
        if source.is_audit() && audit::source_for(self.pm).is_none() {
            let msg = format!(
                "✘ {}: auditing is supported for npm and bun projects. Snyk (s) works with any package manager",
                self.pm.name()
            );
            self.push_log(msg);
            return;
        }
        self.scan_mut(source).status = ScanStatus::Running;
        self.push_log(match source {
            Source::Snyk => {
                "… scanning with Snyk (this sends the dependency list to Snyk)".to_string()
            }
            _ => format!(
                "… running {} (advisories come from your registry)",
                source.label()
            ),
        });
        let (dir, tx, pm) = (self.dir.clone(), self.events_tx.clone(), self.pm);
        let roots = self.root_deps.clone();
        thread::spawn(move || {
            let result = if source.is_audit() {
                audit::scan(pm, &dir, &roots)
            } else {
                snyk::scan(&dir)
            };
            let _ = tx.send(Event::Scan { source, result });
        });
    }

    fn on_scan(&mut self, source: Source, result: Result<Report, String>) {
        let name = source.label();
        match result {
            Err(e) => {
                self.scan_mut(source).status = ScanStatus::Failed;
                self.push_log(format!("✘ {name}: {e}"));
            }
            Ok(report) => {
                for w in &report.warnings {
                    self.push_log(format!("! {name}: {}", w.lines().next().unwrap_or("")));
                }
                for r in &mut self.rows {
                    apply_report(source, &report, r);
                }
                let severe = report
                    .vulns
                    .iter()
                    .filter(|v| v.severity >= Severity::High)
                    .count();
                let scan = self.scan_mut(source);
                scan.status = ScanStatus::Done {
                    total: report.vulns.len(),
                    severe,
                };
                scan.stale = false;

                let shown: HashSet<&str> = self.rows.iter().map(|r| r.name.as_str()).collect();
                let hidden: HashSet<&str> = report
                    .vulns
                    .iter()
                    .map(|v| v.direct.as_str())
                    .filter(|d| !shown.contains(d))
                    .collect();
                let fixes = self
                    .rows
                    .iter()
                    .filter(|r| r.fix_of(source).is_some())
                    .count();
                if report.vulns.is_empty() {
                    self.push_log(format!("✔ {name}: no known vulnerabilities"));
                } else {
                    self.push_log(format!(
                        "✔ {name}: {} vulnerabilities ({severe} high or critical), fixes suggested for {fixes} package(s). Press {} to apply.",
                        report.vulns.len(),
                        fix_key(source)
                    ));
                }
                if !hidden.is_empty() {
                    let mut names: Vec<&str> = hidden.into_iter().collect();
                    names.sort();
                    self.push_log(format!(
                        "! {name}: findings in packages not listed here: {}",
                        names.join(", ")
                    ));
                }
                self.scan_mut(source).report = Some(report);
            }
        }
        self.rebuild_view();
    }
}

/// The key that starts a scan with `source`.
pub fn scan_key(source: Source) -> char {
    if source.is_audit() { 'n' } else { 's' }
}

/// The key that installs the version `source` suggests.
pub fn fix_key(source: Source) -> char {
    if source.is_audit() { 'F' } else { 'f' }
}

/// Copies the findings and the suggested fix for `row` out of `report`, replacing what the
/// same kind of scanner found before. Findings of the other scanner are kept.
fn apply_report(source: Source, report: &Report, row: &mut Row) {
    row.vulns
        .retain(|v| v.source.is_audit() != source.is_audit());
    row.vulns.extend(
        report
            .vulns
            .iter()
            .filter(|v| v.direct == row.name)
            .cloned(),
    );
    row.vulns.sort_by(|a, b| {
        (std::cmp::Reverse(a.severity), &a.id).cmp(&(std::cmp::Reverse(b.severity), &b.id))
    });
    let fix = report.fixes.get(&row.name).cloned();
    if source.is_audit() {
        row.audit_fix = fix;
    } else {
        row.snyk_fix = fix;
    }
}

impl App {
    /// Removes the checked overrides that look unnecessary, or the one under the cursor.
    /// Asks for a second press first, since the verdict is a heuristic.
    fn remove_selected(&mut self) {
        let mut targets: Vec<Override> = self
            .visible_overrides()
            .into_iter()
            .filter(|o| self.selected_overrides.contains(&o.key()))
            .filter(|o| !self.override_busy(o))
            .cloned()
            .collect();
        if targets.is_empty()
            && let Some(item) = self.cursor_item().cloned()
            && let Some(o) = self.detail_override(&item)
            && !self.override_busy(o)
        {
            targets.push(o.clone());
        }
        if targets.is_empty() {
            self.push_log("Nothing to remove: put the cursor on an override, or select some with space.");
            return;
        }

        if !self.confirm_remove {
            self.confirm_remove = true;
            let names: Vec<String> = targets.iter().map(|o| o.describe()).collect();
            self.push_log(format!(
                "✂ will remove from package.json: {}. Press x again to confirm, any other key cancels.",
                names.join("; ")
            ));
            if targets.iter().any(|o| self.unneeded(o).is_none()) {
                self.push_log(
                    "⚠ Not flagged as unneeded: changed it can change which versions get installed and reintroduce vulnerabilities.",
                );
            }
            return;
        }
        self.confirm_remove = false;

        let mut edits = Vec::new();
        let mut keys = Vec::new();
        for o in &targets {
            keys.push(o.key());
            self.changed.insert(o.key());
            self.selected_overrides.remove(&o.key());
            self.busy_overrides.insert(o.key());
            edits.push(Change::Remove {
                loc: o.loc.clone(),
                old: o.value.clone(),
            });
        }
        let what: Vec<String> = keys.iter().map(|k| override_label(k)).collect();
        self.push_log(format!("… queued removal of {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            items: Vec::new(),
            edits,
            keys,
            ..Default::default()
        });
    }
}

/// The version an overridden package is at: the lowest of its overrides that name a literal
/// version, with that override's prefix.
fn override_base(overrides: &[Override], name: &str) -> Option<(&'static str, Version)> {
    overrides
        .iter()
        .filter(|o| o.name == name)
        .filter_map(|o| parse_spec(&o.value))
        .min_by(|a, b| a.1.cmp(&b.1))
}
impl App {
    /// The packages `P` acts on: the checked ones, or the one under the cursor (every package
    /// of a group on a header).
    fn range_targets(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected)
            .collect();
        if idx.is_empty() {
            match self.cursor_item().cloned() {
                Some(Item::Row { idx: i, .. }) => idx.push(i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                _ => {}
            }
        }
        idx.retain(|&i| !self.rows[i].busy());
        idx
    }
    /// Asks which pin type to use for the packages `P` acts on.
    fn ask_pin_type(&mut self) {
        if self.range_targets().is_empty() {
            self.push_log("Nothing to change: put the cursor on a package.");
            return;
        }
        self.pin_prompt = true;
    }
    /// Changes how the packages are pinned, in `package.json`, keeping their version.
    /// Overridden packages change the prefix of their overrides.
    fn set_range(&mut self, to: &'static str) {
        let idx = self.range_targets();
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        let mut what = Vec::new();
        for i in idx {
            let r = &self.rows[i];
            if r.kind == Kind::Override {
                for o in &r.overrides {
                    if self.override_busy(o) {
                        continue;
                    }
                    if let Some(new) = respecced(&o.value, to) {
                        keys.push(o.key());
                        what.push(format!("{} {} → {new}", r.name, o.value));
                        edits.push(Change::Set {
                            loc: o.loc.clone(),
                            old: o.value.clone(),
                            new,
                        });
                    }
                }
                continue;
            }
            let field = match r.kind {
                Kind::Prod => "dependencies",
                Kind::Dev => "devDependencies",
                _ => "optionalDependencies",
            };
            let loc = vec![field.to_string(), r.name.clone()];
            let key = loc.join("\u{1f}");
            let Some(old) = self
                .root_deps
                .iter()
                .find(|(n, _)| *n == r.name)
                .map(|(_, s)| s.clone())
            else {
                continue;
            };
            let Some(new) = respecced(&old, to) else {
                continue;
            };
            if self.busy_overrides.contains(&key) {
                continue;
            }
            // npm insists that an override of a direct dependency equals the dependency's spec.
            if self.pm == Pm::Npm {
                for o in r.overrides.iter().filter(|o| o.global() && o.value == old) {
                    keys.push(o.key());
                    edits.push(Change::Set {
                        loc: o.loc.clone(),
                        old: o.value.clone(),
                        new: new.clone(),
                    });
                }
            }
            what.push(format!("{} {old} → {new}", r.name));
            keys.push(key);
            edits.push(Change::Set { loc, old, new });
        }
        if edits.is_empty() {
            self.push_log("Nothing to change: the packages already have that pin type, or their versions are not plain versions or ranges.");
            return;
        }
        for k in &keys {
            self.busy_overrides.insert(k.clone());
        }
        for r in self.rows.iter_mut() {
            r.selected = false;
        }
        self.push_log(format!("… queued range change: {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            items: Vec::new(),
            edits,
            keys,
            ..Default::default()
        });
    }
}
/// An override that pins a vulnerable transitive package to a fixed version.
struct Pin {
    name: String,
    version: Version,
    /// An existing override of the package that is too old, to be raised instead of adding one.
    existing: Option<Override>,
}
impl App {
    /// The version of a vulnerable package to pin: the lowest fix in the installed major
    /// release (or the lowest newer one), and the highest of those over all its findings.
    fn pin_plan(&mut self, idx: &[usize]) -> Vec<Pin> {
        let mut want: Vec<(String, Version)> = Vec::new();
        for &i in idx {
            for v in &self.rows[i].vulns {
                if v.path.is_empty() || v.package == v.direct {
                    continue;
                }
                let fixes: Vec<Version> = v
                    .newer_fixes()
                    .into_iter()
                    .filter_map(|f| Version::parse(f).ok())
                    .collect();
                let major = Version::parse(&v.version).ok().map(|i| i.major);
                let Some(fix) = fixes
                    .iter()
                    .find(|f| Some(f.major) == major)
                    .or(fixes.first())
                else {
                    continue;
                };
                match want.iter_mut().find(|(n, _)| *n == v.package) {
                    Some((_, cur)) => *cur = (*cur).clone().max(fix.clone()),
                    None => want.push((v.package.clone(), fix.clone())),
                }
            }
        }
        let mut plan = Vec::new();
        for (name, version) in want {
            if self.direct.contains(&name) {
                self.push_log(format!(
                    "{name} is also a direct dependency: update it instead of overriding it."
                ));
                continue;
            }
            let existing = self
                .overrides
                .iter()
                .find(|o| o.name == name && o.global() && o.range.is_none())
                .cloned();
            if let Some(o) = &existing {
                match overrides::min_version(&o.value) {
                    Some(v) if v >= version => {
                        self.push_log(format!("{name} is already overridden to {}.", o.value));
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        self.push_log(format!(
                            "{name} has an override ({}) I can't compare: edit it by hand.",
                            o.value
                        ));
                        continue;
                    }
                }
            }
            plan.push(Pin {
                name,
                version,
                existing,
            });
        }
        plan
    }
    /// Where a new override of `name` goes in `package.json` for the package manager.
    fn new_override_loc(&self, name: &str) -> Vec<String> {
        let (root, nested): (&[&str], bool) = match self.pm {
            Pm::Npm | Pm::Bun => (&["overrides"], true),
            Pm::Yarn => (&["resolutions"], false),
            Pm::Pnpm => (&["pnpm", "overrides"], false),
        };
        let mut loc: Vec<String> = root.iter().map(|s| s.to_string()).collect();
        loc.push(name.to_string());
        // npm keeps the override of a package that has nested overrides under `.`.
        if nested
            && self
                .overrides
                .iter()
                .any(|o| o.loc.len() > loc.len() && o.loc[..loc.len()] == loc[..])
        {
            loc.push(".".to_string());
        }
        loc
    }
    /// Adds overrides that pin the vulnerable transitive packages of the checked packages (or
    /// of the one under the cursor) to the version the scanners say fixes them. Asks for a
    /// second press first.
    fn pin_selected(&mut self) {
        let mut idx: Vec<usize> = self
            .visible_rows()
            .into_iter()
            .filter(|&i| self.rows[i].selected && !self.rows[i].busy())
            .collect();
        if idx.is_empty() {
            match self.cursor_item().cloned() {
                Some(Item::Row { idx: i, .. }) => idx.push(i),
                Some(Item::Header { members, .. }) => idx.extend(members),
                _ => {}
            }
            idx.retain(|&i| !self.rows[i].busy());
        }
        let plan = self.pin_plan(&idx);
        if plan.is_empty() {
            self.push_log("Nothing to pin: put the cursor on a package with a vulnerable dependency that a scan found a fixed version for.");
            return;
        }
        let key_name = match self.pm {
            Pm::Yarn => "resolutions",
            Pm::Pnpm => "pnpm.overrides",
            _ => "overrides",
        };
        if !self.confirm_pin {
            self.confirm_pin = true;
            let names: Vec<String> = plan
                .iter()
                .map(|p| format!("{} → ^{}", p.name, p.version))
                .collect();
            self.push_log(format!(
                "📌 will set in package.json {key_name}: {}. Press p again to confirm, any other key cancels.",
                names.join("; ")
            ));
            self.push_log(
                "⚠ This forces a version the dependents didn't ask for and can break them. Test the app afterwards, then run Snyk and the audit again.",
            );
            return;
        }
        self.confirm_pin = false;
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        for p in &plan {
            let new = format!("^{}", p.version);
            let (loc, change) = match &p.existing {
                Some(o) => (
                    o.loc.clone(),
                    Change::Set {
                        loc: o.loc.clone(),
                        old: o.value.clone(),
                        new,
                    },
                ),
                None => {
                    let loc = self.new_override_loc(&p.name);
                    (loc.clone(), Change::Add { loc, new })
                }
            };
            let key = loc.join("\u{1f}");
            self.changed.insert(key.clone());
            self.busy_overrides.insert(key.clone());
            keys.push(key);
            edits.push(change);
        }
        let what: Vec<String> = plan.iter().map(|p| format!("{}@^{}", p.name, p.version)).collect();
        self.push_log(format!("… queued override {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            items: Vec::new(),
            edits,
            keys,
            ..Default::default()
        });
    }
}
/// Human-readable name of an override from its key (the last path element).
fn override_label(key: &str) -> String {
    let mut parts = key.split('\u{1f}');
    let (first, last) = (parts.next().unwrap_or(key), parts.last());
    match last {
        Some(name) if DEP_FIELDS.contains(&first) => format!("version range of {name}"),
        _ => format!("override {}", last.unwrap_or(first)),
    }
}
const DEP_FIELDS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];
/// `spec` with the range type `prefix` (`^`, `~`, `>=` or none for exact), if it is a plain
/// version or range that isn't of that type already.
fn respecced(spec: &str, prefix: &str) -> Option<String> {
    let (old, v) = parse_spec(spec)?;
    (old != prefix).then(|| format!("{prefix}{v}"))
}

/// Identity of a list item that survives index changes.
fn anchor_of(item: &Item) -> (u8, String) {
    match item {
        Item::Header { label, .. } => (0, label.clone()),
        Item::Row { name, .. } => (1, name.clone()),
        Item::Override { key } => (3, key.clone()),
        Item::Removed { name } => (4, name.clone()),
        Item::Detail {
            row, key, child, ..
        } => (
            2,
            match child {
                Child::More(_) | Child::MoreVulns(_) => format!("{row}\u{0}more"),
                _ => format!("{row}\u{0}{key}"),
            },
        ),
    }
}

fn install_worker(dir: PathBuf, pm: Pm, jobs: Receiver<Job>, tx: Sender<Event>) {
    while let Ok(job) = jobs.recv() {
        let names: Vec<String> = job
            .items
            .iter()
            .map(|i| i.0.clone())
            .chain(job.uninstall.iter().cloned())
            .collect();
        let _ = tx.send(Event::InstallStarted {
            names: names.clone(),
        });
        let result = run_job(&dir, pm, &job);
        if tx
            .send(Event::InstallFinished {
                names,
                keys: job.keys,
                result,
            })
            .is_err()
        {
            break;
        }
    }
}

fn run_job(dir: &std::path::Path, pm: Pm, job: &Job) -> Result<(), String> {
    if !job.uninstall.is_empty() {
        run_pm(dir, pm, &pm.uninstall_args(&job.uninstall))?;
    }
    // One command per (kind, exact) group.
    let mut groups: Vec<((Kind, bool), Vec<String>)> = Vec::new();
    for (name, spec, kind, exact) in &job.items {
        let arg = format!("{name}@{spec}");
        match groups.iter_mut().find(|(k, _)| *k == (*kind, *exact)) {
            Some((_, v)) => v.push(arg),
            None => groups.push(((*kind, *exact), vec![arg])),
        }
    }
    for ((kind, exact), specs) in groups {
        run_pm(dir, pm, &pm.install_args(&specs, kind, exact))?;
    }

    if !job.edits.is_empty() {
        edit::apply(&dir.join("package.json"), &job.edits).map_err(|e| format!("{e:#}"))?;
        run_pm(dir, pm, &["install".to_string()])
            .map_err(|e| format!("package.json was updated, but the install failed:\n{e}"))?;
    }
    Ok(())
}

fn run_pm(dir: &std::path::Path, pm: Pm, args: &[String]) -> Result<(), String> {
    match Command::new(pm.program())
        .args(args)
        .current_dir(dir)
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
            if text.trim().is_empty() {
                text = String::from_utf8_lossy(&o.stdout).into_owned();
            }
            Err(format!(
                "`{} {}` exited with {}\n{}",
                pm.name(),
                args.join(" "),
                o.status,
                text.trim()
            ))
        }
        Err(e) => Err(format!("could not run {}: {e}", pm.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ovr(name: &str, value: &str, key: &str) -> Override {
        Override {
            name: name.into(),
            range: None,
            value: value.into(),
            source: "overrides",
            path: Vec::new(),
            loc: vec!["overrides".into(), key.into()],
        }
    }
    #[test]
    fn pin_type_changes_keep_the_version() {
        assert_eq!(respecced("^1.2.3", "~").as_deref(), Some("~1.2.3"));
        assert_eq!(respecced("^1.2.3", "").as_deref(), Some("1.2.3"));
        assert_eq!(respecced("1.2.3", "^").as_deref(), Some("^1.2.3"));
        assert_eq!(respecced("~1.2.3", ">=").as_deref(), Some(">=1.2.3"));
        assert_eq!(respecced("^1.2.3", "^"), None);
        assert_eq!(respecced("latest", "^"), None);
        assert_eq!(respecced("workspace:*", "^"), None);
    }

    #[test]
    fn override_base_is_the_lowest_literal_version() {
        let all = [
            ovr("foo", "^2.1.0", "a"),
            ovr("foo", "$foo", "b"),
            ovr("foo", "~1.4.0", "c"),
            ovr("bar", "9.0.0", "d"),
        ];
        let (prefix, v) = override_base(&all, "foo").unwrap();
        assert_eq!((prefix, v.to_string()), ("~", "1.4.0".to_string()));
        assert!(override_base(&[ovr("x", "$y", "a")], "x").is_none());
        assert!(override_base(&all, "missing").is_none());
    }
}
