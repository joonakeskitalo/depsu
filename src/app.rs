//! Application state, background workers and key handling.

use crate::audit;
use crate::cache::{Cache, Findings};
use crate::edit::{self, Change};
use crate::npmrc::Npmrc;
use crate::overrides::{self, Compat, Override, Unneeded};
use crate::package::{self, Dep, Kind, parse_spec};
use crate::peers;
use crate::pm::Pm;
use crate::registry;
use crate::snyk;
use crate::tree::{Analyzer, Dependent, Hit};
use crate::view::{self, Child, GroupBy, Item, Overrides, REMOVED, Release, UNNEEDED};
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
    /// Installed packages that depend on each package, by name.
    Dependents(HashMap<String, Vec<Dependent>>),
    Scan {
        source: Source,
        result: Result<Report, String>,
    },
    InstallStarted {
        names: Vec<String>,
    },
    /// The peer dependency check of an install is done.
    PeerCheck {
        plan: Vec<(String, Version)>,
        ovr: Vec<(Override, String)>,
        report: peers::Report,
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
    /// Find which installed packages depend on which, given the project's own deps.
    FindDependents(Vec<(String, String)>),
    /// `node_modules` changed: forget everything read from disk so far.
    Reset,
}

#[derive(Clone, Copy, PartialEq, Debug)]
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
/// An install waiting for the user to decide about the other packages it needs changed.
pub struct PeerPrompt {
    /// What the user asked to install: (name, version).
    pub plan: Vec<(String, Version)>,
    ovr: Vec<(Override, String)>,
    /// The other packages that can be updated so that everything fits.
    pub extra: Vec<(String, Version)>,
    /// Every package that has to change, and whether depsu can update it.
    pub needs: Vec<(peers::Need, bool)>,
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
    /// The version changed since the last vulnerability scan, so the findings (or their
    /// absence) no longer describe what is installed.
    pub scan_outdated: bool,
    /// The latest version hasn't arrived from the registry yet.
    pub loading: bool,
    /// Looking up the latest version failed.
    pub latest_failed: bool,
    /// The resolved version: what the lockfile pins, or else what `node_modules` holds. The
    /// scanners look at this one, not at the range in `package.json` (`current`). `None` when
    /// neither says, e.g. a project that was never installed and has no lockfile.
    pub installed: Option<Version>,
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
    /// The version findings are recorded under: the resolved version. Never the version in
    /// `package.json`, which the scanners don't look at.
    pub fn scanned_version(&self) -> Option<String> {
        self.installed.as_ref().map(Version::to_string)
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

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
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
    /// Some findings may be out of date: a package is installed at a version this scanner
    /// hasn't looked at, or the overrides changed what gets installed below the packages.
    pub stale: bool,
    /// The overrides changed since the last scan, which changes the transitive dependencies
    /// without changing the version of any of the project's own packages.
    pub deps_changed: bool,
    report: Option<Report>,
}

pub struct App {
    pub pm: Pm,
    pub rows: Vec<Row>,
    pub table: ListState,
    pub show_overrides: Overrides,
    pub show_uptodate: bool,
    pub show_vulns: bool,
    /// The panel with details of the item under the cursor.
    pub show_info: bool,
    pub snyk: Scan,
    pub audit: Scan,
    pub view: Vec<Item>,
    pub group_by: GroupBy,
    pub filter: String,
    pub filter_mode: bool,
    /// Waiting for the user to choose the pin type for the packages `P` was pressed on.
    pub pin_prompt: bool,
    /// An install is waiting for the answer to a question about its peer dependencies.
    pub peer_prompt: Option<PeerPrompt>,
    /// The peer dependencies of an install are being checked.
    peer_checking: bool,
    pub log: Vec<String>,
    /// The log is expanded to fill the screen and takes the keys (toggled with Tab).
    pub log_focus: bool,
    /// Lines scrolled up from the newest log line.
    pub log_scroll: usize,
    /// Visible log lines while expanded, set by the renderer, used for paging.
    pub log_page: usize,
    /// Latest versions and findings per package version. Always kept in memory; written to
    /// `cache_path` when `--cache` was given.
    cache: Cache,
    cache_path: Option<PathBuf>,
    cache_dirty: bool,
    cache_error_logged: bool,
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
    /// Installed packages that depend on each package.
    pub dependents: HashMap<String, Vec<Dependent>>,
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
    pub fn start(
        dir: PathBuf,
        pm: Pm,
        deps: Vec<Dep>,
        rc: Npmrc,
        overrides: Vec<Override>,
        cache_path: Option<PathBuf>,
    ) -> App {
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

        let rc = Arc::new(rc);
        let agent = registry::agent();

        // Dependency tree analysis is only needed when the project defines overrides.
        let tree_tx = {
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
                        TreeMsg::FindDependents(roots) => {
                            let found = analyzer.dependents(&roots);
                            if ev_tx.send(Event::Dependents(found)).is_err() {
                                break;
                            }
                        }
                        TreeMsg::Analyze(name) => {
                            if !analyzer.has_overrides() {
                                continue;
                            }
                            let hits = analyzer.analyze(&name);
                            if ev_tx.send(Event::Tree { name, hits }).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            let _ = msg_tx.send(TreeMsg::FindUnneeded(root_deps.clone()));
            let _ = msg_tx.send(TreeMsg::FindDependents(root_deps.clone()));
            Some(msg_tx)
        };

        let events_tx = tx.clone();
        // One install worker: package managers don't tolerate parallel installs.
        let worker_dir = dir.clone();
        thread::spawn(move || install_worker(worker_dir, pm, job_rx, tx));

        let mut app = App {
            pm,
            rows: Vec::new(),
            table: ListState::default(),
            show_overrides: Overrides::Off,
            show_uptodate: true,
            show_vulns: true,
            show_info: false,
            snyk: Scan::default(),
            audit: Scan::default(),
            view: Vec::new(),
            group_by: GroupBy::None,
            filter: String::new(),
            filter_mode: false,
            pin_prompt: false,
            peer_prompt: None,
            peer_checking: false,
            log: Vec::new(),
            log_focus: false,
            log_scroll: 0,
            log_page: 10,
            cache: Cache::default(),
            cache_path: None,
            cache_dirty: false,
            cache_error_logged: false,
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
            dependents: HashMap::new(),
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
        };
        app.add_placeholder_rows();
        if let Some(path) = cache_path {
            match Cache::load(&path) {
                Ok(c) => {
                    app.cache = c;
                    app.cache_path = Some(path);
                }
                // An unreadable cache is left alone rather than overwritten.
                Err(e) => app.push_log(format!("! cache not used: {e:#}")),
            }
        }
        app.apply_cached_scans();
        app.begin_fetch(names.into_iter().collect(), true);
        app
    }

    /// Starts looking up the latest version of `names`. With `use_cache`, versions found in
    /// the cache file are used without asking the registry.
    fn begin_fetch(&mut self, names: Vec<String>, use_cache: bool) {
        self.pending = names.len();
        self.total = names.len();
        let mut queue = VecDeque::new();
        let mut cached = 0;
        for name in names {
            let hit = use_cache
                .then(|| {
                    self.cache
                        .latest
                        .get(&name)
                        .and_then(|v| Version::parse(v).ok())
                })
                .flatten();
            match hit {
                Some(v) => {
                    cached += 1;
                    let _ = self.events_tx.send(Event::Fetched {
                        name,
                        result: Ok(v),
                    });
                }
                None => queue.push_back(name),
            }
        }
        if cached > 0 {
            self.push_log(format!("… {cached} latest version(s) loaded from the cache, R fetches them again"));
        }
        let workers = registry::CONCURRENCY.min(queue.len());
        let queue = Arc::new(Mutex::new(queue));
        for _ in 0..workers {
            let (queue, rc, agent, tx) = (
                queue.clone(),
                self.rc.clone(),
                self.agent.clone(),
                self.events_tx.clone(),
            );
            thread::spawn(move || {
                while let Some(name) = queue.lock().unwrap().pop_front() {
                    let result = registry::latest_version(&rc, &agent, &name);
                    if tx.send(Event::Fetched { name, result }).is_err() {
                        break;
                    }
                }
            });
        }
    }

    /// Looks the latest versions up again, ignoring the cache.
    fn refetch_latest(&mut self) {
        if self.loading() {
            self.push_log("Already checking the latest versions.");
            return;
        }
        let mut names: Vec<String> = self.rows.iter().map(|r| r.name.clone()).collect();
        for o in &self.overrides {
            if parse_spec(&o.value).is_some() && !names.contains(&o.name) {
                names.push(o.name.clone());
            }
        }
        if names.is_empty() {
            return;
        }
        for r in self.rows.iter_mut() {
            r.loading = true;
            r.latest_failed = false;
        }
        self.push_log(format!("… fetching the latest versions of {} package(s)", names.len()));
        self.begin_fetch(names, false);
        self.rebuild_view();
    }

    // ---- cache -------------------------------------------------------------------------

    fn cache_latest(&mut self, name: &str, latest: &Version) {
        let v = latest.to_string();
        if self.cache.latest.get(name) != Some(&v) {
            self.cache.latest.insert(name.to_string(), v);
            self.cache_dirty = true;
        }
    }

    /// Records what a scan found for each listed package, under the version the scanner
    /// looked at: the one it names in its findings, or else the resolved version. Packages
    /// whose version is unknown are not recorded, since a result under a guessed version
    /// would show up for the wrong version later.
    fn cache_scan(&mut self, source: Source, report: &Report) {
        let project = self.project_key();
        let mut mismatched = Vec::new();
        for r in self.rows.iter_mut() {
            let mut by_version: HashMap<Option<String>, Vec<Vuln>> = HashMap::new();
            for v in report.vulns.iter().filter(|v| v.direct == r.name) {
                by_version
                    .entry(v.direct_version.clone())
                    .or_default()
                    .push(v.clone());
            }
            let resolved = r.installed.as_ref().map(Version::to_string);
            // A version depsu couldn't determine is learned from the scanner.
            if resolved.is_none()
                && let Some(v) = by_version
                    .keys()
                    .flatten()
                    .next()
                    .and_then(|v| Version::parse(v).ok())
            {
                r.installed = Some(v);
            }
            let resolved = r.installed.as_ref().map(Version::to_string);
            for scanned in by_version.keys().flatten() {
                if resolved.as_ref().is_some_and(|r| r != scanned) {
                    mismatched.push(format!(
                        "{}@{scanned} (depsu sees {})",
                        r.name,
                        resolved.as_deref().unwrap_or("?")
                    ));
                }
            }
            // Findings without a version of their own belong to the resolved version.
            let untagged = by_version.remove(&None).unwrap_or_default();
            let mut groups: HashMap<String, Vec<Vuln>> = by_version
                .into_iter()
                .filter_map(|(k, v)| Some((k?, v)))
                .collect();
            if let Some(res) = &resolved {
                groups.entry(res.clone()).or_default().extend(untagged);
            }
            let scans = self.cache.scans_mut(&project);
            for (version, vulns) in groups {
                let fix = (resolved.as_ref() == Some(&version) || resolved.is_none())
                    .then(|| report.fixes.get(&r.name).cloned())
                    .flatten();
                scans.set_findings(source.label(), &r.name, &version, Findings { vulns, fix });
            }
        }
        if !mismatched.is_empty() {
            self.push_log(format!(
                "⚠ {} scanned other versions than depsu sees: {}. node_modules may be out of date with the lockfile, run an install.",
                source.label(),
                mismatched.join(", ")
            ));
        }
        self.cache_dirty = true;
    }

    /// Reads the resolved version of each listed package: the lockfile's, or else the one in
    /// `node_modules`.
    fn read_installed_versions(&mut self) {
        let lock = crate::tree::npm_lock_versions(&self.dir);
        for r in self.rows.iter_mut() {
            r.installed = resolved_version(&self.dir, lock.as_ref(), &r.name);
        }
    }

    /// Identifies this project's scan results in the cache: its directory.
    fn project_key(&self) -> String {
        self.dir.display().to_string()
    }

    /// The scanners that have results, from a scan or from the cache.
    fn scanned_sources(&self) -> Vec<Source> {
        [(Source::Snyk, &self.snyk), (self.audit_source(), &self.audit)]
            .into_iter()
            .filter(|(_, s)| s.report.is_some())
            .map(|(src, _)| src)
            .collect()
    }

    /// Gives every row the findings recorded for the version it is installed at. A row whose
    /// version a scanner hasn't looked at gets none of that scanner's findings and is marked
    /// as not scanned, and that scanner's results count as out of date.
    fn refresh_findings(&mut self) {
        let sources = self.scanned_sources();
        let mut missing: HashSet<Source> = HashSet::new();
        let project = self.project_key();
        let project_scans = self.cache.scans(&project);
        for r in self.rows.iter_mut() {
            r.vulns.clear();
            r.snyk_fix = None;
            r.audit_fix = None;
            r.scan_outdated = false;
            let version = r.scanned_version();
            for &source in &sources {
                let found = version
                    .as_ref()
                    .and_then(|ver| project_scans?.findings(source.label(), &r.name, ver));
                match found {
                    Some(f) => {
                        r.vulns.extend(f.vulns.iter().cloned());
                        if source.is_audit() {
                            r.audit_fix = f.fix.clone();
                        } else {
                            r.snyk_fix = f.fix.clone();
                        }
                    }
                    None => {
                        r.scan_outdated = true;
                        missing.insert(source);
                    }
                }
            }
            r.vulns.sort_by(|a, b| {
                (std::cmp::Reverse(a.severity), &a.id).cmp(&(std::cmp::Reverse(b.severity), &b.id))
            });
        }
        for source in sources {
            let scan = self.scan_mut(source);
            scan.stale = scan.deps_changed || missing.contains(&source);
        }
    }

    /// Shows the findings stored in the cache for the versions installed now.
    fn apply_cached_scans(&mut self) {
        let mut sources = vec![Source::Snyk];
        if audit::source_for(self.pm).is_some() {
            sources.push(self.audit_source());
        }
        for source in sources {
            let project = self.project_key();
            let project_scans = self.cache.scans(&project);
            let mut report = Report::default();
            let mut missing = 0;
            for r in &self.rows {
                match r
                    .scanned_version()
                    .and_then(|ver| project_scans?.findings(source.label(), &r.name, &ver))
                {
                    Some(f) => {
                        report.vulns.extend(f.vulns.iter().cloned());
                        if let Some(fix) = &f.fix {
                            report.fixes.insert(r.name.clone(), fix.clone());
                        }
                    }
                    None => missing += 1,
                }
            }
            if missing == self.rows.len() {
                continue; // nothing cached for these versions
            }
            self.push_log(if missing == 0 {
                format!("… {} results loaded from the cache", source.label())
            } else {
                format!(
                    "… {} results loaded from the cache; {missing} package(s) haven't been scanned at their installed version, scan again",
                    source.label()
                )
            });
            self.apply_scan(source, report, true);
        }
        self.rebuild_view();
    }

    fn flush_cache(&mut self) {
        if !self.cache_dirty {
            return;
        }
        self.cache_dirty = false;
        if let Some(path) = &self.cache_path
            && let Err(e) = self.cache.save(path)
            && !self.cache_error_logged
        {
            self.cache_error_logged = true;
            self.push_log(format!("! could not write the cache: {e:#}"));
        }
    }

    /// Lists every dependency right away, before the registry has answered. The rows are
    /// updated in place when the latest versions arrive.
    fn add_placeholder_rows(&mut self) {
        let mut rows: Vec<Row> = self
            .current
            .iter()
            .filter(|(_, (kind, _, _))| *kind != Kind::Override)
            .map(|(name, (kind, prefix, cur))| Row {
                name: name.clone(),
                kind: *kind,
                prefix,
                current: cur.clone(),
                latest: cur.clone(),
                outdated: false,
                selected: false,
                status: Status::Idle,
                overrides: self.own_overrides(name),
                compat: Compat::Ok,
                tree_hits: Vec::new(),
                vulns: Vec::new(),
                snyk_fix: None,
                audit_fix: None,
                changed_from: None,
                scan_outdated: false,
                loading: true,
                latest_failed: false,
                installed: None,
            })
            .collect();
        rows.sort_by(|a, b| (a.kind.label(), &a.name).cmp(&(b.kind.label(), &b.name)));
        self.rows = rows;
        self.read_installed_versions();
        self.rebuild_view();
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
                        Ok(latest) => {
                            self.cache_latest(&name, &latest);
                            self.on_fetched(name, latest);
                        }
                        Err(e) => {
                            if let Some(r) = self.rows.iter_mut().find(|r| r.name == name) {
                                r.loading = false;
                                r.latest_failed = true;
                            }
                            self.push_log(format!("! {name}: {e}"));
                            self.rebuild_view();
                        }
                    }
                }
                Event::Tree { name, hits } => self.on_tree(name, hits),
                Event::Dependents(map) => self.dependents = map,
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
                Event::PeerCheck { plan, ovr, report } => self.on_peer_check(plan, ovr, report),
                Event::InstallFinished {
                    names,
                    keys,
                    result,
                } => self.on_install_finished(names, keys, result),
            }
        }
        self.flush_cache();
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
        // A row that is already listed (at startup, or when fetching again) is updated in place.
        if let Some(i) = self.rows.iter().position(|r| r.name == name) {
            let own = self.own_overrides(&name);
            let (cur, prefix) = (self.rows[i].current.clone(), self.rows[i].prefix);
            let outdated = if kind == Kind::Override {
                own.iter().any(|o| self.update_target(o).is_some())
            } else {
                latest > cur && latest.pre.is_empty()
            };
            let compat = if outdated && kind != Kind::Override {
                overrides::check(&own, self.pm, &format!("{prefix}{latest}"), &latest)
            } else {
                Compat::Ok
            };
            let r = &mut self.rows[i];
            r.latest = latest;
            r.outdated = outdated;
            r.compat = compat;
            r.overrides = own;
            r.loading = false;
            r.latest_failed = false;
            if kind != Kind::Override {
                self.analyze(&name);
            }
            self.rebuild_view();
            return;
        }
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
            scan_outdated: false,
            loading: false,
            latest_failed: false,
            installed: None,
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
        // Risky hits first, so they come first in the list.
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
                        scan.deps_changed |= scan.report.is_some();
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
        // Rows at a new version get the findings recorded for that version, if any.
        self.read_installed_versions();
        self.refresh_findings();
        self.rebuild_view();
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
            let _ = tx.send(TreeMsg::FindDependents(self.root_deps.clone()));
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
        let lock = crate::tree::npm_lock_versions(&self.dir);
        row.installed = resolved_version(&self.dir, lock.as_ref(), &row.name);
        // Keep rows sorted by (kind, name) so late arrivals don't shuffle randomly.
        let key = |r: &Row| (r.kind.label(), r.name.clone());
        let pos = self.rows.partition_point(|r| key(r) < key(&row));
        self.rows.insert(pos, row);
        self.refresh_findings();
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
            self.show_vulns,
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

    /// Installed packages that depend on `name`, one entry per name and version.
    pub fn dependents_of(&self, name: &str) -> Vec<&Dependent> {
        let mut out: Vec<&Dependent> = Vec::new();
        for d in self.dependents.get(name).into_iter().flatten() {
            if !out.iter().any(|o| o.name == d.name && o.version == d.version) {
                out.push(d);
            }
        }
        out
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
            Child::Vuln(_) => None,
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
            Some(Item::Detail {
                child: Child::Vuln(_),
                ..
            }) => true,
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
        global.push("R fetch versions".into());
        global.push(format!("? details: {}", if self.show_info { "on" } else { "off" }));
        global.push("g group".into());
        global.push("o overrides".into());
        scan.push("s snyk".into());
        if let Some(src) = audit::source_for(self.pm) {
            scan.push(format!("n {}", src.label()));
        }
        if self.snyk.report.is_some() || self.audit.report.is_some() {
            scan.push(format!("v vulns: {}", if self.show_vulns { "shown" } else { "hidden" }));
        }
        let remove = self
            .visible_overrides()
            .into_iter()
            .any(|o| self.selected_overrides.contains(&o.key()) && !self.override_busy(o))
            || self.cursor_override().is_some_and(|o| !self.override_busy(o))
            || matches!(self.cursor_item(), Some(Item::Row { idx, .. })
                if self.rows[*idx].overrides.iter().any(|o| !self.override_busy(o)));
        if remove {
            item.push("x remove override".into());
        }
        if matches!(self.cursor_vuln_fix(), Some(Ok(_))) {
            item.push("i install fix".into());
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
        if let Some(p) = self.peer_prompt.take() {
            match key.code {
                KeyCode::Char('y') => {
                    let mut plan = p.plan;
                    plan.extend(p.extra);
                    self.queue_install(plan, p.ovr);
                }
                KeyCode::Char('n') if !p.extra.is_empty() => self.queue_install(p.plan, p.ovr),
                _ => self.push_log("Install cancelled."),
            }
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
            KeyCode::Char('i') | KeyCode::Enter
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
            KeyCode::Char('?') => self.show_info = !self.show_info,
            KeyCode::Char('R') => self.refetch_latest(),
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
                self.show_vulns = !self.show_vulns;
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
    /// The package and version that fix the vulnerability under the cursor, if it is on one.
    /// `Err` explains why there is nothing to install.
    fn cursor_vuln_fix(&self) -> Option<Result<(usize, Version), String>> {
        let Some(Item::Detail {
            idx,
            child: Child::Vuln(i),
            ..
        }) = self.cursor_item()
        else {
            return None;
        };
        let r = &self.rows[*idx];
        let v = r.vulns.get(*i)?;
        if r.busy() {
            return Some(Err(format!("{} is being installed.", r.name)));
        }
        let target = v
            .upgrade_to
            .as_ref()
            .and_then(|t| Version::parse(t).ok())
            .or_else(|| r.fix_of(v.source).cloned());
        Some(match target {
            Some(t) => Ok((*idx, t)),
            None => Err(format!("No fix to install for {}: {}.", v.id, v.fix_summary())),
        })
    }

    fn install_selected(&mut self) {
        // On a vulnerability: install the version that fixes it.
        if let Some(fix) = self.cursor_vuln_fix()
            && !self.rows.iter().any(|r| r.selected && r.actionable())
        {
            match fix {
                Ok((i, target)) => self.dispatch('i', vec![(i, target)], Vec::new()),
                Err(msg) => self.push_log(msg),
            }
            return;
        }
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
        let plan: Vec<(String, Version)> = pkgs
            .into_iter()
            .map(|(i, v)| (self.rows[i].name.clone(), v))
            .collect();
        if plan.is_empty() {
            self.queue_install(plan, ovr);
            return;
        }
        if self.peer_checking {
            self.push_log("Still checking the peer dependencies of the previous install.");
            return;
        }
        self.peer_checking = true;
        let names: Vec<String> = plan.iter().map(|(n, v)| format!("{n}@{v}")).collect();
        self.push_log(format!("… checking peer dependencies of {}", names.join(", ")));
        let direct: Vec<String> = self
            .rows
            .iter()
            .filter(|r| r.kind != Kind::Override)
            .map(|r| r.name.clone())
            .collect();
        let (dir, rc, agent, tx) = (
            self.dir.clone(),
            self.rc.clone(),
            self.agent.clone(),
            self.events_tx.clone(),
        );
        thread::spawn(move || {
            let lock = crate::tree::npm_lock_versions(&dir);
            let installed = |n: &str| resolved_version(&dir, lock.as_ref(), n);
            let installed_peers = |n: &str| crate::tree::installed_peers(&dir, n);
            let fetch = |n: &str| registry::packument(&rc, &agent, n);
            let report = peers::check(
                &plan,
                &peers::Project {
                    direct: &direct,
                    installed: &installed,
                    installed_peers: &installed_peers,
                    fetch: &fetch,
                },
            );
            let _ = tx.send(Event::PeerCheck { plan, ovr, report });
        });
    }

    /// Installs right away if nothing else has to change, otherwise asks.
    fn on_peer_check(
        &mut self,
        plan: Vec<(String, Version)>,
        ovr: Vec<(Override, String)>,
        report: peers::Report,
    ) {
        self.peer_checking = false;
        for w in &report.warnings {
            self.push_log(format!("! {w}"));
        }
        if report.needs.is_empty() {
            self.queue_install(plan, ovr);
            return;
        }
        let mut extra = Vec::new();
        let mut needs = Vec::new();
        let what: Vec<String> = plan.iter().map(|(n, v)| format!("{n}@{v}")).collect();
        let mut lines = vec![format!(
            "⚠ Installing {} needs other packages to change:",
            what.join(", ")
        )];
        for n in &report.needs {
            let updatable = self
                .rows
                .iter()
                .any(|r| r.name == n.name && r.kind != Kind::Override && !r.busy());
            needs.push((n.clone(), updatable && n.to.is_some()));
            match &n.to {
                Some(to) if updatable => {
                    lines.push(format!("  {} {} → {to}: {}", n.name, n.from, n.why));
                    extra.push((n.name.clone(), to.clone()));
                }
                _ => {
                    lines.push(format!(
                        "  ! {} {}: no version depsu can install fits: {}",
                        n.name, n.from, n.why
                    ));
                }
            }
        }
        for l in lines {
            self.push_log(l);
        }
        // The answer must not land in the filter or the pin type prompt.
        self.filter_mode = false;
        self.pin_prompt = false;
        self.peer_prompt = Some(PeerPrompt {
            plan,
            ovr,
            extra,
            needs,
        });
    }

    /// Queues the installs of `plan` (name, version) and the override updates.
    fn queue_install(&mut self, plan: Vec<(String, Version)>, ovr: Vec<(Override, String)>) {
        let mut items = Vec::new();
        for (name, target) in plan {
            let Some(r) = self.rows.iter_mut().find(|r| r.name == name) else {
                continue;
            };
            if r.busy() {
                continue;
            }
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
        if items.is_empty() && ovr.is_empty() {
            return;
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
            Ok(report) => self.apply_scan(source, report, false),
        }
        self.rebuild_view();
    }

    /// Shows the findings of a scan. Scans that just ran are written to the cache; ones read
    /// from it are not.
    fn apply_scan(&mut self, source: Source, report: Report, from_cache: bool) {
        let name = source.label();
        for w in &report.warnings {
            self.push_log(format!("! {name}: {}", w.lines().next().unwrap_or("")));
        }
        if !from_cache {
            self.cache_scan(source, &report);
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
        if !from_cache {
            scan.deps_changed = false;
        }

        let shown: HashSet<&str> = self.rows.iter().map(|r| r.name.as_str()).collect();
        let hidden: HashSet<&str> = report
            .vulns
            .iter()
            .map(|v| v.direct.as_str())
            .filter(|d| !shown.contains(d))
            .collect();
        let fixes = report
            .fixes
            .keys()
            .filter(|n| shown.contains(n.as_str()))
            .count();
        if report.vulns.is_empty() {
            self.push_log(format!("✔ {name}: no known vulnerabilities"));
        } else {
            self.push_log(format!(
                "✔ {name}: {} vulnerabilities ({severe} high or critical), fixes suggested for {fixes} package(s). Move onto a finding and press i to install its fix.",
                report.vulns.len()
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
        self.refresh_findings();
    }
}

/// The version of `name` the scanners see: the one npm's lockfile pins, or else the one in
/// `node_modules`.
fn resolved_version(
    dir: &std::path::Path,
    lock: Option<&HashMap<String, Version>>,
    name: &str,
) -> Option<Version> {
    lock.and_then(|l| l.get(name).cloned())
        .or_else(|| crate::tree::installed_version(dir, name))
}

/// The key that starts a scan with `source`.
pub fn scan_key(source: Source) -> char {
    if source.is_audit() { 'n' } else { 's' }
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
        // On a package: all overrides that target it.
        if targets.is_empty()
            && let Some(Item::Row { idx, .. }) = self.cursor_item().cloned()
        {
            targets.extend(
                self.rows[idx]
                    .overrides
                    .iter()
                    .filter(|o| !self.override_busy(o))
                    .cloned(),
            );
        }
        if targets.is_empty() {
            self.push_log("Nothing to remove: put the cursor on an override or on a package that has one, or select overrides with space.");
            return;
        }

        if !self.confirm_remove {
            self.confirm_remove = true;
            let names: Vec<String> = targets.iter().map(|o| o.describe()).collect();
            self.push_log(format!(
                "✂ will remove from package.json: {}. Press x again to confirm, any other key cancels.",
                names.join("; ")
            ));
            for o in &targets {
                let users = self.dependents_of(&o.name);
                if users.is_empty() {
                    continue;
                }
                let mut names: Vec<&str> = users.iter().map(|d| d.name.as_str()).collect();
                names.sort();
                names.dedup();
                let more = names.len().saturating_sub(5);
                let mut list = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
                if more > 0 {
                    list.push_str(&format!(", +{more} more"));
                }
                self.push_log(format!(
                    "⚠ {} is used by {list}: removing its override can change which version they get.",
                    o.name
                ));
            }
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
    use crate::cache::Scans;
    fn vuln(direct: &str, version: &str, id: &str) -> Vuln {
        Vuln {
            source: Source::Snyk,
            id: id.into(),
            title: "Bad".into(),
            severity: Severity::High,
            package: direct.into(),
            version: version.into(),
            direct: direct.into(),
            direct_version: Some(version.into()),
            path: Vec::new(),
            fixed_in: vec!["1.0.1".into()],
            upgrade_to: Some("1.0.1".into()),
            upgrade_brings: None,
            upgrade_major: false,
            range: None,
            fix_note: None,
            cve: Vec::new(),
        }
    }
    fn found(direct: &str, version: &str, id: &str) -> Findings {
        Findings {
            vulns: vec![vuln(direct, version, id)],
            fix: Some(Version::new(1, 0, 1)),
        }
    }

    /// Starts an app on a project with dependencies `a` and `b`, both installed at 1.0.0,
    /// with a cache file prepared by `fill`. Every latest version is in the cache, so nothing
    /// is fetched from the network.
    fn app_with_cache(latest_a: &str, fill: impl FnOnce(&mut Scans)) -> App {
        app_with_installed(latest_a, &[("a", "1.0.0"), ("b", "1.0.0")], fill)
    }
    /// Writes `node_modules/<name>/package.json` with `version`.
    fn install(dir: &std::path::Path, name: &str, version: &str) {
        let d = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), format!(r#"{{"name":"{name}","version":"{version}"}}"#)).unwrap();
    }
    /// Like `app_with_cache`, with the given packages installed in `node_modules`.
    fn app_with_installed(
        latest_a: &str,
        installed: &[(&str, &str)],
        fill: impl FnOnce(&mut Scans),
    ) -> App {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "depsu-app-cache-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, version) in installed {
            install(&dir, name, version);
        }
        let mut cache = Cache::default();
        cache.latest.insert("a".into(), latest_a.into());
        cache.latest.insert("b".into(), "1.0.0".into());
        fill(cache.scans_mut(&dir.display().to_string()));
        let path = dir.join("cache.json");
        cache.save(&path).unwrap();
        let deps = ["a", "b"]
            .iter()
            .map(|n| Dep {
                name: n.to_string(),
                spec: "^1.0.0".into(),
                kind: Kind::Prod,
            })
            .collect();
        let mut app = App::start(
            dir.clone(),
            Pm::Npm,
            deps,
            Npmrc::load(&dir),
            Vec::new(),
            Some(path),
        );
        app.drain_events();
        app
    }
    fn row<'a>(app: &'a App, name: &str) -> &'a Row {
        app.rows.iter().find(|r| r.name == name).unwrap()
    }
    /// This project's scan results in the in-memory cache.
    fn stored(app: &App) -> &Scans {
        app.cache.scans(&app.project_key()).unwrap()
    }
    fn ids(app: &App, name: &str) -> Vec<String> {
        row(app, name).vulns.iter().map(|v| v.id.clone()).collect()
    }
    /// What an install of `name` at `version` does to the row, without running a package
    /// manager.
    fn switch_version(app: &mut App, name: &str, version: &str) {
        install(&app.dir.clone(), name, version);
        app.read_installed_versions();
        app.refresh_findings();
    }

    #[test]
    fn cached_findings_apply_when_the_scanned_versions_are_installed() {
        let app = app_with_cache("1.0.0", |c| {
            c.set_findings("snyk", "a", "1.0.0", found("a", "1.0.0", "A-1"));
            c.set_findings("snyk", "b", "1.0.0", found("b", "1.0.0", "B-1"));
        });
        assert_eq!(ids(&app, "a"), ["A-1"]);
        assert_eq!(ids(&app, "b"), ["B-1"]);
        assert!(row(&app, "a").snyk_fix.is_some());
        assert!(!row(&app, "a").scan_outdated);
        assert!(!app.snyk.stale);
        assert_eq!(app.snyk.status, ScanStatus::Done { total: 2, severe: 2 });
    }

    #[test]
    fn cached_findings_of_another_version_are_not_shown() {
        // Only a@0.9.0 was scanned, but a@1.0.0 is installed.
        let app = app_with_cache("1.0.0", |c| {
            c.set_findings("snyk", "a", "0.9.0", found("a", "0.9.0", "A-OLD"));
            c.set_findings("snyk", "b", "1.0.0", found("b", "1.0.0", "B-1"));
        });
        let a = row(&app, "a");
        assert!(a.vulns.is_empty(), "findings of another version must not show");
        assert!(a.snyk_fix.is_none());
        assert!(a.scan_outdated);
        // `b` is at the scanned version, so its findings still apply.
        assert_eq!(ids(&app, "b"), ["B-1"]);
        assert!(!row(&app, "b").scan_outdated);
        assert!(app.snyk.stale, "a package hasn't been scanned at its version");
    }

    #[test]
    fn each_version_keeps_its_own_findings_when_switching_back_and_forth() {
        let mut app = app_with_cache("1.1.0", |c| {
            c.set_findings("snyk", "a", "1.0.0", found("a", "1.0.0", "A-OLD"));
            // 1.1.0 was scanned and found clean.
            c.set_findings("snyk", "a", "1.1.0", Findings::default());
            c.set_findings("snyk", "b", "1.0.0", Findings::default());
        });
        assert_eq!(ids(&app, "a"), ["A-OLD"]);

        switch_version(&mut app, "a", "1.1.0");
        assert!(row(&app, "a").vulns.is_empty(), "1.1.0 is clean");
        assert!(row(&app, "a").snyk_fix.is_none());
        assert!(!row(&app, "a").scan_outdated, "1.1.0 was scanned");
        assert!(!app.snyk.stale);

        switch_version(&mut app, "a", "1.2.0");
        assert!(row(&app, "a").vulns.is_empty());
        assert!(row(&app, "a").scan_outdated, "1.2.0 was never scanned");
        assert!(app.snyk.stale);

        // Back to the first version: its findings come back.
        switch_version(&mut app, "a", "1.0.0");
        assert_eq!(ids(&app, "a"), ["A-OLD"]);
        assert!(!row(&app, "a").scan_outdated);
        assert!(!app.snyk.stale);
    }

    #[test]
    fn a_scan_is_recorded_for_the_versions_installed_at_the_time() {
        let mut app = app_with_cache("1.0.0", |_| {});
        let mut report = Report::default();
        report.vulns = vec![vuln("a", "1.0.0", "A-1")];
        app.apply_scan(Source::Snyk, report, false);
        assert_eq!(ids(&app, "a"), ["A-1"]);
        // Upgrading `a` hides the finding: the new version hasn't been scanned.
        switch_version(&mut app, "a", "1.1.0");
        assert!(row(&app, "a").vulns.is_empty());
        assert!(row(&app, "a").scan_outdated);
        // The scan was stored per version, also for the clean package `b`.
        assert_eq!(stored(&app).findings("snyk", "a", "1.0.0").unwrap().vulns.len(), 1);
        assert!(stored(&app).findings("snyk", "a", "1.1.0").is_none());
        assert!(stored(&app).findings("snyk", "b", "1.0.0").unwrap().vulns.is_empty());
        // ... and it was written to the file.
        app.flush_cache();
        let on_disk = Cache::load(app.cache_path.as_ref().unwrap()).unwrap();
        assert_eq!(on_disk.scans(&app.project_key()).unwrap().findings("snyk", "a", "1.0.0").unwrap().vulns[0].id, "A-1");
    }

    #[test]
    fn scanners_are_kept_apart() {
        let app = app_with_cache("1.0.0", |c| {
            c.set_findings("snyk", "a", "1.0.0", found("a", "1.0.0", "SNYK-A"));
            c.set_findings("snyk", "b", "1.0.0", Findings::default());
            // npm audit looked at another version of `a`.
            let mut f = found("a", "0.9.0", "NPM-A");
            f.vulns[0].source = Source::NpmAudit;
            c.set_findings("npm audit", "a", "0.9.0", f);
            c.set_findings("npm audit", "b", "1.0.0", Findings::default());
        });
        assert_eq!(ids(&app, "a"), ["SNYK-A"]);
        assert!(row(&app, "a").audit_fix.is_none());
        assert!(row(&app, "a").scan_outdated, "npm audit hasn't seen a@1.0.0");
        assert!(!app.snyk.stale);
        assert!(app.audit.stale);
    }

    #[test]
    fn findings_are_keyed_by_the_installed_version_not_the_package_json_one() {
        // package.json asks for ^1.0.0, but 1.0.5 is what is installed and was scanned.
        let mut app = app_with_installed("1.0.5", &[("a", "1.0.5")], |c| {
            c.set_findings("snyk", "a", "1.0.0", found("a", "1.0.0", "A-1.0.0"));
            c.set_findings("snyk", "a", "1.0.5", found("a", "1.0.5", "A-1.0.5"));
            c.set_findings("snyk", "b", "1.0.0", Findings::default());
        });
        assert_eq!(row(&app, "a").current, Version::new(1, 0, 0));
        assert_eq!(row(&app, "a").installed, Some(Version::new(1, 0, 5)));
        assert_eq!(ids(&app, "a"), ["A-1.0.5"]);
        assert!(!row(&app, "a").scan_outdated);
        // `b` isn't installed and there's no lockfile: its version is unknown, so no
        // finding is looked up for it, not even under the package.json version.
        assert!(row(&app, "b").installed.is_none());
        assert!(row(&app, "b").vulns.is_empty());
        assert!(row(&app, "b").scan_outdated);

        // The lockfile moves `a` to 1.0.6 without package.json changing.
        install(&app.dir.clone(), "a", "1.0.6");
        app.read_installed_versions();
        app.refresh_findings();
        assert!(row(&app, "a").vulns.is_empty(), "1.0.6 was never scanned");
        assert!(row(&app, "a").scan_outdated);

        // A scan now is recorded under 1.0.6, leaving the other versions' findings alone.
        let mut report = Report::default();
        report.vulns = vec![vuln("a", "1.0.6", "A-1.0.6")];
        app.apply_scan(Source::Snyk, report, false);
        assert_eq!(ids(&app, "a"), ["A-1.0.6"]);
        assert_eq!(stored(&app).findings("snyk", "a", "1.0.6").unwrap().vulns[0].id, "A-1.0.6");
        assert_eq!(stored(&app).findings("snyk", "a", "1.0.0").unwrap().vulns[0].id, "A-1.0.0");
        assert_eq!(stored(&app).findings("snyk", "a", "1.0.5").unwrap().vulns[0].id, "A-1.0.5");
    }

    #[test]
    fn projects_sharing_a_cache_file_keep_their_own_scan_results() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "depsu-two-projects-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let (dir_a, dir_b) = (base.join("a"), base.join("b"));
        // The same version of `a` is installed in both projects.
        for d in [&dir_a, &dir_b] {
            install(d, "a", "1.0.0");
            install(d, "b", "1.0.0");
        }
        let path = base.join("cache.json");
        let mut cache = Cache::default();
        cache.latest.insert("a".into(), "1.0.0".into());
        cache.latest.insert("b".into(), "1.0.0".into());
        cache.save(&path).unwrap();
        let open = |dir: &std::path::Path| {
            let deps = ["a", "b"]
                .iter()
                .map(|n| Dep {
                    name: n.to_string(),
                    spec: "^1.0.0".into(),
                    kind: Kind::Prod,
                })
                .collect();
            let mut app = App::start(
                dir.to_path_buf(),
                Pm::Npm,
                deps,
                Npmrc::load(dir),
                Vec::new(),
                Some(path.clone()),
            );
            app.drain_events();
            app
        };

        // Project A: Snyk finds nothing.
        let mut a = open(&dir_a);
        a.apply_scan(Source::Snyk, Report::default(), false);
        a.flush_cache();
        drop(a);

        // Project B: the same a@1.0.0 brings in something vulnerable there.
        let mut b = open(&dir_b);
        assert!(row(&b, "a").vulns.is_empty(), "A's results must not show in B");
        assert_eq!(b.snyk.status, ScanStatus::NotRun, "B has no scan results of its own");
        let mut report = Report::default();
        report.vulns = vec![vuln("a", "1.0.0", "ONLY-IN-B")];
        b.apply_scan(Source::Snyk, report, false);
        b.flush_cache();
        drop(b);

        // Back in A: still clean.
        let a = open(&dir_a);
        assert!(row(&a, "a").vulns.is_empty(), "B's findings must not show in A");
        assert!(!row(&a, "a").scan_outdated, "A's own scan still applies");
        // And B keeps its finding.
        let b = open(&dir_b);
        assert_eq!(ids(&b, "a"), ["ONLY-IN-B"]);
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Writes a lockfile v3 pinning each `(name, version)`.
    fn write_lock(dir: &std::path::Path, pins: &[(&str, &str)]) {
        let packages: serde_json::Map<String, serde_json::Value> = pins
            .iter()
            .map(|(n, v)| (format!("node_modules/{n}"), serde_json::json!({ "version": v })))
            .collect();
        let lock = serde_json::json!({ "lockfileVersion": 3, "packages": packages });
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("package-lock.json"), lock.to_string()).unwrap();
    }

    #[test]
    fn findings_are_filed_under_the_scanned_lockfile_version_not_the_package_json_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "depsu-lockfile-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let (dir_a, dir_b) = (base.join("a"), base.join("b"));
        // Both package.json files ask for ^1.0.0 (see `open`).
        // A has 1.0.0 installed. B was never installed; its lockfile pins 0.9.0.
        install(&dir_a, "a", "1.0.0");
        install(&dir_a, "b", "1.0.0");
        write_lock(&dir_b, &[("a", "0.9.0"), ("b", "1.0.0")]);
        let path = base.join("cache.json");
        let mut cache = Cache::default();
        cache.latest.insert("a".into(), "1.0.0".into());
        cache.latest.insert("b".into(), "1.0.0".into());
        cache.save(&path).unwrap();
        let open = |dir: &std::path::Path| {
            let deps = ["a", "b"]
                .iter()
                .map(|n| Dep {
                    name: n.to_string(),
                    spec: "^1.0.0".into(),
                    kind: Kind::Prod,
                })
                .collect();
            let mut app = App::start(
                dir.to_path_buf(),
                Pm::Npm,
                deps,
                Npmrc::load(dir),
                Vec::new(),
                Some(path.clone()),
            );
            app.drain_events();
            app
        };

        let mut b = open(&dir_b);
        assert_eq!(row(&b, "a").current, Version::new(1, 0, 0), "package.json");
        assert_eq!(row(&b, "a").installed, Some(Version::new(0, 9, 0)), "lockfile");
        // Snyk scans the lockfile and reports the direct dependency as a@0.9.0.
        let mut report = Report::default();
        report.vulns = vec![vuln("a", "0.9.0", "IN-0.9.0")];
        b.apply_scan(Source::Snyk, report, false);
        assert_eq!(ids(&b, "a"), ["IN-0.9.0"]);
        assert!(stored(&b).findings("snyk", "a", "0.9.0").is_some());
        assert!(
            stored(&b).findings("snyk", "a", "1.0.0").is_none(),
            "nothing may be filed under the package.json version"
        );
        b.flush_cache();
        drop(b);

        // Even if A used B's results (as before results were kept per project), a@1.0.0
        // has none: B never scanned 1.0.0.
        let mut shared = Cache::load(&path).unwrap();
        let b_scans = shared.projects.remove(&dir_b.display().to_string()).unwrap();
        shared.projects.insert(dir_a.display().to_string(), b_scans);
        shared.save(&path).unwrap();
        let a = open(&dir_a);
        assert!(row(&a, "a").vulns.is_empty(), "0.9.0's findings must not show for 1.0.0");
        assert!(row(&a, "a").scan_outdated, "1.0.0 hasn't been scanned");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_snyk_version_that_differs_from_node_modules_is_reported() {
        let mut app = app_with_cache("1.0.0", |_| {});
        let mut report = Report::default();
        // Snyk read 0.9.0 from the lockfile, but node_modules holds 1.0.0.
        report.vulns = vec![vuln("a", "0.9.0", "OLD")];
        app.apply_scan(Source::Snyk, report, false);
        assert!(row(&app, "a").vulns.is_empty(), "not shown for the installed 1.0.0");
        assert!(stored(&app).findings("snyk", "a", "0.9.0").is_some());
        assert!(
            app.log.iter().any(|l| l.contains("a@0.9.0 (depsu sees 1.0.0)")),
            "{:?}",
            app.log
        );
    }

    /// An app whose installs are captured instead of run.
    fn app_capturing_installs() -> (App, Receiver<Job>) {
        let mut app = app_with_cache("2.0.0", |_| {});
        let (tx, rx) = mpsc::channel();
        app.jobs = tx;
        (app, rx)
    }
    fn queued(rx: &Receiver<Job>) -> Vec<String> {
        rx.try_iter()
            .flat_map(|j| j.items)
            .map(|(n, spec, ..)| format!("{n}@{spec}"))
            .collect()
    }
    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn needs_b() -> peers::Report {
        peers::Report {
            needs: vec![peers::Need {
                name: "b".into(),
                from: Version::new(1, 0, 0),
                to: Some(Version::new(2, 0, 0)),
                why: "a@2.0.0 needs b ^2.0.0".into(),
            }],
            warnings: Vec::new(),
        }
    }
    fn plan_a() -> Vec<(String, Version)> {
        vec![("a".to_string(), Version::new(2, 0, 0))]
    }

    #[test]
    fn an_install_with_nothing_else_to_change_goes_ahead() {
        let (mut app, rx) = app_capturing_installs();
        app.on_peer_check(plan_a(), Vec::new(), peers::Report::default());
        assert!(app.peer_prompt.is_none());
        assert_eq!(queued(&rx), ["a@^2.0.0"]);
    }

    #[test]
    fn the_user_is_asked_and_can_update_the_other_package_too() {
        let (mut app, rx) = app_capturing_installs();
        app.on_peer_check(plan_a(), Vec::new(), needs_b());
        let p = app.peer_prompt.as_ref().expect("asks before installing");
        assert_eq!(p.extra, [("b".to_string(), Version::new(2, 0, 0))]);
        assert!(queued(&rx).is_empty(), "nothing is installed before the answer");
        assert!(app.log.iter().any(|l| l.contains("b 1.0.0 → 2.0.0: a@2.0.0 needs b ^2.0.0")));
        app.on_key(key('y'));
        assert!(app.peer_prompt.is_none());
        assert_eq!(queued(&rx), ["a@^2.0.0", "b@^2.0.0"]);
    }

    #[test]
    fn the_user_can_install_only_what_they_picked() {
        let (mut app, rx) = app_capturing_installs();
        app.on_peer_check(plan_a(), Vec::new(), needs_b());
        app.on_key(key('n'));
        assert_eq!(queued(&rx), ["a@^2.0.0"]);
    }

    #[test]
    fn any_other_key_cancels_the_install() {
        let (mut app, rx) = app_capturing_installs();
        app.on_peer_check(plan_a(), Vec::new(), needs_b());
        app.on_key(key('x'));
        assert!(queued(&rx).is_empty());
        assert!(app.peer_prompt.is_none());
        assert_eq!(row(&app, "a").status, Status::Idle);
        assert!(app.log.last().unwrap().contains("cancelled"));
    }

    #[test]
    fn a_change_depsu_cannot_make_is_reported_and_needs_confirming() {
        let (mut app, rx) = app_capturing_installs();
        let mut report = needs_b();
        report.needs[0].to = None;
        app.on_peer_check(plan_a(), Vec::new(), report);
        let p = app.peer_prompt.as_ref().unwrap();
        assert!(p.extra.is_empty());
        assert_eq!(p.needs.len(), 1);
        assert!(!p.needs[0].1, "b can't be updated by depsu");
        // `n` means nothing here: there's nothing to leave out.
        app.on_key(key('n'));
        assert!(queued(&rx).is_empty());
        app.on_peer_check(plan_a(), Vec::new(), {
            let mut r = needs_b();
            r.needs[0].to = None;
            r
        });
        app.on_key(key('y'));
        assert_eq!(queued(&rx), ["a@^2.0.0"], "y installs anyway");
    }

    /// The screen as text, one string per row.
    fn render(app: &mut App, w: u16, h: u16) -> Vec<String> {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    #[test]
    fn the_question_is_shown_as_a_box_in_the_middle_of_the_screen() {
        let (mut app, _rx) = app_capturing_installs();
        app.on_peer_check(plan_a(), Vec::new(), needs_b());
        let screen = render(&mut app, 100, 40);
        let top = screen
            .iter()
            .position(|l| l.contains(" Other packages must change "))
            .expect("the dialog is drawn");
        let bottom = screen[top + 1..]
            .iter()
            .position(|l| l.contains('╰'))
            .map(|i| top + 1 + i)
            .expect("the dialog is closed");
        // Centred vertically (to a row) and horizontally.
        assert!((top as i32 - (40 - 1 - bottom) as i32).abs() <= 1, "top {top}, bottom {bottom}");
        let left = screen[top].find('╭').unwrap();
        let right = 100 - 1 - screen[top].chars().position(|c| c == '╮').unwrap();
        assert!((left as i32 - right as i32).abs() <= 1, "left {left}, right {right}");
        let body = screen[top..=bottom].join("\n");
        assert!(body.contains("Installing a 2.0.0 needs other packages to change"));
        assert!(body.contains("b 1.0.0 → 2.0.0"));
        assert!(body.contains("a@2.0.0 needs b ^2.0.0"));
        assert!(body.contains("y  also update b 2.0.0"));
        assert!(body.contains("n  install only a 2.0.0"));
        // Once answered, it's gone.
        app.on_key(key('x'));
        assert!(!render(&mut app, 100, 40).iter().any(|l| l.contains("Other packages must change")));
    }

    #[test]
    fn cached_latest_versions_are_compared_with_the_installed_version() {
        let app = app_with_cache("2.0.0", |_| {});
        assert!(!app.loading(), "no network lookups were needed");
        let a = row(&app, "a");
        assert_eq!(a.latest, Version::parse("2.0.0").unwrap());
        assert!(a.outdated);
        assert!(!row(&app, "b").outdated);
        assert_eq!(app.snyk.status, ScanStatus::NotRun, "nothing cached, nothing shown");
    }

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
