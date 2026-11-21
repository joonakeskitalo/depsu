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
    /// The registry answered whether the version typed for a package exists.
    VersionChecked {
        name: String,
        version: Version,
        result: Result<registry::Packument, String>,
    },
    /// The registry answered about a package to add.
    AddChecked {
        name: String,
        add_as: AddAs,
        version: Option<Version>,
        result: Result<registry::Packument, String>,
    },
    /// The changes to commit were looked at.
    CommitPrepared(Result<crate::commit::Plan, String>),
    /// git committed (the short hash), or failed.
    Committed(Result<String, String>),
    /// Versions the registry refuses to hand out were found.
    Blocked {
        plan: Vec<(String, Version)>,
        ovr: Vec<(Override, String)>,
        blocked: Vec<crate::blocked::Blocked>,
        after_failure: bool,
    },
    /// The ways to fix a package's unmet peers were looked up.
    PeerFixes {
        name: String,
        unmet: Vec<peers::Unmet>,
        options: Vec<peers::FixOption>,
        notes: Vec<String>,
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
/// A peer dependency an installed package declares.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub name: String,
    pub range: String,
    /// The version of the peer the project has, `None` if it isn't installed.
    pub installed: Option<Version>,
}

impl Peer {
    /// `Some(false)` when the installed peer is outside the range. `None` when the peer isn't
    /// installed (it may be optional) or the range can't be read.
    pub fn met(&self) -> Option<bool> {
        overrides::satisfies(&self.range, self.installed.as_ref()?)
    }
}

/// The peer dependencies the installed copy of `name` declares, with the version of each the
/// project has.
fn peers_of(
    dir: &std::path::Path,
    lock: Option<&HashMap<String, Version>>,
    name: &str,
) -> Vec<Peer> {
    let mut peers: Vec<Peer> = crate::tree::installed_peers(dir, name)
        .unwrap_or_default()
        .into_iter()
        .map(|(peer, range)| Peer {
            installed: resolved_version(dir, lock, &peer),
            name: peer,
            range,
        })
        .collect();
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    peers
}

/// A package uninstalled in this session, kept so it can be restored.
pub struct RemovedPkg {
    pub row: Row,
    /// The range it had in `package.json`.
    pub spec: String,
    pub status: Status,
}
/// Looks a package up in the registry. Replaceable so tests run without the network.
pub type Fetcher = Arc<dyn Fn(&str) -> Result<registry::Packument, String> + Send + Sync>;
/// Whether the registry hands out a package file: (package name, file URL).
pub type Prober = Arc<dyn Fn(&str, &str) -> Result<bool, String> + Send + Sync>;

/// Versions the registry refuses to hand out, waiting for the user to decide.
pub struct BlockedPrompt {
    /// The install that was about to run (empty when it already failed).
    pub plan: Vec<(String, Version)>,
    ovr: Vec<(Override, String)>,
    pub blocked: Vec<crate::blocked::Blocked>,
    /// The install already failed: the blocked version may be a nested package.
    pub after_failure: bool,
}

impl BlockedPrompt {
    pub fn has_alternatives(&self) -> bool {
        self.blocked.iter().any(|b| b.alternative.is_some())
    }
    /// Something in the install isn't blocked.
    pub fn has_others(&self) -> bool {
        !self.ovr.is_empty() || self.plan.iter().any(|(n, _)| !self.blocked.iter().any(|b| b.name == *n))
    }
}

/// Text the user is typing: a version in the footer (`e`), or a package in the add dialog
/// (`+`).
pub struct Input {
    pub purpose: InputPurpose,
    pub text: String,
    /// Why the last attempt didn't work, shown in the dialog.
    pub error: Option<String>,
    /// The package being looked up in the registry, while the dialog waits for it.
    pub looking_up: Option<String>,
}

impl Input {
    fn new(purpose: InputPurpose) -> Input {
        Input {
            purpose,
            text: String::new(),
            error: None,
            looking_up: None,
        }
    }
}

pub enum InputPurpose {
    /// A version to install for an existing package (`e`).
    Version { name: String },
    /// A package to add to the project (`+`).
    Add { add_as: AddAs },
}

/// What a package is added as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddAs {
    Dependency,
    Dev,
    /// An entry in `overrides` (npm, bun), `resolutions` (yarn) or `pnpm.overrides`.
    Override,
}

impl AddAs {
    pub const ALL: [AddAs; 3] = [AddAs::Dependency, AddAs::Dev, AddAs::Override];

    pub fn label(self) -> &'static str {
        match self {
            AddAs::Dependency => "dependency",
            AddAs::Dev => "dev dependency",
            AddAs::Override => "override",
        }
    }

    fn step(self, by: isize) -> AddAs {
        let i = AddAs::ALL.iter().position(|a| *a == self).unwrap_or(0) as isize;
        AddAs::ALL[(i + by).rem_euclid(AddAs::ALL.len() as isize) as usize]
    }
}

/// A package being added: what to install and what the registry says is the latest.
#[derive(Clone)]
struct Adding {
    kind: Kind,
    version: Version,
    latest: Version,
}

/// The commit `c` proposes, with its title as the user edits it.
pub struct CommitPrompt {
    pub plan: crate::commit::Plan,
    pub title: String,
    /// Why the commit failed, e.g. a git hook's output.
    pub error: Option<String>,
    /// git is committing.
    pub busy: bool,
}

/// What `d` is about to delete, waiting for the user to confirm.
pub struct DeletePrompt {
    /// Packages to uninstall.
    pub packages: Vec<String>,
    /// Overrides to remove from `package.json`.
    pub overrides: Vec<Override>,
    /// What may break, e.g. other installed packages that use a package being removed.
    pub warnings: Vec<String>,
}

/// The ways to fix a package's unmet peers, waiting for the user to pick one.
pub struct PeerFix {
    pub name: String,
    pub unmet: Vec<peers::Unmet>,
    pub options: Vec<peers::FixOption>,
    /// Why some fix isn't offered.
    pub notes: Vec<String>,
    /// The highlighted option.
    pub choice: usize,
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
    /// Scanners that have results, but not for the version installed now (it changed since
    /// they ran, or they ran in another session at another version). Their findings, or
    /// their absence, say nothing about this version.
    pub unscanned: Vec<Source>,
    /// The peer dependencies its installed copy declares.
    pub peers: Vec<Peer>,
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
    /// Some scanner with results hasn't looked at the version installed now.
    pub fn scan_outdated(&self) -> bool {
        !self.unscanned.is_empty()
    }
    pub fn busy(&self) -> bool {
        matches!(self.status, Status::Queued | Status::Installing)
    }

    /// Can be installed at its latest version.
    pub fn actionable(&self) -> bool {
        self.outdated && !self.busy()
    }

    /// Can be checked with `space`, to install or delete it.
    pub fn can_select(&self) -> bool {
        !self.busy()
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

/// A package to install.
#[derive(Clone, Debug)]
struct InstallItem {
    name: String,
    /// What `package.json` gets, e.g. `^2.0.0`, or `2.0.0` when pinned exactly.
    spec: String,
    kind: Kind,
    exact: bool,
    /// The spec in `package.json` now, needed to edit it in place.
    old: Option<String>,
}

#[derive(Default)]
struct Job {
    /// Packages to uninstall, before anything else runs.
    uninstall: Vec<String>,
    items: Vec<InstallItem>,
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
    /// The fixes for a package's unmet peers (`f`), waiting for a choice.
    pub peer_fix: Option<PeerFix>,
    /// What `d` is about to delete.
    pub delete_prompt: Option<DeletePrompt>,
    /// Versions the registry refuses, and what can be installed instead.
    pub blocked_prompt: Option<BlockedPrompt>,
    /// The commit `c` proposes.
    pub commit_prompt: Option<CommitPrompt>,
    /// Vulnerabilities queued installs and overrides will fix, with the row name or override
    /// key of the job that fixes them.
    queued_fixes: Vec<(String, crate::commit::Fixed)>,
    /// Vulnerabilities fixed in this session and not committed yet.
    pub session_fixes: Vec<crate::commit::Fixed>,
    /// Packages to install with an exact version the next time they are queued, because a
    /// range would resolve to a blocked version again.
    exact_once: HashSet<String>,
    prober: Prober,
    /// The peer dependencies of an install are being checked.
    peer_checking: bool,
    /// Text the user is typing: a version (`e`) or a package to add (`+`).
    pub input: Option<Input>,
    /// Packages being added, by name.
    adding: HashMap<String, Adding>,
    fetcher: Fetcher,
    pub log: Vec<String>,
    /// The log is expanded to fill the screen and takes the keys (toggled with Tab).
    pub log_focus: bool,
    /// Lines scrolled up from the newest log line.
    pub log_scroll: usize,
    /// Visible log lines while expanded, set by the renderer, used for paging.
    pub log_page: usize,
    /// Rows the package list shows, set by the renderer, used for paging (`,` and `.`).
    pub list_page: usize,
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
            peer_fix: None,
            delete_prompt: None,
            blocked_prompt: None,
            commit_prompt: None,
            queued_fixes: Vec::new(),
            session_fixes: Vec::new(),
            exact_once: HashSet::new(),
            prober: {
                let (rc, agent) = (rc.clone(), agent.clone());
                Arc::new(move |n: &str, url: &str| registry::downloadable(&rc, &agent, n, url))
            },
            peer_checking: false,
            input: None,
            adding: HashMap::new(),
            fetcher: {
                let (rc, agent) = (rc.clone(), agent.clone());
                Arc::new(move |n: &str| registry::packument(&rc, &agent, n))
            },
            log: Vec::new(),
            log_focus: false,
            log_scroll: 0,
            log_page: 10,
            list_page: 10,
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
            r.peers = peers_of(&self.dir, lock.as_ref(), &r.name);
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
            r.unscanned.clear();
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
                        r.unscanned.push(source);
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
                unscanned: Vec::new(),
                peers: Vec::new(),
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
        !self.adding.is_empty()
            || !self.busy_overrides.is_empty()
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
                Event::PeerFixes {
                    name,
                    unmet,
                    options,
                    notes,
                } => self.on_peer_fixes(name, unmet, options, notes),
                Event::Blocked {
                    plan,
                    ovr,
                    blocked,
                    after_failure,
                } => self.on_blocked(plan, ovr, blocked, after_failure),
                Event::CommitPrepared(result) => self.on_commit_prepared(result),
                Event::Committed(result) => self.on_committed(result),
                Event::VersionChecked {
                    name,
                    version,
                    result,
                } => self.on_version_checked(name, version, result),
                Event::AddChecked {
                    name,
                    add_as,
                    version,
                    result,
                } => self.on_add_checked(name, add_as, version, result),
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
            unscanned: Vec::new(),
            peers: Vec::new(),
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
        let ok = result.is_ok();
        let (done, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut self.queued_fixes)
            .into_iter()
            .partition(|(by, _)| names.contains(by) || keys.contains(by));
        self.queued_fixes = pending;
        if ok {
            for (_, f) in done {
                if !self.session_fixes.contains(&f) {
                    self.session_fixes.push(f);
                }
            }
        }
        let forbidden = result
            .as_ref()
            .err()
            .and_then(|e| crate::blocked::parse_forbidden(e));
        let added: Vec<(String, Adding)> = names
            .iter()
            .filter_map(|n| Some((n.clone(), self.adding.remove(n)?)))
            .collect();
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
        // A package that was added gets a row, like the others had from the start.
        if ok {
            for (name, a) in added {
                self.current
                    .insert(name.clone(), (a.kind, "^", a.version.clone()));
                self.direct.insert(name.clone());
                self.on_fetched(name, a.latest);
            }
        }
        // An install changes `node_modules` and usually `package.json` (also when it failed
        // halfway), so everything derived from them has to be recomputed.
        self.reload_project();
        // Rows at a new version get the findings recorded for that version, if any.
        self.read_installed_versions();
        self.refresh_findings();
        self.rebuild_view();
        if let Some((name, version)) = forbidden {
            self.look_for_unblocked(name, version);
        }
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
        row.peers = peers_of(&self.dir, lock.as_ref(), &row.name);
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
        let item = InstallItem {
            name: name.to_string(),
            spec: version.clone(),
            kind: p.row.kind,
            exact: true,
            old: None,
        };
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
            global.push(", . page".into());
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
        global.push("+ add package".into());
        global.push("c commit".into());
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
        if matches!(self.cursor_vuln_fix(), Some(Ok(_))) {
            item.push("i install fix".into());
        }
        if let Some((_, v)) = self.cursor_vuln()
            && self.vuln_pin_fix(v).is_some()
        {
            item.push("p pin fix as override".into());
        }
        if !self.acting_rows(|r| !r.busy()).is_empty() {
            item.push("P pin type".into());
        }
        if self.cursor_vuln().is_none()
            && !self.acting_rows(|r| !r.busy() && !r.vulns.is_empty()).is_empty()
        {
            item.push("p pin fix as override".into());
        }
        if let Some(Item::Row { idx, .. }) = self.cursor_item()
            && self.rows[*idx].kind != Kind::Override
            && !self.rows[*idx].busy()
        {
            item.push("e set version".into());
            if self.rows[*idx].peers.iter().any(|p| p.met() == Some(false)) {
                item.push("f fix unmet peers".into());
            }
        }
        let (packages, overrides, checked) = self.delete_targets();
        let n = packages.len() + overrides.len();
        if checked && n > 0 {
            item.push(format!("d delete {n} checked"));
        } else if !packages.is_empty() {
            item.push("d uninstall".into());
        } else if !overrides.is_empty() {
            item.push("d remove override".into());
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
        if self.input.is_some() {
            self.on_input_key(key);
            return;
        }
        if self.filter_mode {
            self.on_filter_key(key);
            return;
        }
        if self.commit_prompt.is_some() {
            self.on_commit_key(key);
            return;
        }
        if let Some(p) = self.blocked_prompt.take() {
            match key.code {
                KeyCode::Char('y') if p.has_alternatives() => self.use_unblocked(p),
                KeyCode::Char('n') if !p.after_failure && p.has_others() => {
                    let plan: Vec<(String, Version)> = p
                        .plan
                        .into_iter()
                        .filter(|(n, _)| !p.blocked.iter().any(|b| b.name == *n))
                        .collect();
                    for b in &p.blocked {
                        self.adding.remove(&b.name);
                    }
                    self.start_install(plan, p.ovr);
                }
                _ => {
                    for (name, _) in &p.plan {
                        self.adding.remove(name);
                    }
                    if !p.after_failure {
                        self.push_log("Install cancelled.");
                    }
                }
            }
            return;
        }
        if let Some(p) = self.delete_prompt.take() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => self.confirm_delete(p),
                _ => self.push_log("Nothing deleted."),
            }
            return;
        }
        if let Some(mut p) = self.peer_fix.take() {
            let pick = match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    p.choice = p.choice.checked_sub(1).unwrap_or(p.options.len().saturating_sub(1));
                    self.peer_fix = Some(p);
                    return;
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    p.choice = (p.choice + 1) % p.options.len().max(1);
                    self.peer_fix = Some(p);
                    return;
                }
                KeyCode::Enter => Some(p.choice),
                KeyCode::Char(c @ '1'..='9') => Some(c as usize - '1' as usize),
                _ => None,
            };
            match pick.and_then(|i| p.options.get(i)) {
                Some(o) => {
                    self.push_log(format!("… fixing the peers of {}: {}", p.name, o.label));
                    self.start_install(o.plan.clone(), Vec::new());
                }
                None => self.push_log("Peers unchanged."),
            }
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
                _ => {
                    for (name, _) in &p.plan {
                        self.adding.remove(name);
                    }
                    self.push_log("Install cancelled.");
                }
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
            // A page is what the list shows, less a row that stays in view for context.
            KeyCode::Char(',') | KeyCode::PageUp => {
                self.move_cursor(-(self.list_page.saturating_sub(1).max(1) as isize))
            }
            KeyCode::Char('.') | KeyCode::PageDown => {
                self.move_cursor(self.list_page.saturating_sub(1).max(1) as isize)
            }
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
            KeyCode::Char('p') => self.pin_selected(),
            KeyCode::Char('P') => self.ask_pin_type(),
            KeyCode::Char('s') => self.start_scan(Source::Snyk),
            KeyCode::Char('n') => self.start_scan(self.audit_source()),
            KeyCode::Char('?') => self.show_info = !self.show_info,
            KeyCode::Char('R') => self.refetch_latest(),
            KeyCode::Char('r') => self.revert_selected(),
            KeyCode::Char('e') => self.ask_version(),
            KeyCode::Char('f') => self.fix_unmet_peers(),
            KeyCode::Char('c') => self.prepare_commit(),
            KeyCode::Char('+') => {
                self.input = Some(Input::new(InputPurpose::Add {
                    add_as: AddAs::Dependency,
                }))
            }
            KeyCode::Char('d') => self.delete_selected(),
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
            KeyCode::PageUp | KeyCode::Char(',') => self.log_scroll = (self.log_scroll + page).min(max),
            KeyCode::PageDown | KeyCode::Char('.') => self.log_scroll = self.log_scroll.saturating_sub(page),
            KeyCode::Home | KeyCode::Char('g') => self.log_scroll = max,
            KeyCode::End | KeyCode::Char('G') => self.log_scroll = 0,
            _ => {}
        }
    }
    fn on_input_key(&mut self, key: KeyEvent) {
        let Some(input) = &mut self.input else {
            return;
        };
        // While the registry is asked, only cancelling does anything.
        if input.looking_up.is_some() && key.code != KeyCode::Esc {
            return;
        }
        match key.code {
            KeyCode::Esc => self.input = None,
            KeyCode::Enter => match &input.purpose {
                InputPurpose::Version { name } => {
                    let (name, text) = (name.clone(), input.text.clone());
                    self.input = None;
                    self.submit_version(name, &text);
                }
                InputPurpose::Add { add_as } => {
                    let (add_as, text) = (*add_as, input.text.clone());
                    self.submit_add(add_as, &text);
                }
            },
            KeyCode::Backspace => {
                input.text.pop();
                input.error = None;
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
                if let InputPurpose::Add { add_as } = &mut input.purpose {
                    let by = if matches!(key.code, KeyCode::BackTab | KeyCode::Up) { -1 } else { 1 };
                    *add_as = add_as.step(by);
                    input.error = None;
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                input.text.push(c);
                input.error = None;
            }
            _ => {}
        }
    }

    // ---- choosing a version, adding a package -------------------------------------------

    /// Looks up the ways to fix the unmet peers of the package under the cursor, then asks.
    fn fix_unmet_peers(&mut self) {
        let Some(Item::Row { idx, .. }) = self.cursor_item() else {
            self.push_log("Put the cursor on a package marked ⚠ unmet peer.");
            return;
        };
        let r = &self.rows[*idx];
        let unmet: Vec<peers::Unmet> = r
            .peers
            .iter()
            .filter(|p| p.met() == Some(false))
            .filter_map(|p| {
                Some(peers::Unmet {
                    name: p.name.clone(),
                    range: p.range.clone(),
                    installed: p.installed.clone()?,
                })
            })
            .collect();
        if unmet.is_empty() {
            self.push_log(format!("{} has no unmet peers.", r.name));
            return;
        }
        if r.busy() {
            return;
        }
        let name = r.name.clone();
        let have = r.installed.clone().unwrap_or_else(|| r.current.clone());
        self.push_log(format!("… looking up fixes for the peers of {name}"));
        let direct: Vec<String> = self
            .rows
            .iter()
            .filter(|r| r.kind != Kind::Override)
            .map(|r| r.name.clone())
            .collect();
        let (dir, fetcher, tx) = (self.dir.clone(), self.fetcher.clone(), self.events_tx.clone());
        thread::spawn(move || {
            let lock = crate::tree::npm_lock_versions(&dir);
            let installed = |n: &str| resolved_version(&dir, lock.as_ref(), n);
            let fetch = |n: &str| fetcher(n);
            let (options, notes) = peers::fix_options(
                &name,
                &have,
                &unmet,
                &peers::Project {
                    direct: &direct,
                    installed: &installed,
                    installed_peers: &|_| None,
                    fetch: &fetch,
                },
            );
            let _ = tx.send(Event::PeerFixes {
                name,
                unmet,
                options,
                notes,
            });
        });
    }

    fn on_peer_fixes(
        &mut self,
        name: String,
        unmet: Vec<peers::Unmet>,
        options: Vec<peers::FixOption>,
        notes: Vec<String>,
    ) {
        if options.is_empty() {
            self.push_log(format!("✘ Can't fix the peers of {name}: {}.", notes.join("; ")));
            return;
        }
        // The answer must not land in a text prompt or another question.
        self.filter_mode = false;
        self.pin_prompt = false;
        self.input = None;
        self.peer_fix = Some(PeerFix {
            name,
            unmet,
            options,
            notes,
            choice: 0,
        });
    }

    /// Looks at what changed in package.json and the lockfile since the last commit.
    fn prepare_commit(&mut self) {
        if self.installing() {
            self.push_log("Wait for the install to finish before committing.");
            return;
        }
        self.push_log("… looking at what changed since the last commit");
        let (dir, pm, tx) = (self.dir.clone(), self.pm, self.events_tx.clone());
        thread::spawn(move || {
            let _ = tx.send(Event::CommitPrepared(crate::commit::prepare(&dir, pm)));
        });
    }

    fn on_commit_prepared(&mut self, result: Result<crate::commit::Plan, String>) {
        let plan = match result {
            Ok(p) => p.with_fixes(&self.session_fixes),
            Err(e) => return self.push_log(format!("✘ Can't commit: {e}")),
        };
        if plan.files.is_empty() {
            return self.push_log("Nothing to commit: package.json and the lockfile are unchanged.");
        }
        self.filter_mode = false;
        self.pin_prompt = false;
        self.input = None;
        self.commit_prompt = Some(CommitPrompt {
            title: plan.title.clone(),
            plan,
            error: None,
            busy: false,
        });
    }

    fn on_commit_key(&mut self, key: KeyEvent) {
        let Some(p) = &mut self.commit_prompt else {
            return;
        };
        // While git runs (hooks can take a while), keys wait.
        if p.busy {
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.commit_prompt = None;
                self.push_log("Nothing committed.");
            }
            KeyCode::Enter => {
                let title = p.title.trim().to_string();
                if title.is_empty() {
                    p.error = Some("The commit needs a title.".into());
                    return;
                }
                p.busy = true;
                p.error = None;
                let (dir, plan, tx) = (self.dir.clone(), p.plan.clone(), self.events_tx.clone());
                thread::spawn(move || {
                    let _ = tx.send(Event::Committed(crate::commit::run(&dir, &plan, &title)));
                });
            }
            KeyCode::Backspace => {
                p.title.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => p.title.push(c),
            _ => {}
        }
    }

    fn on_committed(&mut self, result: Result<String, String>) {
        match result {
            Ok(hash) => {
                if let Some(p) = self.commit_prompt.take() {
                    self.push_log(format!("✔ committed {hash}: {}", p.title.trim()));
                    // Committed fixes aren't listed again in the next commit.
                    self.session_fixes.retain(|f| !p.plan.fixes.contains(f));
                }
            }
            Err(e) => {
                // The dialog stays open with git's message, e.g. a failing hook.
                let tail: Vec<&str> = e.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
                if let Some(p) = &mut self.commit_prompt {
                    p.busy = false;
                    p.error = Some(tail.join("\n"));
                }
                self.push_log("✘ git commit failed:");
                for l in e.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev() {
                    self.push_log(format!("  {l}"));
                }
            }
        }
    }

    /// Asks which version to install for the package under the cursor.
    fn ask_version(&mut self) {
        let Some(Item::Row { idx, .. }) = self.cursor_item() else {
            self.push_log("Put the cursor on a package to choose its version.");
            return;
        };
        let r = &self.rows[*idx];
        if r.kind == Kind::Override {
            self.push_log(format!(
                "{} isn't a dependency of the project: its version comes from its overrides.",
                r.name
            ));
            return;
        }
        if r.busy() {
            return;
        }
        self.input = Some(Input::new(InputPurpose::Version {
            name: r.name.clone(),
        }));
    }

    fn submit_version(&mut self, name: String, text: &str) {
        let Some(version) = parse_version(text) else {
            self.push_log(format!(
                "✘ {:?} isn't a version like 1.2.3. To change how it is pinned (^, ~), use P.",
                text.trim()
            ));
            return;
        };
        self.push_log(format!("… looking up {name}@{version}"));
        let (fetch, tx) = (self.fetcher.clone(), self.events_tx.clone());
        thread::spawn(move || {
            let result = fetch(&name);
            let _ = tx.send(Event::VersionChecked {
                name,
                version,
                result,
            });
        });
    }

    fn on_version_checked(
        &mut self,
        name: String,
        version: Version,
        result: Result<registry::Packument, String>,
    ) {
        let doc = match result {
            Ok(d) => d,
            Err(e) => return self.push_log(format!("✘ could not look up {name}: {e}")),
        };
        if !doc.versions.contains_key(&version) {
            return self.push_log(no_such_version(&name, &version, &doc));
        }
        let Some(i) = self.rows.iter().position(|r| r.name == name) else {
            return;
        };
        if self.rows[i].busy() {
            return;
        }
        // The version was typed, so a clash with an override is reported but doesn't stop it.
        self.dispatch(None, vec![(i, version)], Vec::new());
    }

    /// Shows `msg` in the add dialog, which stays open so the text can be fixed.
    fn add_error(&mut self, msg: String) {
        if let Some(input) = &mut self.input {
            input.error = Some(msg);
            input.looking_up = None;
        }
    }

    /// Checks `text` (`name` or `name@version`), then asks the registry about it while the
    /// dialog waits.
    fn submit_add(&mut self, add_as: AddAs, text: &str) {
        let text = text.trim();
        // `@scope/name@1.2.3`: the version separator is the last `@` after the first character.
        let (name, version) = match text.get(1..).and_then(|t| t.rfind('@')) {
            Some(i) => (&text[..i + 1], Some(&text[i + 2..])),
            None => (text, None),
        };
        if name.is_empty() {
            return self.add_error("Type the name of a package.".into());
        }
        if !valid_package_name(name) {
            return self.add_error(format!("{name:?} isn't a package name."));
        }
        let version = match version.map(parse_version) {
            None => None,
            Some(Some(v)) => Some(v),
            Some(None) => {
                return self.add_error(format!(
                    "{:?} isn't a version like 1.2.3. Leave it out to add the latest.",
                    version.unwrap_or("")
                ));
            }
        };
        match add_as {
            AddAs::Dependency | AddAs::Dev => {
                if self.direct.contains(name) {
                    return self.add_error(format!(
                        "{name} is already a dependency. Close this and press e on it to choose its version."
                    ));
                }
                if self.adding.contains_key(name) {
                    return self.add_error(format!("{name} is already being added."));
                }
            }
            AddAs::Override => {
                if let Some(o) = self.overrides.iter().find(|o| o.name == name && o.global()) {
                    return self.add_error(format!(
                        "{name} is already overridden ({}). Delete that override with d first.",
                        o.value
                    ));
                }
                if self.pm == Pm::Npm && self.direct.contains(name) {
                    return self.add_error(format!(
                        "{name} is a dependency of the project: npm needs its override to equal its version in package.json. Press e on it to choose its version instead."
                    ));
                }
            }
        }
        if let Some(input) = &mut self.input {
            input.looking_up = Some(name.to_string());
            input.error = None;
        }
        let (fetch, tx, name) = (self.fetcher.clone(), self.events_tx.clone(), name.to_string());
        thread::spawn(move || {
            let result = fetch(&name);
            let _ = tx.send(Event::AddChecked {
                name,
                add_as,
                version,
                result,
            });
        });
    }

    fn on_add_checked(
        &mut self,
        name: String,
        add_as: AddAs,
        version: Option<Version>,
        result: Result<registry::Packument, String>,
    ) {
        // The dialog was closed, or something else was asked for since.
        if self.input.as_ref().and_then(|i| i.looking_up.as_deref()) != Some(name.as_str()) {
            return;
        }
        let doc = match result {
            Ok(d) => d,
            Err(e) => return self.add_error(format!("Could not look up {name}: {e}")),
        };
        let version = match version {
            Some(v) if doc.versions.contains_key(&v) => v,
            Some(v) => {
                let msg = no_such_version(&name, &v, &doc);
                return self.add_error(msg.trim_start_matches("✘ ").to_string());
            }
            None => match &doc.latest {
                Some(l) => l.clone(),
                None => return self.add_error(format!("{name} has no `latest` version.")),
            },
        };
        self.input = None;
        let latest = doc.latest.clone().unwrap_or_else(|| version.clone());
        match add_as {
            AddAs::Override => self.add_override(&name, &version, false),
            AddAs::Dependency | AddAs::Dev => {
                let kind = if add_as == AddAs::Dev { Kind::Dev } else { Kind::Prod };
                self.adding.insert(
                    name.clone(),
                    Adding {
                        kind,
                        version: version.clone(),
                        latest,
                    },
                );
                self.start_install(vec![(name, version)], Vec::new());
            }
        }
    }

    /// Adds an override that forces `name` to `version` everywhere in the dependency tree.
    /// Forces `name` to `version` everywhere in the dependency tree with an override, `^version`
    /// or exactly `version`. An existing override of it is changed instead.
    fn add_override(&mut self, name: &str, version: &Version, exact: bool) {
        let new = if exact { version.to_string() } else { format!("^{version}") };
        let (loc, change) = match self
            .overrides
            .iter()
            .find(|o| o.name == name && o.global() && o.range.is_none())
        {
            Some(o) => (
                o.loc.clone(),
                Change::Set {
                    loc: o.loc.clone(),
                    old: o.value.clone(),
                    new: new.clone(),
                },
            ),
            None => {
                let loc = self.new_override_loc(name);
                (loc.clone(), Change::Add { loc, new: new.clone() })
            }
        };
        let key = loc.join("\u{1f}");
        self.changed.insert(key.clone());
        self.busy_overrides.insert(key.clone());
        self.push_log(format!("… queued override {name} → {new}"));
        let _ = self.jobs.send(Job {
            edits: vec![change],
            keys: vec![key],
            ..Default::default()
        });
    }

    /// Shows what the registry refuses and what it hands out instead.
    fn on_blocked(
        &mut self,
        plan: Vec<(String, Version)>,
        ovr: Vec<(Override, String)>,
        blocked: Vec<crate::blocked::Blocked>,
        after_failure: bool,
    ) {
        if !after_failure {
            self.peer_checking = false;
        }
        for b in &blocked {
            self.push_log(format!(
                "✘ {} {} can't be downloaded: the registry refuses it (403).{}",
                b.name,
                b.version,
                match &b.alternative {
                    Some(a) => format!(" The newest version it hands out is {a}."),
                    None => " No older version could be downloaded either.".to_string(),
                }
            ));
        }
        let p = BlockedPrompt {
            plan,
            ovr,
            blocked,
            after_failure,
        };
        // After a failed install there's only something to ask if a version was found.
        if after_failure && !p.has_alternatives() {
            return;
        }
        // The answer must not land in a text prompt or another question.
        self.filter_mode = false;
        self.pin_prompt = false;
        self.input = None;
        self.blocked_prompt = Some(p);
    }

    /// Installs (or, for a nested package, overrides to) the versions the registry hands out,
    /// pinned exactly: a range would resolve to the blocked version again.
    fn use_unblocked(&mut self, p: BlockedPrompt) {
        if p.after_failure {
            for b in p.blocked {
                let Some(alt) = b.alternative else {
                    continue;
                };
                let is_row = self
                    .rows
                    .iter()
                    .any(|r| r.name == b.name && r.kind != Kind::Override);
                if is_row {
                    self.exact_once.insert(b.name.clone());
                    self.start_install(vec![(b.name, alt)], Vec::new());
                } else {
                    self.add_override(&b.name, &alt, true);
                }
            }
            return;
        }
        let mut plan = Vec::new();
        for (name, version) in p.plan {
            match p.blocked.iter().find(|b| b.name == name) {
                None => plan.push((name, version)),
                Some(b) => match &b.alternative {
                    Some(alt) => {
                        self.exact_once.insert(name.clone());
                        if let Some(a) = self.adding.get_mut(&name) {
                            a.version = alt.clone();
                        }
                        plan.push((name, alt.clone()));
                    }
                    None => {
                        self.adding.remove(&name);
                    }
                },
            }
        }
        self.start_install(plan, p.ovr);
    }

    /// After an install failed because the registry refused a file: looks for the newest
    /// version of that package it hands out.
    fn look_for_unblocked(&mut self, name: String, version: Version) {
        self.push_log(format!(
            "… the registry refused {name} {version} (403): looking for a version it hands out"
        ));
        let direct = self.direct.contains(&name);
        let (fetcher, prober, tx) = (self.fetcher.clone(), self.prober.clone(), self.events_tx.clone());
        thread::spawn(move || {
            let alternative = fetcher(&name)
                .ok()
                .and_then(|doc| crate::blocked::latest_available(&doc, &version, &|u| prober(&name, u)));
            let _ = tx.send(Event::Blocked {
                plan: Vec::new(),
                ovr: Vec::new(),
                blocked: vec![crate::blocked::Blocked {
                    name,
                    version,
                    alternative,
                    direct,
                }],
                after_failure: true,
            });
        });
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
    /// The version of the direct dependency `i` installs to fix `v`, if there is one.
    pub fn vuln_install_fix(&self, r: &Row, v: &Vuln) -> Option<Version> {
        v.upgrade_to
            .as_ref()
            .and_then(|t| Version::parse(t).ok())
            .or_else(|| r.fix_of(v.source).cloned())
    }

    /// The version `p` would force the vulnerable package to with an override, when the
    /// finding is in a transitive dependency and a fixed version is known.
    pub fn vuln_pin_fix(&self, v: &Vuln) -> Option<Version> {
        let fix = pin_target(v)?;
        if self.direct.contains(&v.package) {
            return None;
        }
        // Already overridden to the fix or higher: nothing left to do.
        let pinned = self
            .overrides
            .iter()
            .find(|o| o.name == v.package && o.global() && o.range.is_none())
            .and_then(|o| overrides::min_version(&o.value));
        match pinned {
            Some(p) if p >= fix => None,
            _ => Some(fix),
        }
    }

    /// The finding under the cursor, with the index of its row.
    fn cursor_vuln(&self) -> Option<(usize, &Vuln)> {
        let Some(Item::Detail {
            idx,
            child: Child::Vuln(i),
            ..
        }) = self.cursor_item()
        else {
            return None;
        };
        Some((*idx, self.rows[*idx].vulns.get(*i)?))
    }

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
        Some(match self.vuln_install_fix(r, v) {
            Some(t) => Ok((*idx, t)),
            None if self.vuln_pin_fix(v).is_some() => Err(format!(
                "Upgrading {} doesn't fix {}: press p to override {} to the fixed version.",
                r.name, v.id, v.package
            )),
            None => Err(format!("No fix to install for {}: {}.", v.id, v.fix_summary())),
        })
    }

    fn install_selected(&mut self) {
        // On a vulnerability: install the version that fixes it.
        if let Some(fix) = self.cursor_vuln_fix()
            && !self.rows.iter().any(|r| r.selected && r.actionable())
        {
            match fix {
                Ok((i, target)) => self.dispatch(Some('i'), vec![(i, target)], Vec::new()),
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
        self.dispatch(Some('i'), pkgs, ovr);
    }

    /// Uninstalls the checked packages, or the one under the cursor. Asks to press `d` again.
    /// What `d` deletes: the checked packages and overrides (a checked row of an overridden
    /// package that isn't a dependency stands for its overrides), or else the item under the
    /// cursor.
    pub fn delete_targets(&self) -> (Vec<String>, Vec<Override>, bool) {
        let mut packages = Vec::new();
        let mut overrides: Vec<Override> = Vec::new();
        let add_override = |list: &mut Vec<Override>, o: &Override| {
            if !self.override_busy(o) && !list.iter().any(|x| x.key() == o.key()) {
                list.push(o.clone());
            }
        };
        for i in self.visible_rows() {
            let r = &self.rows[i];
            if !r.selected || r.busy() {
                continue;
            }
            if r.kind == Kind::Override {
                for o in &r.overrides {
                    add_override(&mut overrides, o);
                }
            } else {
                packages.push(r.name.clone());
            }
        }
        for o in self.visible_overrides() {
            if self.selected_overrides.contains(&o.key()) {
                add_override(&mut overrides, o);
            }
        }
        let checked = !packages.is_empty() || !overrides.is_empty();
        if !checked {
            match self.cursor_item() {
                Some(Item::Row { idx, .. }) => {
                    let r = &self.rows[*idx];
                    if r.busy() {
                    } else if r.kind == Kind::Override {
                        for o in &r.overrides {
                            add_override(&mut overrides, o);
                        }
                    } else {
                        packages.push(r.name.clone());
                    }
                }
                Some(item) => {
                    if let Some(o) = self.detail_override(item) {
                        add_override(&mut overrides, o);
                    }
                }
                None => {}
            }
        }
        (packages, overrides, checked)
    }

    /// Asks before deleting the checked packages and overrides (or the item under the cursor).
    fn delete_selected(&mut self) {
        let (packages, overrides, _) = self.delete_targets();
        if packages.is_empty() && overrides.is_empty() {
            self.push_log(
                "Nothing to delete: put the cursor on a package or an override, or check some with space.",
            );
            return;
        }
        let users = |name: &str, leaving: &[String]| -> Vec<String> {
            let mut names: Vec<String> = self
                .dependents_of(name)
                .iter()
                .map(|d| d.name.clone())
                .filter(|n| !leaving.contains(n))
                .collect();
            names.sort();
            names.dedup();
            names
        };
        let mut warnings = Vec::new();
        for name in &packages {
            let users = users(name, &packages);
            if !users.is_empty() {
                warnings.push(format!(
                    "{name} is used by {}: they may stop working without it",
                    users.join(", ")
                ));
            }
        }
        for o in &overrides {
            let users = users(&o.name, &packages);
            if !users.is_empty() {
                warnings.push(format!(
                    "{} is used by {}: without the override they may get another version",
                    o.name,
                    users.join(", ")
                ));
            }
        }
        let flagged = overrides.iter().all(|o| self.unneeded(o).is_some());
        if !overrides.is_empty() && !flagged {
            let unflagged: Vec<&str> = overrides
                .iter()
                .filter(|o| self.unneeded(o).is_none())
                .map(|o| o.name.as_str())
                .collect();
            warnings.push(format!(
                "Not flagged ✂ unneeded: {}. Removing them can change which versions get installed and bring back vulnerable ones: scan again afterwards",
                unflagged.join(", ")
            ));
        } else if !overrides.is_empty() {
            warnings.push("Scan again afterwards to check nothing vulnerable came back".into());
        }
        self.delete_prompt = Some(DeletePrompt {
            packages,
            overrides,
            warnings,
        });
    }

    fn confirm_delete(&mut self, p: DeletePrompt) {
        for r in self.rows.iter_mut().filter(|r| p.packages.contains(&r.name)) {
            r.selected = false;
            r.status = Status::Queued;
        }
        let mut edits = Vec::new();
        let mut keys = Vec::new();
        for o in &p.overrides {
            keys.push(o.key());
            self.changed.insert(o.key());
            self.selected_overrides.remove(&o.key());
            self.busy_overrides.insert(o.key());
            edits.push(Change::Remove {
                loc: o.loc.clone(),
                old: o.value.clone(),
            });
        }
        // Checked rows of overridden packages stood for their overrides.
        for r in self.rows.iter_mut().filter(|r| r.kind == Kind::Override) {
            r.selected = false;
        }
        self.uninstalling.extend(p.packages.iter().cloned());
        let mut what: Vec<String> = p.packages.clone();
        what.extend(keys.iter().map(|k| override_label(k)));
        self.push_log(format!("… queued deleting {}", what.join(", ")));
        let _ = self.jobs.send(Job {
            uninstall: p.packages,
            edits,
            keys,
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
            items.push(InstallItem {
                name: r.name.clone(),
                spec: from.to_string(),
                kind: r.kind,
                exact: true,
                old: spec_in_manifest(&self.root_deps, &r.name),
            });
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
    /// `key` is the key that must be pressed again to go ahead despite override conflicts;
    /// `None` when the user typed the version, so the conflict is only reported.
    fn dispatch(
        &mut self,
        key: Option<char>,
        pkgs: Vec<(usize, Version)>,
        ovr: Vec<(Override, String)>,
    ) {
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
        if !conflicts.is_empty() {
            match key {
                Some(key) if self.confirm_conflicts != Some(key) => {
                    let msg = format!(
                        "⚠ conflicts with overrides: {}. Press {key} again to install anyway, any other key cancels.",
                        conflicts.join(", ")
                    );
                    self.confirm_conflicts = Some(key);
                    self.push_log(msg);
                    return;
                }
                None => {
                    let msg = format!(
                        "⚠ conflicts with overrides: {}. The override may keep the version from changing.",
                        conflicts.join(", ")
                    );
                    self.push_log(msg);
                }
                Some(_) => {}
            }
        }
        self.confirm_conflicts = None;
        let plan: Vec<(String, Version)> = pkgs
            .into_iter()
            .map(|(i, v)| (self.rows[i].name.clone(), v))
            .collect();
        self.start_install(plan, ovr);
    }

    /// Checks the peer dependencies of `plan`, then installs or asks.
    fn start_install(&mut self, plan: Vec<(String, Version)>, ovr: Vec<(Override, String)>) {
        if plan.is_empty() {
            self.queue_install(plan, ovr);
            return;
        }
        if self.peer_checking {
            for (name, _) in &plan {
                self.adding.remove(name);
            }
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
        let (dir, fetcher, prober, tx) = (
            self.dir.clone(),
            self.fetcher.clone(),
            self.prober.clone(),
            self.events_tx.clone(),
        );
        thread::spawn(move || {
            let lock = crate::tree::npm_lock_versions(&dir);
            let installed = |n: &str| resolved_version(&dir, lock.as_ref(), n);
            let installed_peers = |n: &str| crate::tree::installed_peers(&dir, n);
            // Each package document is fetched once for both checks.
            let memo: std::cell::RefCell<HashMap<String, Result<registry::Packument, String>>> =
                Default::default();
            let fetch = |n: &str| {
                if let Some(r) = memo.borrow().get(n) {
                    return r.clone();
                }
                let r = fetcher(n);
                memo.borrow_mut().insert(n.to_string(), r.clone());
                r
            };
            // A version the registry refuses would only fail the install.
            let blocked = crate::blocked::find_blocked(&plan, &fetch, &|n, u| prober(n, u), &direct);
            if !blocked.is_empty() {
                let _ = tx.send(Event::Blocked {
                    plan,
                    ovr,
                    blocked,
                    after_failure: false,
                });
                return;
            }
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
        self.input = None;
        self.peer_prompt = Some(PeerPrompt {
            plan,
            ovr,
            extra,
            needs,
        });
    }

    /// Queues the installs of `plan` (name, version) and the override updates.
    fn queue_install(&mut self, plan: Vec<(String, Version)>, ovr: Vec<(Override, String)>) {
        for (name, target) in &plan {
            if let Some(r) = self.rows.iter().find(|r| r.name == *name && !r.busy()) {
                for v in &r.vulns {
                    if self.vuln_install_fix(r, v).is_some_and(|fix| *target >= fix) {
                        self.queued_fixes.push((name.clone(), fixed(&r.name, v)));
                    }
                }
            }
        }
        let mut items = Vec::new();
        for (name, target) in plan {
            let exact_now = self.exact_once.remove(&name);
            let Some(r) = self.rows.iter_mut().find(|r| r.name == name) else {
                if let Some(a) = self.adding.get(&name) {
                    items.push(InstallItem {
                        name: name.clone(),
                        spec: if exact_now { target.to_string() } else { format!("^{target}") },
                        kind: a.kind,
                        exact: exact_now,
                        old: None,
                    });
                }
                continue;
            };
            if r.busy() {
                continue;
            }
            r.selected = false;
            r.status = Status::Queued;
            let exact = exact_now || r.prefix.is_empty();
            items.push(InstallItem {
                name: r.name.clone(),
                spec: if exact { target.to_string() } else { format!("{}{target}", r.prefix) },
                kind: r.kind,
                exact,
                old: spec_in_manifest(&self.root_deps, &r.name),
            });
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
        let mut what: Vec<String> = items.iter().map(|i| format!("{}@{}", i.name, i.spec)).collect();
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
        let vulns: Vec<Vuln> = idx
            .iter()
            .flat_map(|&i| self.rows[i].vulns.iter().cloned())
            .collect();
        self.pin_plan_for(&vulns)
    }

    fn pin_plan_for(&mut self, vulns: &[Vuln]) -> Vec<Pin> {
        let mut want: Vec<(String, Version)> = Vec::new();
        for v in vulns {
            let Some(fix) = pin_target(v) else {
                continue;
            };
            match want.iter_mut().find(|(n, _)| *n == v.package) {
                Some((_, cur)) => *cur = (*cur).clone().max(fix),
                None => want.push((v.package.clone(), fix)),
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
        // On a finding with nothing checked: pin that finding's package.
        if !self.rows.iter().any(|r| r.selected)
            && let Some((i, v)) = self.cursor_vuln()
            && !self.rows[i].busy()
        {
            let v = v.clone();
            let plan = self.pin_plan_for(std::slice::from_ref(&v));
            return self.confirm_and_pin(plan);
        }
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
        self.confirm_and_pin(plan);
    }

    fn confirm_and_pin(&mut self, plan: Vec<Pin>) {
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
            let fixes: Vec<crate::commit::Fixed> = self
                .rows
                .iter()
                .flat_map(|r| &r.vulns)
                .filter(|v| v.package == p.name && pin_target(v).is_some_and(|t| t <= p.version))
                .map(|v| fixed(&p.name, v))
                .collect();
            self.queued_fixes.extend(fixes.into_iter().map(|f| (key.clone(), f)));
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
/// `v`, fixed by changing `package`, as the commit lists it.
fn fixed(package: &str, v: &Vuln) -> crate::commit::Fixed {
    crate::commit::Fixed {
        package: package.to_string(),
        id: v.id.clone(),
        title: v.title.clone(),
        source: v.source.label().to_string(),
        severity: v.severity.label().to_string(),
    }
}

/// The version of a vulnerable transitive package to pin it to: the lowest fix in its
/// installed major release, or else the lowest newer fix.
fn pin_target(v: &Vuln) -> Option<Version> {
    if v.path.is_empty() || v.package == v.direct {
        return None;
    }
    let fixes: Vec<Version> = v
        .newer_fixes()
        .into_iter()
        .filter_map(|f| Version::parse(f).ok())
        .collect();
    let major = Version::parse(&v.version).ok().map(|i| i.major);
    fixes
        .iter()
        .find(|f| Some(f.major) == major)
        .or(fixes.first())
        .cloned()
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
            .map(|i| i.name.clone())
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

/// `1.2.3`, also written `v1.2.3` or `=1.2.3`.
fn parse_version(text: &str) -> Option<Version> {
    Version::parse(text.trim().trim_start_matches(['v', '='])).ok()
}

/// npm package names: `name` or `@scope/name`, of URL-safe characters.
fn valid_package_name(name: &str) -> bool {
    let ok = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    };
    match name.strip_prefix('@') {
        Some(scoped) => matches!(scoped.split_once('/'), Some((scope, pkg)) if ok(scope) && ok(pkg)),
        None => ok(name) && name.len() <= 214,
    }
}

fn no_such_version(name: &str, version: &Version, doc: &registry::Packument) -> String {
    // The nearest published versions around the one asked for.
    let below = doc.versions.keys().filter(|v| *v < version).next_back();
    let above = doc.versions.keys().find(|v| *v > version);
    let near: Vec<String> = below.into_iter().chain(above).map(Version::to_string).collect();
    let mut msg = format!("✘ {name} has no published version {version}");
    if !near.is_empty() {
        msg.push_str(&format!(" (nearest: {})", near.join(", ")));
    }
    if let Some(l) = &doc.latest {
        msg.push_str(&format!(", latest is {l}"));
    }
    msg
}

fn spec_in_manifest(root_deps: &[(String, String)], name: &str) -> Option<String> {
    root_deps
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, spec)| spec.clone())
}

/// How the packages of a job are installed.
#[derive(Debug, PartialEq)]
enum InstallPlan {
    /// Package manager commands, run in order (each the arguments after the program).
    Commands(Vec<Vec<String>>),
    /// Edit `package.json`, then run one plain install.
    Manifest(Vec<Change>),
}

/// One command can only install packages of one kind (`-D`, `-O`) and pin style (`--exact`).
/// When a job mixes them, separate commands would each be resolved on their own: updating
/// `react` (a dependency) fails while the old `eslint-plugin-react-hooks` (a dev dependency)
/// still asks for the old `react`, and the command that would have updated it never runs.
/// So such a job writes every new spec into `package.json` and installs once, letting the
/// package manager resolve them together.
fn install_plan(pm: Pm, items: &[InstallItem]) -> InstallPlan {
    let mut groups: Vec<((Kind, bool), Vec<String>)> = Vec::new();
    for it in items {
        let arg = format!("{}@{}", it.name, it.spec);
        match groups.iter_mut().find(|(k, _)| *k == (it.kind, it.exact)) {
            Some((_, v)) => v.push(arg),
            None => groups.push(((it.kind, it.exact), vec![arg])),
        }
    }
    let editable = items.iter().all(|it| it.kind != Kind::Override);
    if groups.len() > 1 && editable {
        return InstallPlan::Manifest(
            items
                .iter()
                .map(|it| {
                    let loc = vec![dep_field(it.kind).to_string(), it.name.clone()];
                    match &it.old {
                        Some(old) => Change::Set {
                            loc,
                            old: old.clone(),
                            new: it.spec.clone(),
                        },
                        // Not in package.json yet: a package being added or restored.
                        None => Change::Add {
                            loc,
                            new: it.spec.clone(),
                        },
                    }
                })
                .collect(),
        );
    }
    InstallPlan::Commands(
        groups
            .into_iter()
            .map(|((kind, exact), specs)| pm.install_args(&specs, kind, exact))
            .collect(),
    )
}

fn dep_field(kind: Kind) -> &'static str {
    match kind {
        Kind::Dev => "devDependencies",
        Kind::Optional => "optionalDependencies",
        Kind::Prod | Kind::Override => "dependencies",
    }
}

/// Applies `changes` to `package.json` and runs `install`. If the install fails, the file is
/// put back as it was, so a failed install doesn't leave new versions in it.
fn install_with_manifest(
    path: &std::path::Path,
    changes: &[Change],
    install: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let original = std::fs::read_to_string(path).map_err(|e| format!("reading package.json: {e}"))?;
    edit::apply(path, changes).map_err(|e| format!("{e:#}"))?;
    if let Err(e) = install() {
        let restored = std::fs::write(path, &original).is_ok();
        return Err(if restored {
            format!("{e}\n(package.json was put back as it was)")
        } else {
            format!("{e}\n(package.json could not be put back, check it)")
        });
    }
    Ok(())
}

fn run_job(dir: &std::path::Path, pm: Pm, job: &Job) -> Result<(), String> {
    if !job.uninstall.is_empty() {
        run_pm(dir, pm, &pm.uninstall_args(&job.uninstall))?;
    }
    if !job.items.is_empty() {
        match install_plan(pm, &job.items) {
            InstallPlan::Commands(cmds) => {
                for args in cmds {
                    run_pm(dir, pm, &args)?;
                }
            }
            InstallPlan::Manifest(changes) => {
                install_with_manifest(&dir.join("package.json"), &changes, || {
                    run_pm(dir, pm, &["install".to_string()])
                })?;
            }
        }
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
        assert!(!row(&app, "a").scan_outdated());
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
        assert!(a.scan_outdated());
        // `b` is at the scanned version, so its findings still apply.
        assert_eq!(ids(&app, "b"), ["B-1"]);
        assert!(!row(&app, "b").scan_outdated());
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
        assert!(!row(&app, "a").scan_outdated(), "1.1.0 was scanned");
        assert!(!app.snyk.stale);

        switch_version(&mut app, "a", "1.2.0");
        assert!(row(&app, "a").vulns.is_empty());
        assert!(row(&app, "a").scan_outdated(), "1.2.0 was never scanned");
        assert!(app.snyk.stale);

        // Back to the first version: its findings come back.
        switch_version(&mut app, "a", "1.0.0");
        assert_eq!(ids(&app, "a"), ["A-OLD"]);
        assert!(!row(&app, "a").scan_outdated());
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
        assert!(row(&app, "a").scan_outdated());
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
        assert!(row(&app, "a").scan_outdated(), "npm audit hasn't seen a@1.0.0");
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
        assert!(!row(&app, "a").scan_outdated());
        // `b` isn't installed and there's no lockfile: its version is unknown, so no
        // finding is looked up for it, not even under the package.json version.
        assert!(row(&app, "b").installed.is_none());
        assert!(row(&app, "b").vulns.is_empty());
        assert!(row(&app, "b").scan_outdated());

        // The lockfile moves `a` to 1.0.6 without package.json changing.
        install(&app.dir.clone(), "a", "1.0.6");
        app.read_installed_versions();
        app.refresh_findings();
        assert!(row(&app, "a").vulns.is_empty(), "1.0.6 was never scanned");
        assert!(row(&app, "a").scan_outdated());

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
        assert!(!row(&a, "a").scan_outdated(), "A's own scan still applies");
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
        assert!(row(&a, "a").scan_outdated(), "1.0.0 hasn't been scanned");
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
            .map(|i| format!("{}@{}", i.name, i.spec))
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

    fn item(name: &str, spec: &str, kind: Kind, old: Option<&str>) -> InstallItem {
        InstallItem {
            name: name.into(),
            spec: spec.into(),
            kind,
            exact: !spec.starts_with(['^', '~', '>']),
            old: old.map(String::from),
        }
    }

    #[test]
    fn packages_of_one_kind_install_with_one_command() {
        let plan = install_plan(
            Pm::Npm,
            &[
                item("react", "^19.0.0", Kind::Prod, Some("^18.2.0")),
                item("react-dom", "^19.0.0", Kind::Prod, Some("^18.2.0")),
            ],
        );
        assert_eq!(
            plan,
            InstallPlan::Commands(vec![vec![
                "install".into(),
                "react@^19.0.0".into(),
                "react-dom@^19.0.0".into()
            ]])
        );
    }

    #[test]
    fn packages_of_different_kinds_are_written_to_package_json_and_installed_once() {
        let plan = install_plan(
            Pm::Npm,
            &[
                item("react", "^19.0.0", Kind::Prod, Some("^18.2.0")),
                item("eslint-plugin-react-hooks", "^5.0.0", Kind::Dev, Some("^4.6.0")),
                item("typescript", "5.6.3", Kind::Dev, Some("5.4.5")),
            ],
        );
        let InstallPlan::Manifest(changes) = plan else {
            panic!("expected one install from package.json, got {plan:?}");
        };
        assert_eq!(
            changes,
            [
                Change::Set {
                    loc: vec!["dependencies".into(), "react".into()],
                    old: "^18.2.0".into(),
                    new: "^19.0.0".into()
                },
                Change::Set {
                    loc: vec!["devDependencies".into(), "eslint-plugin-react-hooks".into()],
                    old: "^4.6.0".into(),
                    new: "^5.0.0".into()
                },
                Change::Set {
                    loc: vec!["devDependencies".into(), "typescript".into()],
                    old: "5.4.5".into(),
                    new: "5.6.3".into()
                },
            ]
        );
    }

    #[test]
    fn a_package_not_in_package_json_yet_is_added_to_it() {
        // A package being added (or restored) together with a package of another kind.
        let plan = install_plan(
            Pm::Npm,
            &[
                item("react", "^19.0.0", Kind::Prod, Some("^18.2.0")),
                item("lodash", "^4.17.21", Kind::Dev, None),
            ],
        );
        let InstallPlan::Manifest(changes) = plan else {
            panic!("{plan:?}");
        };
        assert_eq!(
            changes[1],
            Change::Add {
                loc: vec!["devDependencies".into(), "lodash".into()],
                new: "^4.17.21".into()
            }
        );
    }

    #[test]
    fn a_failed_install_puts_package_json_back() {
        let dir = std::env::temp_dir().join(format!("depsu-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("package.json");
        let original = "{\n  \"dependencies\": {\n    \"react\": \"^18.2.0\"\n  }\n}\n";
        std::fs::write(&path, original).unwrap();
        let changes = [Change::Set {
            loc: vec!["dependencies".into(), "react".into()],
            old: "^18.2.0".into(),
            new: "^19.0.0".into(),
        }];

        let seen = std::cell::RefCell::new(String::new());
        let err = install_with_manifest(&path, &changes, || {
            *seen.borrow_mut() = std::fs::read_to_string(&path).unwrap();
            Err("npm error ERESOLVE".into())
        })
        .unwrap_err();
        assert!(seen.borrow().contains("^19.0.0"), "the install sees the new versions");
        assert!(err.contains("ERESOLVE") && err.contains("put back"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        install_with_manifest(&path, &changes, || Ok(())).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"react\": \"^19.0.0\""));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A fake registry: `a` has 1.0.0, 1.5.0 and 2.0.0; `lodash` has 4.17.20 and 4.17.21.
    fn fake_registry() -> Fetcher {
        use crate::registry::{Packument, VersionInfo};
        let doc = |name: &str, latest: &str, versions: &[&str]| Packument {
            latest: Some(Version::parse(latest).unwrap()),
            versions: versions
                .iter()
                .map(|v| {
                    let tarball = Some(format!("https://r/{name}/-/{name}-{v}.tgz"));
                    (Version::parse(v).unwrap(), VersionInfo { tarball, ..Default::default() })
                })
                .collect(),
        };
        let docs = HashMap::from([
            ("a".to_string(), doc("a", "2.0.0", &["1.0.0", "1.5.0", "2.0.0"])),
            ("b".to_string(), doc("b", "1.0.0", &["1.0.0"])),
            ("lodash".to_string(), doc("lodash", "4.17.21", &["4.17.20", "4.17.21"])),
            ("qs".to_string(), doc("qs", "6.0.4", &["6.0.3", "6.0.4"])),
        ]);
        Arc::new(move |n: &str| docs.get(n).cloned().ok_or_else(|| format!("{n} not found")))
    }
    /// Every file downloads, except those whose URL contains one of `blocked`.
    fn blocking(blocked: &'static [&'static str]) -> Prober {
        Arc::new(move |_, url: &str| Ok(!blocked.iter().any(|b| url.contains(b))))
    }
    fn offline_app() -> (App, Receiver<Job>) {
        let (mut app, rx) = app_capturing_installs();
        app.fetcher = fake_registry();
        app.prober = blocking(&[]);
        (app, rx)
    }
    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(c));
        }
    }
    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }
    /// Handles background events until an install is queued, or the log says `done`. With
    /// `done` = "never", waits briefly to show that nothing happens.
    fn settle(app: &mut App, rx: &Receiver<Job>, done: &str) -> Vec<Job> {
        let wait = if done == "never" { 200 } else { 5000 };
        let until = std::time::Instant::now() + std::time::Duration::from_millis(wait);
        let mut jobs = Vec::new();
        while std::time::Instant::now() < until {
            app.drain_events();
            jobs.extend(rx.try_iter());
            if !jobs.is_empty() || (!done.is_empty() && app.log.iter().any(|l| l.contains(done))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        jobs
    }
    fn specs(jobs: &[Job]) -> Vec<String> {
        jobs.iter()
            .flat_map(|j| &j.items)
            .map(|i| format!("{}@{}", i.name, i.spec))
            .collect()
    }

    #[test]
    fn e_installs_the_version_the_user_types() {
        let (mut app, rx) = offline_app();
        assert!(matches!(app.cursor_item(), Some(Item::Row { name, .. }) if name == "a"));
        app.on_key(key('e'));
        assert!(matches!(&app.input, Some(Input { purpose: InputPurpose::Version { name }, .. }) if name == "a"));
        type_text(&mut app, "1.5.0");
        press(&mut app, KeyCode::Enter);
        assert!(app.input.is_none());
        let jobs = settle(&mut app, &rx, "");
        assert_eq!(specs(&jobs), ["a@^1.5.0"], "keeps the ^ pin type");
    }

    #[test]
    fn e_rejects_a_version_that_was_never_published() {
        let (mut app, rx) = offline_app();
        app.on_key(key('e'));
        type_text(&mut app, "1.4.0");
        press(&mut app, KeyCode::Enter);
        let jobs = settle(&mut app, &rx, "no published version");
        assert!(jobs.is_empty());
        let msg = app.log.iter().find(|l| l.contains("no published version")).unwrap();
        assert!(msg.contains("a has no published version 1.4.0 (nearest: 1.0.0, 1.5.0), latest is 2.0.0"), "{msg}");
    }

    #[test]
    fn e_rejects_text_that_is_not_a_version() {
        let (mut app, rx) = offline_app();
        app.on_key(key('e'));
        type_text(&mut app, "^1.5");
        press(&mut app, KeyCode::Enter);
        assert!(app.log.last().unwrap().contains("isn't a version like 1.2.3"));
        assert!(settle(&mut app, &rx, "never").is_empty());
    }

    #[test]
    fn esc_cancels_typing() {
        let (mut app, rx) = offline_app();
        app.on_key(key('e'));
        type_text(&mut app, "1.5.0");
        press(&mut app, KeyCode::Esc);
        assert!(app.input.is_none());
        assert!(settle(&mut app, &rx, "never").is_empty());
        // Keys work as usual again.
        app.on_key(key('?'));
        assert!(app.show_info);
    }

    #[test]
    fn plus_adds_a_package_with_the_chosen_version_and_type() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "lodash@4.17.20");
        press(&mut app, KeyCode::Tab); // dependency → dev dependency
        assert!(matches!(&app.input, Some(Input { purpose: InputPurpose::Add { add_as: AddAs::Dev }, .. })));
        press(&mut app, KeyCode::Enter);
        let jobs = settle(&mut app, &rx, "");
        assert_eq!(specs(&jobs), ["lodash@^4.17.20"]);
        assert_eq!(jobs[0].items[0].kind, Kind::Dev);
        assert_eq!(jobs[0].items[0].old, None, "not in package.json yet");

        // Once installed it is listed like the others.
        app.on_install_finished(vec!["lodash".into()], Vec::new(), Ok(()));
        let r = row(&app, "lodash");
        assert_eq!(r.kind, Kind::Dev);
        assert_eq!(r.current, Version::new(4, 17, 20));
        assert!(r.outdated, "4.17.21 is out");
        assert!(!app.installing());
    }

    #[test]
    fn plus_without_a_version_adds_the_latest() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "lodash");
        press(&mut app, KeyCode::Enter);
        assert_eq!(specs(&settle(&mut app, &rx, "")), ["lodash@^4.17.21"]);
    }

    fn add_error(app: &App) -> String {
        app.input.as_ref().and_then(|i| i.error.clone()).unwrap_or_default()
    }

    #[test]
    fn problems_are_shown_in_the_dialog_which_stays_open() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "a");
        press(&mut app, KeyCode::Enter);
        assert!(add_error(&app).contains("a is already a dependency"), "{}", add_error(&app));
        // Fixing the text clears the message.
        press(&mut app, KeyCode::Backspace);
        assert_eq!(add_error(&app), "");

        type_text(&mut app, "nope");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.input.as_ref().unwrap().looking_up.as_deref(), Some("nope"));
        // Keys other than esc wait for the registry.
        app.on_key(key('x'));
        assert_eq!(app.input.as_ref().unwrap().text, "nope");
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while add_error(&app).is_empty() && std::time::Instant::now() < until {
            app.drain_events();
        }
        assert!(add_error(&app).contains("Could not look up nope"), "{}", add_error(&app));
        assert!(app.input.as_ref().unwrap().looking_up.is_none());

        app.input.as_mut().unwrap().text.clear();
        type_text(&mut app, "lodash@4.0.0");
        press(&mut app, KeyCode::Enter);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while add_error(&app).is_empty() && std::time::Instant::now() < until {
            app.drain_events();
        }
        assert!(add_error(&app).contains("lodash has no published version 4.0.0"), "{}", add_error(&app));

        app.input.as_mut().unwrap().text.clear();
        type_text(&mut app, "not a name");
        press(&mut app, KeyCode::Enter);
        assert!(add_error(&app).contains("isn't a package name"));
        assert!(rx.try_iter().next().is_none());
        assert!(!app.installing(), "nothing left half-added");
    }

    #[test]
    fn closing_the_dialog_while_looking_up_drops_the_answer() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "lodash");
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Esc);
        assert!(app.input.is_none());
        assert!(settle(&mut app, &rx, "never").is_empty());
        assert!(!app.installing());
    }

    #[test]
    fn plus_adds_an_override() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        // Up from the first choice wraps to the last: override.
        press(&mut app, KeyCode::Up);
        assert!(matches!(&app.input, Some(Input { purpose: InputPurpose::Add { add_as: AddAs::Override }, .. })));
        type_text(&mut app, "lodash@4.17.20");
        press(&mut app, KeyCode::Enter);
        let jobs = settle(&mut app, &rx, "");
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].items.is_empty(), "an override installs nothing by name");
        assert_eq!(
            jobs[0].edits,
            [Change::Add {
                loc: vec!["overrides".into(), "lodash".into()],
                new: "^4.17.20".into()
            }]
        );
        assert!(app.installing());
    }

    #[test]
    fn npm_cannot_override_a_dependency_of_the_project() {
        let (mut app, _rx) = offline_app();
        app.on_key(key('+'));
        press(&mut app, KeyCode::BackTab);
        type_text(&mut app, "a");
        press(&mut app, KeyCode::Enter);
        assert!(add_error(&app).contains("npm needs its override to equal"), "{}", add_error(&app));
    }

    #[test]
    fn the_add_dialog_is_drawn_in_the_middle_of_the_screen() {
        let (mut app, _rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "lodash");
        press(&mut app, KeyCode::Tab);
        let screen = render(&mut app, 100, 40);
        let top = screen.iter().position(|l| l.contains(" Add a package ")).expect("drawn");
        let bottom = top + 1 + screen[top + 1..].iter().position(|l| l.contains('╰')).unwrap();
        assert!((top as i32 - (40 - 1 - bottom) as i32).abs() <= 1, "top {top}, bottom {bottom}");
        let body = screen[top..=bottom].join("\n");
        assert!(body.contains("Package  lodash█"));
        assert!(body.contains("○ dependency"));
        assert!(body.contains("● dev dependency"));
        assert!(body.contains("○ dependency      dependencies"));
        assert!(body.contains("○ override        overrides"));
    }

    #[test]
    fn a_failed_add_leaves_no_row_behind() {
        let (mut app, rx) = offline_app();
        app.on_key(key('+'));
        type_text(&mut app, "lodash");
        press(&mut app, KeyCode::Enter);
        settle(&mut app, &rx, "");
        app.on_install_finished(vec!["lodash".into()], Vec::new(), Err("E404".into()));
        assert!(!app.rows.iter().any(|r| r.name == "lodash"));
        assert!(!app.installing());
    }

    #[test]
    fn package_names() {
        for ok in ["lodash", "@types/node", "left-pad", "a.b_c~d"] {
            assert!(valid_package_name(ok), "{ok}");
        }
        for bad in ["", "has space", "@scope", "@/x", ".hidden", "a/b", "ä"] {
            assert!(!valid_package_name(bad), "{bad}");
        }
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
        let left = screen[top].chars().position(|c| c == '╭').unwrap();
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
    fn the_row_names_the_scanner_that_has_not_scanned_its_version() {
        // npm audit ran at a@0.9.0 in an earlier session; a@1.0.0 is installed now.
        let mut app = app_with_cache("1.0.0", |c| {
            c.set_findings("npm audit", "a", "0.9.0", Findings::default());
            c.set_findings("npm audit", "b", "1.0.0", Findings::default());
        });
        assert_eq!(row(&app, "a").unscanned, [Source::NpmAudit]);

        // Scanning with Snyk now covers Snyk, but not npm audit.
        app.apply_scan(Source::Snyk, Report::default(), false);
        assert_eq!(row(&app, "a").unscanned, [Source::NpmAudit]);
        assert!(row(&app, "b").unscanned.is_empty());
        assert!(!app.snyk.stale);
        assert!(app.audit.stale);
        let screen = render(&mut app, 140, 30).join("\n");
        assert!(
            screen.contains("↻ npm audit (n) hasn't scanned this version"),
            "{screen}"
        );

        // After npm audit, nothing is missing.
        app.apply_scan(Source::NpmAudit, Report::default(), false);
        assert!(row(&app, "a").unscanned.is_empty());
        assert!(!render(&mut app, 140, 30).join("\n").contains("↻"));
    }

    /// `a` with three findings: one fixed by upgrading `a`, one only by overriding the nested
    /// `qs`, and one without any fix.
    fn app_with_three_findings() -> App {
        let mut upgrade = vuln("a", "1.0.0", "UPGRADE");
        upgrade.upgrade_to = Some("1.0.1".into());
        let mut nested = vuln("a", "1.0.0", "NESTED");
        nested.package = "qs".into();
        nested.version = "6.0.0".into();
        nested.path = vec!["mid".into(), "qs".into()];
        nested.upgrade_to = None;
        nested.fixed_in = vec!["5.9.0".into(), "6.0.4".into()];
        let mut none = vuln("a", "1.0.0", "NOFIX");
        none.package = "x".into();
        none.path = vec!["x".into()];
        none.upgrade_to = None;
        none.fixed_in = Vec::new();
        app_with_cache("1.0.0", |c| {
            c.set_findings(
                "snyk",
                "a",
                "1.0.0",
                Findings {
                    vulns: vec![upgrade, nested, none],
                    fix: None,
                },
            );
            c.set_findings("snyk", "b", "1.0.0", Findings::default());
        })
    }
    /// Puts the cursor on the finding `id`.
    fn cursor_on_finding(app: &mut App, id: &str) {
        let pos = app
            .view
            .iter()
            .position(|it| {
                matches!(it, Item::Detail { idx, child: Child::Vuln(i), .. }
                    if app.rows[*idx].vulns[*i].id == id)
            })
            .expect("finding listed");
        app.table.select(Some(pos));
    }
    /// The screen line containing `needle`, and the colour of the cell where `mark` starts.
    fn line_and_colour(
        app: &mut App,
        needle: &str,
        mark: &str,
    ) -> (String, Option<ratatui::style::Color>) {
        let (w, h) = (220u16, 30u16);
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        for y in 0..h {
            let line: String = (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect();
            if line.contains(needle) {
                // The cell where `mark` starts (wide characters take two cells).
                let at = (0..w).find(|&x| {
                    (x..w)
                        .map(|c| buf[(c, y)].symbol().to_string())
                        .collect::<String>()
                        .starts_with(mark)
                });
                return (line, at.map(|x| buf[(x, y)].fg));
            }
        }
        panic!("{needle:?} not on screen");
    }

    #[test]
    fn findings_with_a_fix_a_key_can_apply_are_highlighted() {
        let mut app = app_with_three_findings();
        let (line, colour) = line_and_colour(&mut app, "UPGRADE", "⬆ fix");
        assert!(line.contains("⬆ fix: i installs a ^1.0.1"), "{line}");
        assert_eq!(colour, Some(ratatui::style::Color::Green));

        let (line, colour) = line_and_colour(&mut app, "NESTED", "⬆ fix");
        assert!(line.contains("⬆ fix: p overrides qs to ^6.0.4"), "{line}");
        assert!(line.contains("(upgrading a doesn't bring it in)"), "{line}");
        assert_eq!(colour, Some(ratatui::style::Color::Green));

        let (line, colour) = line_and_colour(&mut app, "NOFIX", "no fix");
        assert!(line.contains("no fix available"), "{line}");
        assert!(!line.contains("fix: i") && !line.contains("fix: p"), "{line}");
        assert_eq!(colour, Some(ratatui::style::Color::DarkGray));
    }

    #[test]
    fn the_keys_do_what_the_highlight_says() {
        let mut app = app_with_three_findings();
        let (tx, rx) = mpsc::channel();
        app.jobs = tx;

        // p on the nested finding pins qs (asking first).
        cursor_on_finding(&mut app, "NESTED");
        assert!(app.hints().0.contains(&"p pin fix as override".to_string()));
        assert!(!app.hints().0.contains(&"i install fix".to_string()));
        app.on_key(key('p'));
        assert!(
            app.log.iter().any(|l| l.contains("will set in package.json overrides: qs → ^6.0.4")),
            "{:?}",
            app.log
        );
        app.on_key(key('p'));
        let job = rx.try_recv().expect("override queued");
        assert_eq!(
            job.edits,
            [Change::Add {
                loc: vec!["overrides".into(), "qs".into()],
                new: "^6.0.4".into()
            }]
        );

        // i on it explains that p is the way.
        app.on_key(key('i'));
        assert!(app.log.last().unwrap().contains("press p to override qs"), "{:?}", app.log.last());

        // On the finding without a fix, neither key is offered.
        cursor_on_finding(&mut app, "NOFIX");
        let hints = app.hints().0;
        assert!(!hints.iter().any(|h| h.contains("install fix") || h.contains("pin fix")), "{hints:?}");
    }

    #[test]
    fn the_report_lists_vulnerable_packages_first_in_their_own_table() {
        let mut app = app_with_cache("1.0.0", |c| {
            // a: two high findings from Snyk, one low from npm audit. b: one critical.
            let mut low = vuln("a", "1.0.0", "A-LOW");
            low.severity = Severity::Low;
            low.source = Source::NpmAudit;
            c.set_findings(
                "snyk",
                "a",
                "1.0.0",
                Findings {
                    vulns: vec![vuln("a", "1.0.0", "A-1"), vuln("a", "1.0.0", "A-2")],
                    fix: None,
                },
            );
            c.set_findings("npm audit", "a", "1.0.0", Findings { vulns: vec![low], fix: None });
            let mut crit = vuln("b", "1.0.0", "B-1");
            crit.severity = Severity::Critical;
            c.set_findings("snyk", "b", "1.0.0", Findings { vulns: vec![crit], fix: None });
            c.set_findings("npm audit", "b", "1.0.0", Findings::default());
        });
        // A third package without findings.
        install(&app.dir.clone(), "c", "1.0.0");
        app.current.insert("c".into(), (Kind::Prod, "^", Version::new(1, 0, 0)));
        app.on_fetched("c".into(), Version::new(1, 0, 0));

        let md = crate::export::markdown(&app);
        let vulnerable = md.find("## Packages with vulnerabilities").expect("own table");
        let others = md.find("## Other packages").expect("the rest");
        let snyk = md.find("## Snyk report").expect("findings after the packages");
        assert!(vulnerable < others && others < snyk, "{md}");
        let first = &md[vulnerable..others];
        let rest = &md[others..snyk];
        assert!(first.contains("| Vulnerabilities |"));
        // Worst first: b (critical) before a (high).
        let (b, a) = (first.find("| b |").unwrap(), first.find("| a |").unwrap());
        assert!(b < a, "{first}");
        assert!(first.contains("| 2 high, 1 low (snyk 2, npm audit 1) |"), "{first}");
        assert!(first.contains("| 1 critical (snyk 1) |"), "{first}");
        assert!(!first.contains("| c |"));
        assert!(rest.contains("| c | dep | 1.0.0 | 1.0.0 | up to date |"), "{rest}");
        assert!(!rest.contains("| a |") && !rest.contains("| b |"));
    }

    #[test]
    fn a_report_without_findings_has_a_single_package_table() {
        let app = app_with_cache("1.0.0", |_| {});
        let md = crate::export::markdown(&app);
        assert!(md.contains("## Packages\n"));
        assert!(!md.contains("with vulnerabilities") && !md.contains("Other packages"));
        assert!(md.contains("| a | dep |") && md.contains("| b | dep |"));
    }

    /// `a` declares peers `react ^18.0.0` (not installed) and `b ^2.0.0` (1.0.0 is).
    fn app_with_peers() -> App {
        let mut app = app_with_cache("1.0.0", |_| {});
        let dir = app.dir.join("node_modules").join("a");
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"a","version":"1.0.0","peerDependencies":{"react":"^18.0.0","b":"^2.0.0"}}"#,
        )
        .unwrap();
        app.read_installed_versions();
        app
    }

    #[test]
    fn a_package_knows_its_peers_and_whether_they_fit() {
        let app = app_with_peers();
        let peers = &row(&app, "a").peers;
        assert_eq!(peers.len(), 2);
        assert_eq!((peers[0].name.as_str(), peers[0].range.as_str()), ("b", "^2.0.0"));
        assert_eq!(peers[0].installed, Some(Version::new(1, 0, 0)));
        assert_eq!(peers[0].met(), Some(false));
        assert_eq!(peers[1].name, "react");
        assert_eq!(peers[1].met(), None, "not installed");
        assert!(row(&app, "b").peers.is_empty());
    }

    #[test]
    fn the_list_flags_only_unmet_peers() {
        let mut app = app_with_peers();
        let (line, colour) = line_and_colour(&mut app, "unmet", "⚠");
        assert!(line.contains("⚠ unmet peer: b ^2.0.0 (has 1.0.0)"), "{line}");
        assert_eq!(colour, Some(ratatui::style::Color::Yellow));
        // The peer that isn't installed, and peers that fit, stay out of the list.
        let screen = render(&mut app, 200, 30).join("\n");
        assert!(!screen.contains("react ^18"), "{screen}");
        assert_eq!(screen.matches("⚠ unmet peer").count(), 1, "only a has an unmet peer");

        // Too narrow for the details: just the count.
        let screen = render(&mut app, 80, 20).join("\n");
        assert!(screen.contains("⚠ 1 unmet peer"), "{screen}");
        assert!(!screen.contains("(has 1.0.0)"), "{screen}");

        // Once the peer fits, the warning is gone.
        install(&app.dir.clone(), "b", "2.0.0");
        app.read_installed_versions();
        assert!(!render(&mut app, 200, 30).join("\n").contains("unmet"));
    }

    #[test]
    fn the_details_panel_lists_the_peers_with_their_versions() {
        let mut app = app_with_peers();
        app.on_key(key('?'));
        let screen = render(&mut app, 200, 40).join("\n");
        assert!(
            screen.contains("2 peer dependencies: b ^2.0.0, but 1.0.0 is installed, react ^18.0.0 (not installed)"),
            "{screen}"
        );
    }

    /// A registry where `a` 0.9.0 accepts `b ^1`, and `b` has 2.0.0 and 2.1.0.
    fn peer_fix_registry() -> Fetcher {
        use crate::registry::{Packument, VersionInfo};
        let doc = |latest: &str, versions: &[(&str, &[(&str, &str)])]| Packument {
            latest: Some(Version::parse(latest).unwrap()),
            versions: versions
                .iter()
                .map(|(v, peers)| {
                    (
                        Version::parse(v).unwrap(),
                        VersionInfo {
                            peers: peers.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect(),
                            tarball: None,
                        },
                    )
                })
                .collect(),
        };
        let docs = HashMap::from([
            (
                "a".to_string(),
                doc("1.0.0", &[("0.9.0", &[("b", "^1.0.0")]), ("1.0.0", &[("b", "^2.0.0")])]),
            ),
            ("b".to_string(), doc("2.1.0", &[("1.0.0", &[]), ("2.0.0", &[]), ("2.1.0", &[])])),
        ]);
        Arc::new(move |n: &str| docs.get(n).cloned().ok_or_else(|| format!("{n} not found")))
    }
    /// Handles background events until `done` holds.
    fn wait_until(app: &mut App, done: impl Fn(&App) -> bool) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !done(app) && std::time::Instant::now() < until {
            app.drain_events();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(done(app), "timed out; log: {:?}", app.log);
    }

    #[test]
    fn f_offers_to_update_the_peer_or_change_the_package() {
        let mut app = app_with_peers();
        app.fetcher = peer_fix_registry();
        let (tx, rx) = mpsc::channel();
        app.jobs = tx;
        assert!(app.hints().0.contains(&"f fix unmet peers".to_string()));
        app.on_key(key('f'));
        wait_until(&mut app, |a| a.peer_fix.is_some());
        let p = app.peer_fix.as_ref().unwrap();
        let labels: Vec<&str> = p.options.iter().map(|o| o.label.as_str()).collect();
        assert_eq!(labels, ["update b to 2.1.0", "downgrade a to 0.9.0"]);

        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains(" Fix the peers of a "), "{screen}");
        assert!(screen.contains("a needs b ^2.0.0, but 1.0.0 is installed."), "{screen}");
        assert!(screen.contains("› 1 update b to 2.1.0"), "{screen}");
        assert!(screen.contains("  2 downgrade a to 0.9.0"), "{screen}");

        // Down, then enter: the second option goes through the peer check, then installs.
        press(&mut app, KeyCode::Down);
        assert_eq!(app.peer_fix.as_ref().unwrap().choice, 1);
        press(&mut app, KeyCode::Enter);
        assert!(app.peer_fix.is_none());
        let jobs = settle(&mut app, &rx, "");
        assert_eq!(specs(&jobs), ["a@^0.9.0"]);
    }

    #[test]
    fn a_number_picks_an_option_and_other_keys_cancel() {
        let mut app = app_with_peers();
        app.fetcher = peer_fix_registry();
        let (tx, rx) = mpsc::channel();
        app.jobs = tx;
        app.on_key(key('f'));
        wait_until(&mut app, |a| a.peer_fix.is_some());
        app.on_key(key('x'));
        assert!(app.peer_fix.is_none());
        assert!(settle(&mut app, &rx, "never").is_empty());

        app.on_key(key('f'));
        wait_until(&mut app, |a| a.peer_fix.is_some());
        app.on_key(key('1'));
        assert_eq!(specs(&settle(&mut app, &rx, "")), ["b@^2.1.0"]);
    }

    #[test]
    fn f_on_a_package_without_unmet_peers_says_so() {
        let mut app = app_with_peers();
        let b = app.view.iter().position(|it| matches!(it, Item::Row { name, .. } if name == "b")).unwrap();
        app.table.select(Some(b));
        app.on_key(key('f'));
        assert_eq!(app.log.last().unwrap(), "b has no unmet peers.");
        assert!(!app.hints().0.iter().any(|h| h.contains("unmet")));
    }

    /// `a` and `b` (both up to date), `a` with an override listed under it, and `b` used by `a`.
    fn app_to_delete_from() -> (App, Receiver<Job>) {
        let (mut app, rx) = app_capturing_installs();
        let i = app.rows.iter().position(|r| r.name == "a").unwrap();
        app.rows[i].overrides = vec![ovr("a", "1.0.0", "a")];
        app.show_overrides = Overrides::Full;
        app.dependents.insert(
            "b".into(),
            vec![crate::tree::Dependent {
                name: "a".into(),
                version: Some(Version::new(1, 0, 0)),
                range: "^1.0.0".into(),
                direct: "a".into(),
            }],
        );
        app.rebuild_view();
        (app, rx)
    }
    fn cursor_to(app: &mut App, pred: impl Fn(&Item) -> bool) {
        let pos = app.view.iter().position(pred).expect("listed");
        app.table.select(Some(pos));
    }

    #[test]
    fn up_to_date_packages_can_be_checked() {
        let (mut app, _rx) = app_to_delete_from();
        assert!(!row(&app, "b").outdated);
        cursor_to(&mut app, |it| matches!(it, Item::Row { name, .. } if name == "b"));
        app.on_key(key(' '));
        assert!(row(&app, "b").selected);
        app.on_key(key('a'));
        assert!(row(&app, "a").selected && row(&app, "b").selected);
    }

    #[test]
    fn d_deletes_checked_packages_and_overrides_together_after_asking() {
        let (mut app, rx) = app_to_delete_from();
        cursor_to(&mut app, |it| matches!(it, Item::Row { name, .. } if name == "b"));
        app.on_key(key(' '));
        cursor_to(&mut app, |it| matches!(it, Item::Detail { child: Child::Own(0), .. }));
        app.on_key(key(' '));
        assert!(app.hints().0.contains(&"d delete 2 checked".to_string()), "{:?}", app.hints().0);

        app.on_key(key('d'));
        let p = app.delete_prompt.as_ref().expect("asks first");
        assert_eq!(p.packages, ["b"]);
        assert_eq!(p.overrides.len(), 1);
        assert!(p.warnings[0].contains("b is used by a"), "{:?}", p.warnings);
        assert!(rx.try_recv().is_err(), "nothing happens before the answer");
        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains(" Delete 2 items "), "{screen}");
        assert!(screen.contains("Uninstall 1 package:"), "{screen}");
        assert!(screen.contains("✂ b ^1.0.0  (dep)"), "{screen}");
        assert!(screen.contains("Remove 1 override from package.json:"), "{screen}");
        assert!(screen.contains("⚠ b is used by a"), "{screen}");

        app.on_key(key('y'));
        assert!(app.delete_prompt.is_none());
        let job = rx.try_recv().expect("queued");
        assert_eq!(job.uninstall, ["b"]);
        assert_eq!(
            job.edits,
            [Change::Remove {
                loc: vec!["overrides".into(), "a".into()],
                old: "1.0.0".into()
            }]
        );
        assert_eq!(row(&app, "b").status, Status::Queued);
        assert!(!row(&app, "b").selected && app.selected_overrides.is_empty());
    }

    /// The rows of the dialog box on `screen`: from its top border to its bottom border.
    fn dialog_rows(screen: &[String], title: &str) -> Vec<String> {
        let top = screen.iter().position(|l| l.contains(title)).expect("dialog drawn");
        let bottom = top
            + screen[top..]
                .iter()
                .position(|l| l.contains('╰'))
                .expect("the dialog's bottom border is on the screen");
        screen[top..=bottom].to_vec()
    }

    #[test]
    fn a_long_delete_list_fits_the_dialog() {
        let (mut app, _rx) = app_capturing_installs();
        // 30 packages with long names, each used by another installed package.
        let names: Vec<String> = (0..30).map(|i| format!("@some-long-scope/package-number-{i:02}")).collect();
        for n in &names {
            app.dependents.insert(
                n.clone(),
                vec![crate::tree::Dependent {
                    name: format!("{n}-consumer"),
                    version: None,
                    range: "^1.0.0".into(),
                    direct: n.clone(),
                }],
            );
        }
        let overrides: Vec<Override> = (0..8).map(|i| ovr(&format!("o{i}"), "1.0.0", &format!("o{i}"))).collect();
        app.delete_prompt = Some(DeletePrompt {
            packages: names.clone(),
            overrides,
            warnings: names
                .iter()
                .map(|n| format!("{n} is used by {n}-consumer: they may stop working without it"))
                .collect(),
        });
        for (w, h) in [(100u16, 30u16), (60, 24), (120, 50)] {
            let screen = render(&mut app, w, h);
            let rows = dialog_rows(&screen, " Delete 38 items ");
            let body = rows.join("\n");
            assert!(body.contains("y / enter delete"), "{w}x{h}: the keys must stay visible\n{body}");
            assert!(body.contains("Uninstall 30 packages:"), "{w}x{h}\n{body}");
            assert!(body.contains("Remove 8 overrides from package.json:"), "{w}x{h}\n{body}");
            assert!(body.contains("… and "), "{w}x{h}: the cut lists say how much is left\n{body}");
            assert!(rows.len() <= h as usize, "{w}x{h}");
            // Every row of the box is closed on both sides: no text runs past the border.
            let top: Vec<char> = rows[0].chars().collect();
            let left = top.iter().position(|&c| c == '╭').unwrap();
            let right = top.iter().position(|&c| c == '╮').unwrap();
            for r in &rows[1..rows.len() - 1] {
                let c: Vec<char> = r.chars().collect();
                assert!(c[left] == '│' && c[right] == '│', "{w}x{h}: {r:?}");
            }
            let bottom: Vec<char> = rows.last().unwrap().chars().collect();
            assert!(bottom[left] == '╰' && bottom[right] == '╯', "{w}x{h}");
        }
    }

    #[test]
    fn d_removes_an_unneeded_override_and_x_no_longer_does_anything() {
        let (mut app, rx) = app_capturing_installs();
        let o = ovr("lodash", "4.17.21", "lodash");
        app.unneeded.insert(o.key(), Unneeded::Unused);
        app.overrides = vec![o];
        app.rebuild_view();
        let screen = render(&mut app, 120, 30).join("\n");
        assert!(screen.contains("Unneeded overrides (1), press d to remove"), "{screen}");
        cursor_to(&mut app, |it| matches!(it, Item::Override { .. }));
        assert!(app.hints().0.contains(&"d remove override".to_string()));
        assert!(!app.hints().0.iter().any(|h| h.starts_with("x ")));

        app.on_key(key('x'));
        assert!(app.delete_prompt.is_none() && rx.try_recv().is_err(), "x is free now");

        app.on_key(key('d'));
        let p = app.delete_prompt.as_ref().expect("asks first");
        assert_eq!(p.overrides[0].name, "lodash");
        assert!(p.warnings.iter().any(|w| w.starts_with("Scan again")), "{:?}", p.warnings);
        app.on_key(key('y'));
        let job = rx.try_recv().expect("queued");
        assert_eq!(
            job.edits,
            [Change::Remove {
                loc: vec!["overrides".into(), "lodash".into()],
                old: "4.17.21".into()
            }]
        );
    }

    #[test]
    fn removing_an_override_not_flagged_unneeded_warns_in_the_dialog() {
        let (mut app, _rx) = app_to_delete_from();
        cursor_to(&mut app, |it| matches!(it, Item::Detail { child: Child::Own(0), .. }));
        app.on_key(key('d'));
        let w = &app.delete_prompt.as_ref().unwrap().warnings;
        assert!(w.iter().any(|w| w.starts_with("Not flagged ✂ unneeded: a.")), "{w:?}");
    }

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let o = std::process::Command::new("git").args(args).current_dir(dir).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    #[test]
    fn c_commits_the_changes_with_a_conventional_title() {
        let (mut app, _rx) = app_capturing_installs();
        let dir = app.dir.clone();
        let lock = |v: &str| {
            format!(r#"{{"lockfileVersion":3,"packages":{{"node_modules/a":{{"version":"{v}"}}}}}}"#)
        };
        std::fs::write(dir.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        std::fs::write(dir.join("package-lock.json"), lock("1.0.0")).unwrap();
        std::fs::write(dir.join(".gitignore"), "node_modules\ncache.json*\n").unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")] {
            git(&dir, &["config", k, v]);
        }
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-q", "-m", "init"]);
        // An upgrade, as an install of a@2.0.0 would leave it.
        std::fs::write(dir.join("package.json"), r#"{"dependencies":{"a":"^2.0.0"}}"#).unwrap();
        std::fs::write(dir.join("package-lock.json"), lock("2.0.0")).unwrap();

        assert!(app.hints().2.contains(&"c commit".to_string()));
        app.on_key(key('c'));
        wait_until(&mut app, |a| a.commit_prompt.is_some());
        let p = app.commit_prompt.as_ref().unwrap();
        assert_eq!(p.title, "chore: upgrade a 1.0.0 to 2.0.0");
        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains(" Commit to git "), "{screen}");
        assert!(screen.contains("Title  chore: upgrade a 1.0.0 to 2.0.0█"), "{screen}");
        assert_eq!(screen.matches("upgrade a 1.0.0 to 2.0.0").count(), 1, "the title isn't repeated\n{screen}");
        assert!(screen.contains("Body   (none: the title says it all)"), "{screen}");
        assert!(screen.contains("Files  package.json, package-lock.json   on main"), "{screen}");

        // The title can be edited: `chore:` → `fix(deps):`.
        for _ in 0.."chore: upgrade a 1.0.0 to 2.0.0".len() {
            press(&mut app, KeyCode::Backspace);
        }
        type_text(&mut app, "fix(deps): upgrade a to 2.0.0");
        // Without the versions the title no longer says it all: the body comes back.
        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains("Body   - upgrade a 1.0.0 to 2.0.0"), "{screen}");
        let before = dialog_rows(&render(&mut app, 120, 40), " Commit to git ");
        press(&mut app, KeyCode::Enter);
        // Committing doesn't move anything in the dialog: the status replaces the keys.
        if app.commit_prompt.as_ref().is_some_and(|p| p.busy) {
            let during = dialog_rows(&render(&mut app, 120, 40), " Commit to git ");
            assert_eq!(during.len(), before.len(), "{}", during.join("\n"));
            // Only the title's cursor goes (it can't be edited while git runs).
            let plain = |rows: &[String]| -> Vec<String> { rows.iter().map(|r| r.replace('█', " ")).collect() };
            assert_eq!(plain(&during[..during.len() - 4]), plain(&before[..before.len() - 4]));
            assert!(during.join("\n").contains("Committing…"));
            assert!(!during.join("\n").contains("enter commit"));
        }
        wait_until(&mut app, |a| a.commit_prompt.is_none());
        assert!(app.log.last().unwrap().contains("committed") && app.log.last().unwrap().contains("fix(deps): upgrade a to 2.0.0"), "{:?}", app.log);
        assert_eq!(git(&dir, &["log", "-1", "--format=%s"]), "fix(deps): upgrade a to 2.0.0");
        assert_eq!(git(&dir, &["log", "-1", "--format=%b"]), "- upgrade a 1.0.0 to 2.0.0");

        // Nothing left: c says so.
        app.on_key(key('c'));
        wait_until(&mut app, |a| a.log.last().is_some_and(|l| l.starts_with("Nothing to commit")));
        assert!(app.commit_prompt.is_none());
    }

    #[test]
    fn applied_fixes_are_listed_in_the_commit_body() {
        let mut app = app_with_three_findings();
        let (tx, rx) = mpsc::channel();
        app.jobs = tx;
        let dir = app.dir.clone();
        std::fs::write(dir.join("package.json"), r#"{"dependencies":{"a":"^1.0.0","b":"^1.0.0"}}"#).unwrap();
        std::fs::write(dir.join(".gitignore"), "node_modules\ncache.json*\n").unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")] {
            git(&dir, &["config", k, v]);
        }
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-q", "-m", "init"]);

        // Upgrading a to its fix version fixes UPGRADE (and nothing else).
        app.queue_install(vec![("a".into(), Version::new(1, 0, 1))], Vec::new());
        rx.try_recv().expect("install queued");
        app.on_install_finished(vec!["a".into()], Vec::new(), Ok(()));
        let ids: Vec<&str> = app.session_fixes.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["UPGRADE"]);

        // Overriding qs with p fixes NESTED.
        cursor_on_finding(&mut app, "NESTED");
        app.on_key(key('p'));
        app.on_key(key('p'));
        let job = rx.try_recv().expect("override queued");
        app.on_install_finished(Vec::new(), job.keys, Ok(()));
        let ids: Vec<&str> = app.session_fixes.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["UPGRADE", "NESTED"]);
        assert_eq!(app.session_fixes[1].package, "qs");

        // What those installs left in package.json.
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies":{"a":"^1.0.1","b":"^1.0.0"},"overrides":{"qs":"^6.0.4"}}"#,
        )
        .unwrap();
        app.on_key(key('c'));
        wait_until(&mut app, |a| a.commit_prompt.is_some());
        let p = app.commit_prompt.as_ref().unwrap();
        assert_eq!(p.title, "chore: upgrade a 1.0.0 to 1.0.1, override qs to ^6.0.4");
        assert_eq!(
            p.plan.body,
            "- upgrade a 1.0.0 to 1.0.1\n- override qs to ^6.0.4\n\nFixes:\n- UPGRADE: Bad (high)\n- NESTED: Bad (high)"
        );
        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains("Body   Fixes:") && screen.contains("- NESTED: Bad (high)"), "{screen}");
        assert_eq!(screen.matches("upgrade a 1.0.0 to 1.0.1").count(), 1, "only in the title\n{screen}");

        press(&mut app, KeyCode::Enter);
        wait_until(&mut app, |a| a.commit_prompt.is_none());
        // The title names both changes: the body doesn't repeat them, only the fixes.
        assert_eq!(
            git(&dir, &["log", "-1", "--format=%b"]),
            "Fixes:\n- UPGRADE: Bad (high)\n- NESTED: Bad (high)"
        );
        assert!(app.session_fixes.is_empty(), "committed fixes aren't listed again");
    }

    #[test]
    fn a_failed_install_fixes_nothing() {
        let mut app = app_with_three_findings();
        let (tx, _rx) = mpsc::channel();
        app.jobs = tx;
        app.queue_install(vec![("a".into(), Version::new(1, 0, 1))], Vec::new());
        app.on_install_finished(vec!["a".into()], Vec::new(), Err("npm error".into()));
        assert!(app.session_fixes.is_empty());
        // A version below the fix fixes nothing either.
        app.queue_install(vec![("a".into(), Version::new(1, 0, 0))], Vec::new());
        app.on_install_finished(vec!["a".into()], Vec::new(), Ok(()));
        assert!(app.session_fixes.is_empty());
    }

    #[test]
    fn a_failing_commit_keeps_the_dialog_open_with_git_s_message() {
        let (mut app, _rx) = app_capturing_installs();
        let dir = app.dir.clone();
        std::fs::write(dir.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        std::fs::write(dir.join(".gitignore"), "node_modules\ncache.json*\n").unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")] {
            git(&dir, &["config", k, v]);
        }
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-q", "-m", "init"]);
        // A pre-commit hook that refuses.
        let hook = dir.join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\necho 'lint failed: 3 problems' >&2\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(dir.join("package.json"), r#"{"dependencies":{"a":"^2.0.0"}}"#).unwrap();

        app.on_key(key('c'));
        wait_until(&mut app, |a| a.commit_prompt.is_some());
        press(&mut app, KeyCode::Enter);
        wait_until(&mut app, |a| a.commit_prompt.as_ref().is_some_and(|p| p.error.is_some()));
        let p = app.commit_prompt.as_ref().unwrap();
        assert!(!p.busy);
        assert!(p.error.as_ref().unwrap().contains("lint failed: 3 problems"), "{:?}", p.error);
        assert_eq!(git(&dir, &["log", "-1", "--format=%s"]), "init", "nothing was committed");
        press(&mut app, KeyCode::Esc);
        assert!(app.commit_prompt.is_none());
    }

    fn buffer(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        term.backend().buffer().clone()
    }
    /// The cell where the screen text `needle` starts: (column, row).
    fn find(buf: &ratatui::buffer::Buffer, needle: &str) -> (u16, u16) {
        let (w, h) = (buf.area.width, buf.area.height);
        for y in 0..h {
            for x in 0..w {
                let rest: String = (x..w).map(|c| buf[(c, y)].symbol().to_string()).collect();
                if rest.starts_with(needle) {
                    return (x, y);
                }
            }
        }
        panic!("{needle:?} not on screen");
    }

    #[test]
    fn the_package_list_has_a_bright_border_while_it_has_the_keys() {
        use ratatui::style::{Color, Modifier};
        let (mut app, _rx) = app_capturing_installs();
        assert_eq!(crate::ui::focus(&app), crate::ui::Focus::List);
        let buf = buffer(&mut app, 100, 30);
        let (x, y) = find(&buf, " packages ");
        assert_eq!(buf[(x, y)].fg, Color::Cyan);
        // The box's corner, left of the title.
        let corner = (0..x).find(|&c| buf[(c, y)].symbol() == "╭").expect("rounded corner");
        assert_eq!(buf[(corner, y)].fg, Color::Cyan);
        assert!(!buf[(corner, y)].modifier.contains(Modifier::DIM));
    }

    #[test]
    fn a_footer_prompt_takes_the_bright_border_from_the_list() {
        use ratatui::style::Color;
        let (mut app, _rx) = app_capturing_installs();
        app.on_key(key('/'));
        assert_eq!(crate::ui::focus(&app), crate::ui::Focus::Footer);
        let buf = buffer(&mut app, 100, 30);
        let (x, y) = find(&buf, " packages ");
        assert_eq!(buf[(x, y)].fg, Color::DarkGray, "the list is inactive");
        assert!((0..x).any(|c| buf[(c, y)].symbol() == "┌"), "a plain corner");
        // The footer is boxed in cyan around the prompt.
        let (_, py) = find(&buf, "/█");
        let top = (0..py).rev().find(|&r| buf[(0, r)].symbol() == "╭").expect("box above the prompt");
        assert_eq!(buf[(0, top)].fg, Color::Cyan);
        assert_eq!(buf[(0, py)].symbol(), "│");
    }

    #[test]
    fn behind_an_open_dialog_everything_is_dimmed() {
        use ratatui::style::{Color, Modifier};
        let (mut app, _rx) = app_to_delete_from();
        app.on_key(key('d'));
        assert_eq!(crate::ui::focus(&app), crate::ui::Focus::Dialog);
        let buf = buffer(&mut app, 120, 40);
        let (x, y) = find(&buf, " packages ");
        assert!(buf[(x, y)].modifier.contains(Modifier::DIM), "the list is dimmed");
        assert_eq!(buf[(x, y)].fg, Color::DarkGray);
        let (dx, dy) = find(&buf, " Delete ");
        assert!(!buf[(dx, dy)].modifier.contains(Modifier::DIM), "the dialog is not");
        assert_eq!(buf[(dx, dy)].fg, Color::Cyan);
        let (tx, ty) = find(&buf, "Uninstall 1 package:");
        assert!(!buf[(tx, ty)].modifier.contains(Modifier::DIM));
    }

    #[test]
    fn the_expanded_log_has_the_bright_border() {
        use ratatui::style::Color;
        let (mut app, _rx) = app_capturing_installs();
        app.push_log("hello");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(crate::ui::focus(&app), crate::ui::Focus::Log);
        let buf = buffer(&mut app, 100, 30);
        let (x, y) = find(&buf, " log ");
        assert_eq!(buf[(x, y)].fg, Color::Cyan);
        let (hx, hy) = find(&buf, "hello");
        assert!((0..hx).any(|c| buf[(c, hy)].symbol() == "│"), "inside the box");
    }

    #[test]
    fn comma_and_dot_page_up_and_down() {
        let (mut app, _rx) = app_capturing_installs();
        for i in 0..60 {
            let name = format!("p{i:02}");
            app.current.insert(name.clone(), (Kind::Prod, "^", Version::new(1, 0, 0)));
            app.on_fetched(name, Version::new(1, 0, 0));
        }
        render(&mut app, 120, 30);
        let page = app.list_page;
        assert!(page > 5 && page < 30, "the list's height: {page}");
        let at = |app: &App| app.table.selected().unwrap();
        app.table.select(Some(0));

        app.on_key(key('.'));
        assert_eq!(at(&app), page - 1, "a page down, keeping a row of context");
        app.on_key(key('.'));
        assert_eq!(at(&app), 2 * (page - 1));
        app.on_key(key(','));
        assert_eq!(at(&app), page - 1);
        // At the ends it stops.
        for _ in 0..20 {
            app.on_key(key('.'));
        }
        assert_eq!(at(&app), app.view.len() - 1);
        for _ in 0..20 {
            app.on_key(key(','));
        }
        assert_eq!(at(&app), 0);
        assert!(app.hints().2.contains(&", . page".to_string()));

        // In the log, too.
        for i in 0..100 {
            app.push_log(format!("line {i}"));
        }
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        render(&mut app, 120, 30);
        app.on_key(key(','));
        assert_eq!(app.log_scroll, app.log_page);
        app.on_key(key('.'));
        assert_eq!(app.log_scroll, 0);
    }

    #[test]
    fn any_other_key_keeps_everything() {
        let (mut app, rx) = app_to_delete_from();
        app.on_key(key('a'));
        app.on_key(key('d'));
        assert_eq!(app.delete_prompt.as_ref().unwrap().packages, ["a", "b"]);
        app.on_key(key('n'));
        assert!(app.delete_prompt.is_none());
        assert!(rx.try_recv().is_err());
        assert_eq!(app.log.last().unwrap(), "Nothing deleted.");
        assert!(row(&app, "a").selected, "the selection stays");
    }

    #[test]
    fn with_nothing_checked_d_deletes_the_item_under_the_cursor() {
        let (mut app, _rx) = app_to_delete_from();
        cursor_to(&mut app, |it| matches!(it, Item::Row { name, .. } if name == "a"));
        assert!(app.hints().0.contains(&"d uninstall".to_string()));
        app.on_key(key('d'));
        let p = app.delete_prompt.take().unwrap();
        assert_eq!(p.packages, ["a"]);
        assert!(p.overrides.is_empty());

        cursor_to(&mut app, |it| matches!(it, Item::Detail { child: Child::Own(0), .. }));
        assert!(app.hints().0.contains(&"d remove override".to_string()));
        app.on_key(key('d'));
        let p = app.delete_prompt.unwrap();
        assert!(p.packages.is_empty());
        assert_eq!(p.overrides[0].name, "a");
    }

    fn items(jobs: &[Job]) -> Vec<(String, String, bool)> {
        jobs.iter()
            .flat_map(|j| &j.items)
            .map(|i| (i.name.clone(), i.spec.clone(), i.exact))
            .collect()
    }

    #[test]
    fn a_blocked_version_is_replaced_by_the_newest_one_the_registry_hands_out() {
        let (mut app, rx) = offline_app();
        app.prober = blocking(&["lodash-4.17.21.tgz"]);
        app.on_key(key('+'));
        type_text(&mut app, "lodash");
        press(&mut app, KeyCode::Enter);
        wait_until(&mut app, |a| a.blocked_prompt.is_some());
        let p = app.blocked_prompt.as_ref().unwrap();
        assert_eq!(p.blocked[0].name, "lodash");
        assert_eq!(p.blocked[0].version, Version::new(4, 17, 21));
        assert_eq!(p.blocked[0].alternative, Some(Version::new(4, 17, 20)));
        assert!(rx.try_recv().is_err(), "nothing installs before the answer");

        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains(" Blocked by the registry "), "{screen}");
        assert!(screen.contains("lodash 4.17.21 can't be downloaded: the registry refuses it (403 Forbidden)."), "{screen}");
        assert!(screen.contains("The newest version it hands out is 4.17.20."), "{screen}");
        assert!(screen.contains("y  install lodash 4.17.20 instead"), "{screen}");
        assert!(screen.contains("a range like ^4.17.20 would pick 4.17.21 again"), "{screen}");

        app.on_key(key('y'));
        let jobs = settle(&mut app, &rx, "");
        assert_eq!(items(&jobs), [("lodash".to_string(), "4.17.20".to_string(), true)], "pinned exactly");
        app.on_install_finished(vec!["lodash".into()], Vec::new(), Ok(()));
        assert_eq!(row(&app, "lodash").current, Version::new(4, 17, 20));
    }

    #[test]
    fn n_installs_what_is_not_blocked() {
        let (mut app, rx) = offline_app();
        app.prober = blocking(&["a-2.0.0.tgz"]);
        app.start_install(
            vec![("a".into(), Version::new(2, 0, 0)), ("b".into(), Version::new(1, 0, 0))],
            Vec::new(),
        );
        wait_until(&mut app, |a| a.blocked_prompt.is_some());
        assert_eq!(app.blocked_prompt.as_ref().unwrap().blocked[0].alternative, Some(Version::new(1, 5, 0)));
        app.on_key(key('n'));
        assert_eq!(specs(&settle(&mut app, &rx, "")), ["b@^1.0.0"]);
    }

    #[test]
    fn a_version_typed_with_e_that_is_blocked_is_offered_an_alternative() {
        let (mut app, rx) = offline_app();
        app.prober = blocking(&["a-2.0.0.tgz"]);
        app.on_key(key('e'));
        type_text(&mut app, "2.0.0");
        press(&mut app, KeyCode::Enter);
        wait_until(&mut app, |a| a.blocked_prompt.is_some());
        app.on_key(key('y'));
        assert_eq!(items(&settle(&mut app, &rx, "")), [("a".to_string(), "1.5.0".to_string(), true)]);
    }

    #[test]
    fn a_failed_install_refused_with_403_for_a_nested_package_offers_an_override() {
        let (mut app, rx) = offline_app();
        app.prober = blocking(&["qs-6.0.4.tgz"]);
        let npm = "`npm install a@^2.0.0` exited with exit status: 1\nnpm error code E403\nnpm error 403 403 Forbidden - GET https://r/qs/-/qs-6.0.4.tgz\nnpm error 403 In most cases, you or one of your dependencies are requesting";
        app.on_install_finished(vec!["a".into()], Vec::new(), Err(npm.into()));
        wait_until(&mut app, |a| a.blocked_prompt.is_some());
        let p = app.blocked_prompt.as_ref().unwrap();
        assert!(p.after_failure && !p.blocked[0].direct);
        let screen = render(&mut app, 120, 40).join("\n");
        assert!(screen.contains("qs 6.0.4 can't be downloaded"), "{screen}");
        assert!(screen.contains("y  override qs to 6.0.3"), "{screen}");
        assert!(!screen.contains("install the others only"), "{screen}");
        app.on_key(key('y'));
        let job = rx.try_recv().expect("override queued");
        assert_eq!(
            job.edits,
            [Change::Add {
                loc: vec!["overrides".into(), "qs".into()],
                new: "6.0.3".into()
            }]
        );
    }

    #[test]
    fn a_failed_install_refused_for_a_dependency_reinstalls_it_at_the_version_found() {
        let (mut app, rx) = offline_app();
        app.prober = blocking(&["a-2.0.0.tgz"]);
        let pnpm = " ERR_PNPM_FETCH_403  GET https://r/a/-/a-2.0.0.tgz: Forbidden - 403";
        app.on_install_finished(vec!["a".into()], Vec::new(), Err(pnpm.into()));
        wait_until(&mut app, |a| a.blocked_prompt.is_some());
        app.on_key(key('y'));
        assert_eq!(items(&settle(&mut app, &rx, "")), [("a".to_string(), "1.5.0".to_string(), true)]);
    }

    #[test]
    fn nothing_is_asked_when_no_version_can_be_downloaded_after_a_failure() {
        let (mut app, _rx) = offline_app();
        app.prober = blocking(&["qs-"]);
        app.on_install_finished(
            vec!["a".into()],
            Vec::new(),
            Err("npm error 403 403 Forbidden - GET https://r/qs/-/qs-6.0.4.tgz".into()),
        );
        wait_until(&mut app, |a| a.log.iter().any(|l| l.contains("No older version could be downloaded")));
        assert!(app.blocked_prompt.is_none());
    }

    #[test]
    fn an_unreachable_registry_does_not_stop_the_install() {
        let (mut app, rx) = offline_app();
        app.prober = Arc::new(|_, _| Err("connection refused".into()));
        app.start_install(vec![("a".into(), Version::new(2, 0, 0))], Vec::new());
        assert_eq!(specs(&settle(&mut app, &rx, "")), ["a@^2.0.0"]);
        assert!(app.blocked_prompt.is_none());
    }

    #[test]
    fn both_scanners_are_named_when_neither_has_scanned_the_version() {
        assert_eq!(
            crate::ui::unscanned_label(&[Source::Snyk, Source::NpmAudit]),
            "↻ snyk (s) and npm audit (n) haven't scanned this version"
        );
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
