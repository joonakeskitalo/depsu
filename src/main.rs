mod config;
mod deps;
mod proxy;
mod registry;
mod security;
mod tui;

use anyhow::{Result, bail};
use ratatui::crossterm::ExecutableCommand;
use ratatui::crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "depsu - interactive npm dependency updater

USAGE:
    depsu [OPTIONS]

OPTIONS:
    -C, --dir <PATH>   Project directory (default: current directory)
        --pm <NAME>    Force package manager: npm, yarn, pnpm or bun
        --pm-cache <DIR>
                       Keep the package manager's download cache in DIR (npm --cache,
                       pnpm --store-dir, yarn cache folder, bun cache dir)
        --prefer-offline
                       Use cached packages without checking the registry for newer
                       metadata (npm, pnpm and Yarn 1; ignored by Yarn 2+ and bun)
        --proxy-cache <DIR>
                       Run npm through a caching registry proxy that depsu starts, and keep
                       the downloaded packages and metadata in DIR (npm only)
        --reset-cache  Forget what --cache remembers about this project (its scan results and
                       the latest versions) before starting. Other projects in the file stay.
                       Needs --cache. The package manager and proxy caches are not touched.
        --clear-npm-cache
                       Empty npm's cache before starting: the one given with --pm-cache,
                       or else npm's own, and the one given with --proxy-cache. npm only.
        --cooldown <DAYS>
                       Only offer a version as the latest once it has been published for
                       DAYS days (default 3, 0 turns it off). [ and ] change it while
                       depsu runs. Needs the full package document, which is larger.
        --cache <FILE> JSON file that remembers latest versions and scans between runs
    -h, --help         Print help
    -V, --version      Print version

KEYS:
    up/down, j/k   move                 home/end  first / last
    , .            page up / page down (also PgUp / PgDn)
    space          select (package, group header or override line)
    a              select all / none
    i, enter       install the selected packages (or the highlighted one, or the
                   fix of the highlighted vulnerability)
    /              filter by name, override or finding (enter keeps it, esc clears it)
    g              group by: none, release type, name prefix, dependency type
    o              show / hide the override lines under each package
    d              delete: uninstall the checked packages and remove the checked
                   overrides, or the package / override under the cursor (asks first)
                   on an ignored finding or a .snyk rule: remove the rule (press twice)
    s              scan with Snyk
    n              run npm audit / bun audit (by the project's package manager)
    e              edit the version of the highlighted package (and its pin type)
    f              fix the unmet peers of the highlighted package
    I              add the registry's integrity checksum to package-lock.json for the
                   checked packages (or the highlighted one) the lockfile has none for
    c              commit package.json, lockfile and .snyk, titled as a conventional
                   commit of the changes (e.g. 'chore: upgrade eslint 8.57.0 to 9.0.0')
    +              add a package as a dependency, dev dependency or override
    R              fetch the latest versions again (ignoring the cache)
    T              installed tab: every package in node_modules with its size, install
                   date and why it is there (s sort, / filter, r reread)
    [ ]            shorten / lengthen the release cooldown by a day
    ?              show / hide the details panel
    shift+up/down  scroll the details panel
    P              ask how to pin the selected packages (e exact, c ^, t ~, m >=)
    p              override a vulnerable dependency with the fixed version a scan
                   suggests (press twice to confirm)
    v              show / hide vulnerability findings
    q, esc         quit

MOUSE:
    click          move the cursor to an item; click its mark to (un)check it
    click          a key hint in the footer or an item in the header runs it;
                   the log opens when clicked, dialog choices pick themselves
    wheel          move the cursor, scroll the details panel or the expanded log
    drag           select text in the details panel or the log; y copies it, esc drops it
                   (hold shift to select text with the mouse)";

fn main() -> Result<()> {
    let mut dir = PathBuf::from(".");
    let mut forced_pm = None;
    let mut cache_path: Option<PathBuf> = None;
    let mut proxy_dir: Option<PathBuf> = None;
    let mut reset_cache = false;
    let mut clear_npm_cache = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                return {
                    println!("{HELP}");
                    Ok(())
                };
            }
            "-V" | "--version" => {
                return {
                    println!("depsu {}", env!("CARGO_PKG_VERSION"));
                    Ok(())
                };
            }
            "-C" | "--dir" => match args.next() {
                Some(p) => dir = p.into(),
                None => bail!("{arg} requires a value"),
            },
            "--cache" => match args.next() {
                Some(p) => cache_path = Some(p.into()),
                None => bail!("{arg} requires a value"),
            },
            "--pm-cache" => match args.next() {
                Some(d) => {
                    // Package managers run in the project directory, so the path must not be relative.
                    let path = std::path::absolute(&d)?;
                    std::fs::create_dir_all(&path)?;
                    config::pm::set_cache_dir(path.to_string_lossy().into_owned());
                }
                None => bail!("{arg} requires a value"),
            },
            "--proxy-cache" => match args.next() {
                Some(d) => proxy_dir = Some(std::path::absolute(&d)?),
                None => bail!("{arg} requires a value"),
            },
            "--cooldown" => {
                let v = args.next().unwrap_or_default();
                match v.parse::<u32>() {
                    Ok(d) if d <= 365 => registry::registry::set_cooldown_days(d),
                    _ => bail!("--cooldown needs a number of days from 0 to 365, not `{v}`"),
                }
            }
            "--reset-cache" => reset_cache = true,
            "--clear-npm-cache" => clear_npm_cache = true,
            "--prefer-offline" => config::pm::set_prefer_offline(),
            "--pm" => {
                let v = args.next().unwrap_or_default();
                match config::pm::Pm::parse(&v) {
                    Some(p) => forced_pm = Some(p),
                    None => bail!("unknown package manager `{v}` (use npm, yarn, pnpm or bun)"),
                }
            }
            other => bail!("unknown argument `{other}`\n\n{HELP}"),
        }
    }

    let dir = dir.canonicalize()?;
    if reset_cache {
        let Some(path) = &cache_path else {
            bail!("--reset-cache needs --cache <FILE>");
        };
        registry::cache::Cache::reset(path, &dir.display().to_string())?;
    }
    let manifest = deps::package::read_manifest(&dir.join("package.json"))?;
    let pm = forced_pm.unwrap_or_else(|| config::pm::Pm::detect(&dir, manifest.package_manager.as_deref()));
    let overrides = deps::overrides::collect(&manifest.raw, pm);
    // Each package manager has its own idea of where the registry settings live.
    let (rc, warnings) = if pm == config::pm::Pm::Yarn && config::yarnrc::is_yarn_modern(&dir) {
        // Yarn 2+ reads `.yarnrc.yml` only and ignores `.npmrc` completely.
        config::yarnrc::load(&dir)
    } else {
        let mut rc = config::npmrc::Npmrc::load(&dir);
        // Bun reads bunfig.toml (taking precedence over .npmrc), so honour it for bun projects.
        let warnings = if pm == config::pm::Pm::Bun {
            config::bunfig::merge_into(&mut rc, &dir)
        } else {
            Vec::new()
        };
        (rc, warnings)
    };
    let mut notes = Vec::new();
    if clear_npm_cache {
        if pm != config::pm::Pm::Npm {
            bail!("--clear-npm-cache works with npm projects, this one uses {}", pm.name());
        }
        notes.push(config::pm::clean_npm_cache(&dir, config::pm::cache_dir()).map_err(anyhow::Error::msg)?);
        if let Some(d) = &proxy_dir {
            let n = proxy::clear(d, &dir).map_err(anyhow::Error::msg)?;
            notes.push(format!("Cleared the proxy cache in {} ({n} entries)", d.display()));
        }
    }
    if let Some(proxy_dir) = proxy_dir {
        if pm != config::pm::Pm::Npm {
            notes.push(format!("--proxy-cache only works with npm, not {}: ignored.", pm.name()));
        } else {
            let registry = rc.registry_for("x");
            let auth = rc.auth_header(&registry);
            match proxy::start(&proxy_dir, &registry, auth) {
                Ok(a) => notes.push(format!(
                    "Caching proxy {} for {} ({})",
                    a.registry_url,
                    registry,
                    proxy_dir.display()
                )),
                Err(e) => bail!("{e}"),
            }
        }
    }
    let mut app = tui::app::App::start(dir, pm, manifest.deps, rc, overrides, cache_path);
    for w in warnings.into_iter().chain(notes) {
        app.push_log(w);
    }
    let mut terminal = ratatui::init();
    // The terminal reports clicks and the wheel to depsu while this is on. Holding shift (alt
    // in some terminals) selects text as usual.
    let _ = std::io::stdout().execute(EnableMouseCapture);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::io::stdout().execute(DisableMouseCapture);
        hook(info);
    }));
    let result = run(&mut terminal, &mut app);
    // Don't leave a running install behind when quitting.
    tui::app::kill_running_pm();
    let _ = std::io::stdout().execute(DisableMouseCapture);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut tui::app::App) -> Result<()> {
    while !app.quit {
        app.drain_events();
        terminal.draw(|f| tui::ui::draw(f, app))?;
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key),
                Event::Mouse(m) => app.on_mouse(m),
                _ => {}
            }
        }
    }
    Ok(())
}
