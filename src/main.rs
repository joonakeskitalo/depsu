mod app;
mod bunfig;
mod edit;
mod npmrc;
mod overrides;
mod package;
mod pm;
mod registry;
mod snyk;
mod tree;
mod ui;
mod view;

use anyhow::{Result, bail};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "depsu - interactive npm dependency updater

USAGE:
    depsu [OPTIONS]

OPTIONS:
    -C, --dir <PATH>   Project directory (default: current directory)
        --pm <NAME>    Force package manager: npm, yarn, pnpm or bun
    -h, --help         Print help
    -V, --version      Print version

KEYS:
    up/down, j/k   move                 home/end  first / last
    space          select (package, group header or override line)
    a              select all / none
    i, enter       install the selected packages (or the highlighted one)
    /              filter by name (enter keeps it, esc clears it)
    g              group by: none, release type, name prefix
    u              show / hide up-to-date packages
    o              overrides: hidden, compact, full
    x              remove overrides marked as unneeded (press twice to confirm)
    s              scan with Snyk
    f              install the version Snyk suggests
    v              show / hide Snyk findings
    q, esc         quit";

fn main() -> Result<()> {
    let mut dir = PathBuf::from(".");
    let mut forced_pm = None;
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
            "--pm" => {
                let v = args.next().unwrap_or_default();
                match pm::Pm::parse(&v) {
                    Some(p) => forced_pm = Some(p),
                    None => bail!("unknown package manager `{v}` (use npm, yarn, pnpm or bun)"),
                }
            }
            other => bail!("unknown argument `{other}`\n\n{HELP}"),
        }
    }

    let dir = dir.canonicalize()?;
    let manifest = package::read_manifest(&dir.join("package.json"))?;
    let pm = forced_pm.unwrap_or_else(|| pm::Pm::detect(&dir, manifest.package_manager.as_deref()));
    let overrides = overrides::collect(&manifest.raw, pm);
    let mut rc = npmrc::Npmrc::load(&dir);
    // Bun reads bunfig.toml (taking precedence over .npmrc), so honour it for bun projects.
    let warnings = if pm == pm::Pm::Bun {
        bunfig::merge_into(&mut rc, &dir)
    } else {
        Vec::new()
    };

    let mut app = app::App::start(dir, pm, manifest.deps, rc, overrides);
    for w in warnings {
        app.push_log(w);
    }
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut app::App) -> Result<()> {
    while !app.quit {
        app.drain_events();
        terminal.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key);
        }
    }
    Ok(())
}
