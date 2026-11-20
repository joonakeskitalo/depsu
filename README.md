# depsu

An interactive dependency updater for npm projects, written in Rust. It works like
[`npm-check-updates`](https://github.com/raineorshine/npm-check-updates), but the list stays open
after you install something, so you can update packages one after another without restarting.

It also shows how your package manager's **overrides** affect each dependency, and it can check
packages for vulnerabilities with **Snyk** and install the version Snyk suggests.

Illustrative output:

```
 depsu  pnpm · https://registry.npmjs.org/ · 3 outdated · 12 up to date · snyk: 10 vulnerabilities (5 high+)
○ lodash            ✱    dep 4.17.15       → 4.18.1   snyk fix: 4.18.1
     ├─ ✱ high     SNYK-JS-LODASH-1040724  Code Injection  · lodash@4.17.15  · CVE-2021-23337  · fixed in lodash 4.17.21
     └─ … +7 more vulnerabilities (press o for all)
○ react-dom         ⚑    dep ^18.2.0       → ^19.0.0
· zod                    dep ^3.23.8       ✓ up to date
```

## Features

- **Stays open.** Press `i` to install, keep browsing, press `i` again. Installs run in the
  background, one at a time.
- **Uses your package manager.** npm, yarn, pnpm or bun, detected from the project.
- **Uses your registry.** Reads `.npmrc`, `.yarnrc.yml` for Yarn 2+ and `bunfig.toml` for bun, including private
  registries and auth tokens.
- **Selection, grouping, filtering.** Group by release type (patch, minor, major) or by name
  prefix, and filter by name.
- **Overrides.** Shows overridden packages, checks that an update is compatible with the override,
  finds overrides that are probably no longer needed, and can update or remove them.
- **Snyk.** Lists vulnerabilities per dependency and installs Snyk's suggested version.

## Install

Requires a Rust toolchain.

```sh
make release          # builds target/release/depsu
make install          # copies it to ~/.local/bin (override with PREFIX=/usr/local)
```

or `cargo install --path .`.

## Usage

Run it in a project directory:

```sh
depsu
depsu --dir ../other-project
depsu --pm pnpm       # skip detection
```

| Option | |
|---|---|
| `-C`, `--dir <PATH>` | Project directory (default: current directory) |
| `--pm <NAME>` | Force the package manager: `npm`, `yarn`, `pnpm` or `bun` |
| `-h`, `--help` / `-V`, `--version` | |

### Keys

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k`, `Home` `End` | Move |
| `space` | Select a package, a whole group (on its header) or an override line |
| `a` | Select all / none of the shown packages |
| `i` / `Enter` | Install the selected packages, or the highlighted one |
| `/` | Filter by name. `Enter` keeps the filter, `Esc` clears it |
| `g` | Group by: none → release type → name prefix |
| `u` | Show / hide up-to-date packages |
| `o` | Overrides: hidden → compact → full |
| `x` | Remove overrides marked `✂` (press twice to confirm) |
| `s` | Scan with Snyk |
| `f` | Install the version Snyk suggests |
| `v` | Show / hide Snyk findings |
| `q` / `Esc` | Quit (press twice while an install is running) |

`a`, `i` and `f` act only on the packages currently shown, so a filter narrows what they touch.

## How it works

### Package manager

The `packageManager` field in `package.json` wins. Otherwise `depsu` looks for `bun.lock` /
`bun.lockb`, `pnpm-lock.yaml`, `yarn.lock` or `package-lock.json` in the project directory and its
parents (so monorepos work), and falls back to npm. Installs run `npm install <pkg>@<spec>` or
`<yarn|pnpm|bun> add <pkg>@<spec>`, with `-D` / `-O` for dev and optional dependencies. The range
prefix (`^`, `~`, none) of the existing spec is kept.

### Registry and authentication

Per-package, `depsu` picks the registry like npm does and sends the matching token.

- `.npmrc` in the project, then `~/.npmrc` (the project wins): `registry`, `@scope:registry`,
  `//host/path/:_authToken`, `_auth`, `username` + `_password`, and `${VAR}` / `${VAR:-default}`.
  `NPM_CONFIG_REGISTRY` overrides the default registry.
- For bun projects, `bunfig.toml` (project, then `~/.bunfig.toml`) takes precedence:
  `[install] registry`, `[install.registry]` with `url` / `token` / `username` / `password`, and
  `[install.scopes]`, with `$VAR` / `${VAR}`.
- For Yarn 2+ projects (a `.yarnrc.yml` in the project directory or a parent), `.yarnrc.yml` is
  used **instead of** `.npmrc`, which Yarn Modern ignores as well. Files are merged from `~/.yarnrc.yml`
  down to the nearest one, which wins. Supported: `npmRegistryServer`, `npmAuthToken`,
  `npmAuthIdent`, `npmScopes.<scope>.{npmRegistryServer,npmAuthToken,npmAuthIdent}` and
  `npmRegistries.<url>.{npmAuthToken,npmAuthIdent}`, plus `YARN_NPM_REGISTRY_SERVER`,
  `YARN_NPM_AUTH_TOKEN` and `YARN_NPM_AUTH_IDENT`. Credentials are picked like Yarn does: the
  package's scope, then the registry's own `npmRegistries` entry, then the top-level ones. The
  top-level credentials are never sent to `registry.npmjs.org` or `registry.yarnpkg.com`. Yarn's
  `${VAR}`, `${VAR:-fallback}` and `${VAR-fallback}` expansions work. A variable that isn't set
  drops that setting and shows a warning in the log. `npmAlwaysAuth` is not needed: credentials
  are sent whenever they are configured.

Versions are fetched the way `npm-check-updates` does it: the package document is requested with
the abbreviated (corgi) `Accept` header and reading stops as soon as `dist-tags` has been seen,
with a retry for the full document on a 404. Requests run 16 at a time.

### What counts as outdated

`depsu` compares the lowest version of each dependency's range with the registry's `latest`
dist-tag. Prereleases are ignored. Specs that are not a plain version or range (`git`, `file:`,
`workspace:`, `npm:` aliases, tags, `||` ranges) are skipped. Up-to-date packages are listed too
(`u` hides them).

### Overrides

Overrides come from `overrides` (npm, bun), `resolutions` (yarn, bun) or `pnpm.overrides` (pnpm).
Only the field your package manager honours is read. By default they are hidden; press `o` to list
them under each package.

**Markers** next to a package name:

| Marker | Meaning |
|---|---|
| `⚑` | The package itself is overridden, and the update is compatible |
| `⚠` | The update conflicts with its override |
| `?` | The override can't be interpreted (URL, alias, odd range) |
| `↳` | An override applies somewhere in the package's installed dependency tree (yellow if it forces a version outside what the parent declares) |
| `✱` | Snyk found vulnerabilities (coloured by worst severity) |

**Compatibility.** npm requires an override on a direct dependency to have the exact same spec as
the dependency (or be `$name`), otherwise it fails with `EOVERRIDE`. yarn, pnpm and bun let the
override win silently, so the update has no effect when the new version is outside it. `depsu`
checks the right rule for your package manager and asks for a second keypress before installing a
conflicting update.

**Dependency tree.** `depsu` walks the installed tree in `node_modules` (including pnpm's symlinked
layout) and lists every override that applies to a dependency of the package, at any depth, with
the chain that leads to it.

**Updating an override.** Override lines whose value is a plain version or range show
`⇢ new value`. Select them with `space` and press `i`. `depsu` edits `package.json` in place
(keeping indentation, key order and the trailing newline) and runs the package manager's install.
On npm, overrides on direct dependencies can't be updated separately, because of the rule above.

**Unneeded overrides.** An override is flagged `✂ may be removed` when the installed tree shows it
no longer changes anything: nothing depends on the package, every dependent already asks for the
same spec, or every dependent already requires at least the override's version. They are also
listed in an "Unneeded overrides" section. Press `x` to remove the selected one (or the one under
the cursor), and `x` again to confirm. The entry is deleted from `package.json` (empty containers
go too) and the package manager's install runs.

This is a heuristic, so verify before removing. It reads `node_modules`, so nothing is flagged
without it, and a pin that guards against a newer release looks the same as one that only sets a
floor.

### Snyk

Requires the [Snyk CLI](https://docs.snyk.io/snyk-cli) (`npm i -g snyk`) and `snyk auth` (or
`SNYK_TOKEN`).

`s` runs `snyk test --json --dev` in the project. This **sends your dependency list to Snyk and
counts against your organisation's test quota**, so it never runs automatically.

- Each vulnerability is shown under the direct dependency that brings it in, with severity, ID,
  CVE, the vulnerable package and the path to it, and what to do about it from the direct
  dependency's point of view: the version of the direct dependency that fixes the finding
  (`fixed by upgrading express to 4.22.0 (brings qs 6.14.3)`), or, when upgrading it doesn't help,
  the fixed releases of the nested package that are newer than the installed one.
- `snyk fix: <version>` on a row is Snyk's suggested version for that dependency. It fixes
  everything fixable and can be lower than the latest release. Press `f` to install it.
- After an install, the findings of updated packages are dropped and the top bar says the results
  are outdated. Press `s` to rescan.

## Development

```sh
make check      # rustfmt check, clippy (warnings are errors) and the tests
make test
make run ARGS="--dir ../project"
make help
```

Source layout:

| File | |
|---|---|
| `main.rs` | Argument parsing, startup |
| `app.rs` | State, key handling, background workers (fetching, installing, analysis) |
| `ui.rs`, `view.rs` | Rendering, and the list model (grouping, filtering, nested lines) |
| `registry.rs`, `npmrc.rs`, `bunfig.rs`, `yarnrc.rs` | Registry access and configuration |
| `pm.rs`, `package.rs`, `edit.rs` | Package manager detection and commands, `package.json` reading and editing |
| `overrides.rs`, `tree.rs` | Override parsing, compatibility, unneeded detection, dependency tree walk |
| `snyk.rs` | Snyk CLI integration. `tests/fixtures/` holds real and hand-written Snyk output |

## Limitations

- Only the `latest` dist-tag is considered. There is no `--target minor` / `patch`.
- Yarn Classic's `.yarnrc` (`registry "…"`) and overrides in `pnpm-workspace.yaml` are not read.
  Yarn Classic still gets its registry from `.npmrc`.
- Override analysis reads `node_modules`, so it finds nothing with Yarn Plug'n'Play or before the
  first install, and it does not predict the dependency tree of a new version.
- Not tested on Windows.
