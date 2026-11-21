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
     └─ ✱ medium   SNYK-JS-LODASH-1018905  ReDoS  · lodash@4.17.15  · CVE-2020-28500  · fixed in lodash 4.17.21
○ react-dom         ⚑    dep ^18.2.0       → ^19.0.0
· zod                    dep ^3.23.8       ✓ up to date
```

## Features

- **Stays open.** Press `i` to install, keep browsing, press `i` again. Installs run in the
  background, one at a time.
- **Uses your package manager.** npm, yarn, pnpm or bun, detected from the project.
- **Uses your registry.** Reads `.npmrc`, `.yarnrc.yml` for Yarn 2+ and `bunfig.toml` for bun, including private
  registries and auth tokens.
- **Version range.** The range prefix of each version is highlighted: `^` yellow, `~` cyan, `>=` red.
  A version without a prefix is pinned exactly.
- **Selection, grouping, filtering.** Group by release type (patch, minor, major), by name
  prefix or by dependency type (dependencies, dev dependencies, optional dependencies, overrides), and
  filter by name.
- **Overrides.** Shows overridden packages, checks that an update is compatible with the override,
  finds overrides that are probably no longer needed, and can update or remove them.
- **Vulnerabilities.** Lists vulnerabilities per dependency from Snyk, `npm audit` or `bun audit`,
  and installs the version they suggest.

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
depsu --cache .depsu-cache.json   # remember versions and scans between runs
```

| Option | |
|---|---|
| `-C`, `--dir <PATH>` | Project directory (default: current directory) |
| `--pm <NAME>` | Force the package manager: `npm`, `yarn`, `pnpm` or `bun` |
| `--cache <FILE>` | JSON file that stores the latest versions, and the Snyk / audit findings per project and package version. One file can be shared by several projects: latest versions are shared, scan results are kept apart per project directory. Read at start, updated as results arrive. A file that can't be parsed is left untouched and not used |
| `-h`, `--help` / `-V`, `--version` | |

### Keys

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k`, `Home` `End` | Move |
| `space` | Select a package, a whole group (on its header) or an override line |
| `a` | Select all / none of the shown packages |
| `i` / `Enter` | Install the selected packages, or the highlighted one. On a vulnerability finding, install the version that fixes it |
| `/` | Filter by name. `Enter` keeps the filter, `Esc` clears it |
| `g` | Group by: none → release type → name prefix → dependency type |
| `o` | Show / hide the override lines under each package |
| `x` | Remove the selected or highlighted overrides, or the overrides of the highlighted package, flagged `✂` or not. Warns when installed packages use the overridden package (press twice to confirm) |
| `P` | Choose how the selected or highlighted packages are pinned: exact (`e`), caret `^` (`c`), tilde `~` (`t`) or at least `>=` (`m`). Letters are used because `^` and `~` are dead keys on Nordic keyboards. The version stays, `package.json` is edited and the install runs |
| `p` | Pin a vulnerable transitive dependency to the fixed version a scan suggests, as an override (press twice to confirm) |
| `s` | Scan with Snyk |
| `n` | Run `npm audit` / `bun audit` (whichever the project uses) |
| `v` | Show / hide vulnerability findings |
| `R` | Fetch the latest versions again, ignoring the cache |
| `?` | Show / hide the details panel for the highlighted package: installed packages that use it and its override summary |
| `q` / `Esc` | Quit (press twice while an install is running) |

`a` and `i` act only on the packages currently shown, so a filter narrows what they touch.

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
| `✱` | A scan found vulnerabilities (coloured by worst severity) |

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

**Overridden packages in the list.** A package that is overridden but isn't a dependency of the
project gets a row of its own (kind `ovr`) under an "Overridden packages" heading at the bottom of
the list, after the regular packages whatever the grouping. Its latest version is looked up like for any other
package. The row shows the lowest version its overrides name and is marked outdated when any of
them can move to a newer one. Checking the row and pressing `i` rewrites those overrides in
`package.json` and runs the install, the same as for the override lines under a package. Overrides
whose value isn't a plain version or range (`$foo`, URLs, aliases) get no row.

**Pinning a fix.** When Snyk or the audit reports a vulnerable package below a direct dependency
and lists a fixed version, `p` adds an override for it (`overrides`, `resolutions` or
`pnpm.overrides`, depending on the package manager) set to `^<fixed version>`. It uses the lowest fix
in the installed major release, or the lowest newer one. It works on the checked packages or the one
under the cursor, asks for a second press, and warns that forcing a version can break dependents.
An existing global override that is too low is raised instead. Run Snyk and the audit again
afterwards (the old results are marked outdated).

**Unneeded overrides.** An override is flagged `✂ may be removed` when the installed tree shows it
no longer changes anything: nothing depends on the package, every dependent already asks for the
same spec, or every dependent already requires at least the override's version. They are also
listed in an "Unneeded overrides" section. Press `x` to remove the selected one (or the one under
the cursor), and `x` again to confirm. The entry is deleted from `package.json` (empty containers
go too) and the package manager's install runs. Overrides not flagged `✂` can be removed too, with an
extra warning, because that can change what gets installed. After any removal, depsu reminds you to
run Snyk and the audit again.

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
- Findings are kept per project and per resolved package version, in memory and in the
  `--cache` file. The resolved version is the one `package-lock.json` pins, or else the one in
  `node_modules`, since that is what Snyk and `npm audit` look at; the range in `package.json`
  is never used. A Snyk finding is filed under the version Snyk names in it, and depsu warns
  when that differs from `node_modules`. A package whose version can't be determined (not
  installed, no npm lockfile) is not recorded. After an install
  or revert, a package shows the findings recorded for its new version if that version was
  scanned before. `↻ not scanned at this version` means no scanner has looked at the installed
  version yet. Press `s` or `n` to scan it. Findings are matched by the version of your direct
  dependency, so a change deeper in the tree (for example from editing overrides) still needs a
  new scan.
- `snyk fix: <version>` on a row is Snyk's suggested version for that dependency. It fixes
  everything fixable and can be lower than the latest release. Move onto a finding and press `i` to
  install the version that fixes it.
- After an install, the findings of updated packages are dropped and the top bar says the results
  are outdated. Press `s` to rescan.

### npm audit and bun audit

`n` runs the project's own audit command: `npm audit --json` for npm projects, `bun audit --json`
for bun projects (a Bun new enough to have `bun audit`). Nothing leaves your machine except the
package list the command itself sends to your registry, and no account is needed. Yarn and pnpm
projects can't be audited this way (use Snyk, which works with any package manager).

The findings look like Snyk's and are tagged `[npm audit]` or `[bun audit]`, so both can be shown
at once. A rescan replaces only the findings of that tool.

Neither tool says which direct dependency a finding belongs to or which installed copy is
affected, so `depsu` matches the advisories against the installed tree in `node_modules`: every
copy whose version is in the advisory's affected range is listed under each direct dependency
that reaches it, with the path to it and its installed version. This needs installed dependencies;
without `node_modules` the scan stops with a message.

Suggested fixes:

- **npm:** uses `fixAvailable` from the report. If the direct dependency's own entry says
  upgrading it fixes it, that is what each finding under it shows (`fixed by upgrading express to
  4.22.3`, with `(breaking)` for a semver-major upgrade). `i` on the finding installs it, keeping your range
  prefix. When npm can fix something only by updating the lockfile, the finding says so
  (`run npm audit fix`), since no `package.json` version is involved.
- **bun:** uses the plan from `bun audit fix --dry-run --json`, which changes nothing. A direct
  dependency that Bun would upgrade in `package.json` gets that version. Findings Bun can't fix
  say which dependent blocks them (`qs 6.16.1 has the fix, but express@4.17.1 requires 6.7.0`),
  per installed copy.

`npm audit` doesn't report CVE numbers or fixed-version lists, so those parts of a Snyk finding
are replaced by the advisory's affected range.

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
| `snyk.rs`, `audit.rs`, `vuln.rs` | Snyk CLI integration, `npm audit` / `bun audit` integration, and the finding type they share. `tests/fixtures/` holds real and hand-written output |

## Limitations

- Only the `latest` dist-tag is considered. There is no `--target minor` / `patch`.
- Yarn Classic's `.yarnrc` (`registry "…"`) and overrides in `pnpm-workspace.yaml` are not read.
  Yarn Classic still gets its registry from `.npmrc`.
- Override analysis reads `node_modules`, so it finds nothing with Yarn Plug'n'Play or before the
  first install, and it does not predict the dependency tree of a new version.
- `npm audit` / `bun audit` findings are traced through `node_modules`, so they need installed
  dependencies. Bun's plan comes from `bun audit fix --dry-run`, which I could only check with
  Bun 1.4.5. Older Bun versions have no `bun audit`.
- Not tested on Windows.
