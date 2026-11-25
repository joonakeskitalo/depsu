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
  finds overrides that are probably no longer needed, and can update or remove them. An override that forces
  a version outside the range the packages it reaches declare is marked `⚠` and lists them with the ranges
  they accept.
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
| `--pm-cache <DIR>` | Keep the package manager's download cache in `DIR` (created if missing; a relative path is taken from where you start depsu). Passed as `--cache` to npm, `--store-dir` to pnpm, `--cache-folder` to Yarn 1, and as `YARN_CACHE_FOLDER` / `BUN_INSTALL_CACHE_DIR` to Yarn 2+ / bun |
| `--prefer-offline` | Pass `--prefer-offline` to npm, pnpm and Yarn 1, so cached packages are used without asking the registry whether they are stale. Combine with `--pm-cache`. Yarn 2+ and bun have no such flag and ignore it |
| `--proxy-cache <DIR>` | npm only. depsu starts a caching registry proxy on `127.0.0.1` and runs npm through it (`--registry`, `--replace-registry-host`), keeping tarballs and package metadata in `DIR`. The proxy adds the credentials from `.npmrc`, follows the registry's redirects (such as Cloudsmith's 307 to a CDN) and serves stored metadata when the registry is unreachable. Tarballs are stored once and never asked for again; metadata is checked with `If-None-Match` each time. Any address of the proxy that npm writes to `package-lock.json` is changed back to the real registry after each install. Scoped registries (`@scope:registry`) are not routed through it. `DIR` holds the packages you install, so treat it like the registry's credentials |
| `--cooldown <DAYS>` | Only offer a version as the latest once it has been published for `DAYS` days (default `3`, `0` turns it off). The latest version shown is then the newest stable release old enough, not the registry's `latest` tag; a package whose releases are all younger stays where it is. Publish times come from the full package document, which is larger than the one depsu otherwise reads, so lookups are slower and bigger than with `0`. Times are kept in the `--cache` file, so changing the cooldown there needs no new request. Adding a package with `+` is not affected |
| `--cache <FILE>` | JSON file that stores the latest versions, and the Snyk / audit findings per project and package version. One file can be shared by several projects: latest versions are shared, scan results are kept apart per project directory. Read at start, updated as results arrive. A file that can't be parsed is left untouched and not used |
| `--reset-cache` | Before starting, forget what `--cache` remembers about this project: its Snyk / audit results and the latest versions. Results of other projects in the same file stay. Needs `--cache`. The package manager cache (`--pm-cache`) and the proxy cache (`--proxy-cache`) are not touched: delete those directories to empty them |
| `--clear-npm-cache` | Before starting, empty npm's cache: the one in `--pm-cache` if given, otherwise npm's own (`npm cache clean --force`), and the proxy cache in `--proxy-cache` if given. The proxy directory is refused if it is the project, above it, your home directory, or holds a `package.json` or `.git`. npm projects only |
| `-h`, `--help` / `-V`, `--version` | |

### Keys

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k`, `Home` `End` | Move |
| `,` `.` (or `PgUp` `PgDn`) | Page up / page down, in the list and in the log |
| `space` | Select a package (up to date or not), a whole group (on its header) or an override line |
| `a` | Select all / none of the shown packages |
| `i` / `Enter` | Install the selected packages, or the highlighted one. On a vulnerability finding, install the version that fixes it. If the update needs other installed packages to change (peer dependencies), depsu lists them and asks: `y` update them too, `n` install only what you picked, any other key cancels. Packages that would need different install flags (dependency vs dev dependency, exact vs range) are written into `package.json` together and installed with one `install`, so the package manager resolves them at once; if that fails, `package.json` is put back |
| `/` | Filter by name, by an override (name, value, where it is set) or by a finding (ID, title, package, CVE, severity, scanner such as `snyk`). `Enter` keeps the filter, `Esc` clears it |
| `g` | Group by: none → release type → name prefix → dependency type |
| `o` | Show / hide the override lines under each package |
| `d` | Delete the checked packages and overrides in one go, or the package or override under the cursor. On an ignored finding (or a finding a `.snyk` rule covers), or on a rule in the `.snyk ignores` section, `d` removes that rule from `.snyk` after a second press. A dialog lists what will be uninstalled and removed from `package.json`, warns about installed packages that use them, and asks `y` / `enter` to go ahead. Deleted packages can be restored with `r` |
| `e` | Edit the version of the highlighted package in a dialog, pre-filled with what it has now, e.g. `^18.3.1`. Change the version (older or newer) and the pin type in front of it (`^`, `~`, `>=`, or none for exact); while you type, the dialog says whether that version is published, naming the nearest ones if not. `Enter` installs it, with the peer and blocked-version checks of `i` |
| `c` | Commit `package.json` and the lockfile with git. The title is a conventional commit of what changed since the last commit, e.g. `chore: upgrade eslint 8.57.0 to 9.0.0`, made less specific to stay within 72 characters, and the body lists every change. Integrity checksums the lockfile got since the last commit, for packages at the same version (e.g. from `I`), are a change of their own: `chore: add the checksum of lodash 4.17.21`. Vulnerabilities fixed in this session by the committed changes, through an install that reaches the fix version or an override from `p`, are listed after the changes under `Fixes:` with their ID, title and severity (`- SNYK-JS-LODASH-1040724: Prototype Pollution (high)`). The body leaves out what the title already says: the list of changes when the title names every change with its versions, and a fixed vulnerability when the title mentions its ID. If nothing is left, the commit gets no body. Edit the title and the body in the dialog: `Tab` switches between them, the arrow keys, `Home` and `End` move the cursor. `Enter` commits from the title and starts a new line in the body; `Ctrl+S` commits from either. Until you edit the body, it follows the title; once edited it is committed as written, and an emptied body means none. Only those two files are committed: other staged or modified files are left as they are. Git hooks run; if one fails, its message is shown and nothing is committed |
| `f` | Fix the unmet peers of the highlighted package (marked `⚠ unmet peer`): depsu looks up which versions would fit and offers them in a dialog — update the peers to versions in the range the package asks for, or change the package (up or down) to a version that accepts what is installed. The chosen fix installs with the usual peer check |
| `+` | Add a package in a dialog: type `name` (latest) or `name@1.2.3`, and pick with `Tab` / `↑` `↓` whether it is added as a dependency, a dev dependency or an override (`overrides`, `resolutions` or `pnpm.overrides`, by package manager). Saved as `^version`. The registry is checked before anything changes, and problems are shown in the dialog. Peer dependencies of new dependencies are checked as for `i` |
| `P` | Choose how the selected or highlighted packages are pinned: exact (`e`), caret `^` (`c`), tilde `~` (`t`) or at least `>=` (`m`). Letters are used because `^` and `~` are dead keys on Nordic keyboards. The version stays, `package.json` is edited and the install runs |
| `p` | Pin a vulnerable transitive dependency to the fixed version a scan suggests, as an override (press twice to confirm) |
| `s` | Scan with Snyk |
| `x` | Ignore a Snyk finding in the project's `.snyk` file, or edit an existing ignore. On a finding (ignored ones too), or on a rule in the `.snyk ignores` section of the list, a dialog asks for a reason (required), an expiry date (`YYYY-MM-DD`, pre-filled with 30 days for a new ignore, empty for none) and the path (the finding's own path like `a > b`, or `*` for every path). `Tab` switches fields; `Ctrl+D` removes the rule being edited. Findings a non-expired rule covers are tagged `⊘ ignored in .snyk`. The `.snyk ignores` section lists every rule with its ID, path, expiry (expired ones dimmed) and reason, and follows the `/` filter. Findings Snyk leaves out because of a rule are listed, dimmed and not selectable, under their package as `⊘ … · ignored in .snyk until <date>: <reason>` after a scan of this session (they are not kept in the cache file). Each rule says whether it is still needed: `✔ still needed` when a Snyk scan of this session found a finding it covers (Snyk lists what the policy left out under `filtered.ignore`), `✂ no longer needed` when the scan found nothing for it, and `? run Snyk (s) to check` before a scan and after `.snyk` changes. `d` on a rule removes it after a second press. Other keys in `.snyk` are kept, but comments are lost when the file is rewritten (depsu says so in the log). Snyk applies the file on the next scan (`s`) |
| `n` | Run `npm audit` / `bun audit` (whichever the project uses) |
| `v` | Show / hide vulnerability findings |
| `R` | Fetch the latest versions again, ignoring the cache |
| `T` | Open the installed tab: every package in `node_modules` (transitive ones too) with its version, size on disk, install date and why it is installed. `/` filters (by name or reason), `s` cycles the sort (name, size, date), `r` reads again, `Esc` or `T` goes back. *Installed* is when the package folder was created on this machine. *Why* is `direct dependency` for the project's own and otherwise the installed packages that require it (dependencies, optional and peer dependencies, read from their `package.json` as `npm ls` does), with the direct dependencies they come through. Only packages found in the top-level `node_modules` are listed, so with pnpm's layout the transitive packages kept in `.pnpm` are missing |
| `[` / `]` | Shorten / lengthen the release cooldown by a day. The latest versions are recomputed at once; if they were fetched with the cooldown off, they are fetched again. The header shows the current value |
| `?` | Show / hide the details panel for the highlighted package: whether it is deprecated, its install scripts, installed version, size and file count, engines (checked against the node, npm and package manager versions installed here; a mismatch is also flagged in the list with `⚠ needs node >=20 (has 18.19.0)`) and platform (`os`, `cpu`, `libc`), the lockfile's integrity checksum (while the panel is open, a package the lockfile lists as a download without one is also flagged in the list with `⚠ no integrity checksum`), its dependencies and how they changed since the last commit, installed packages that use it, its peer dependencies with the versions installed, and its override summary. A package with an installed peer outside the range it declares is flagged in the list with `⚠ unmet peer: react ^18.0.0 (has 19.0.0)` |
| `Shift+↑` / `Shift+↓` | Scroll the details panel. It keeps the same height for every package; its title shows which lines are in view when there are more |
| `U` | Reinstall everything: deletes `node_modules` in the project directory and runs the package manager's `install` (`npm install`, `yarn install`, `pnpm install`, `bun install`), so the lockfile decides the versions. Nothing else is deleted and `package.json` isn't edited, so no version changes. Press `U` twice to confirm (any other key cancels); it is refused while another install runs. All rows show as installing until it ends. If the install fails, `node_modules` is already gone: the log says so and the error is shown, and `U` can be pressed again to retry |
| `I` | Add the missing integrity checksum of the checked packages, or the highlighted one, to `package-lock.json`. It is the checksum the registry publishes for the locked version, and it is only written when the registry's file is the one the lockfile's `resolved` names. Git packages have none to add; for `pnpm-lock.yaml`, run `pnpm install --fix-lockfile` |
| `q` / `Esc` | Quit (press twice while an install is running) |

The part of the screen that takes the keys has a cyan border: the package list, a prompt typed in the footer (filter, version, pin type), the expanded log, or a dialog. While a dialog is open, everything behind it is dimmed.

`a` and `i` act only on the packages currently shown, so a filter narrows what they touch.
The details come from disk only, nothing is downloaded. The installed copy in `node_modules` is read
first, and the lockfile (`package-lock.json` or `pnpm-lock.yaml`) fills in the rest and gives the
deprecation message and the checksum. Dependency changes compare with the lockfile in `HEAD`
(`git show`). The size is that of the installed copy, its own `node_modules` left out.
### Mouse
- Click an item in the list to move the cursor to it. Click the mark (`○`, `●`) in front of a package or group to check it.
- Click a key hint in the footer to press that key. Click a header item (`group: …`, `vulns hidden`, `overrides hidden`, a scan result) to run its key. Click the `selected:` heading to toggle the details panel.
- Click the log at the bottom to expand it. The list stays visible above it: click a package to give the keys back to the list, click the log to return to it. The wheel scrolls whichever the pointer is over.
- In dialogs, click the footer hints, a peer fix option or an `Add as` choice.
- The wheel moves the cursor in the list and scrolls the details panel and the expanded log.
- Drag over text in the details panel or the log to select it, then press `y` (or click `y copy selection`) to copy it to the clipboard (pbcopy, wl-copy, xclip, xsel or clip.exe). `Esc` or any other key drops the selection. Elsewhere, hold Shift (Option in some terminals) to select with the terminal.

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

Versions are fetched with a small request per package, `/-/package/<name>/dist-tags`, which is read
to the end so the connection goes back to the pool and the next request reuses it (no new TCP and
TLS handshake). A registry that doesn't serve it (the request fails but the package document can be
read) is asked for the document instead, the way `npm-check-updates` does it: the abbreviated (corgi)
`Accept` header, reading stops as soon as `dist-tags` has been seen, with a retry for the full
document on a 404. depsu remembers such a registry for the rest of the session. Requests run 16 at
a time.

**Blocked versions.** Registries with a security policy (JFrog Curation, Nexus Firewall and
the like) list blocked versions but answer 403 when one is downloaded. Before an install, depsu
checks that each version it is about to install can be downloaded. If one can't, it looks for the
newest older release that can (trying up to 15) and offers it in a dialog: `y` installs it
instead, `n` installs the rest only. If an install still fails with a 403 for a package file,
also for a nested package, depsu does the same and offers that version, or for a nested package
an override to it. The version is pinned exactly, because a range would resolve to the blocked
version again.

### What counts as outdated

`depsu` compares the lowest version of each dependency's range with the registry's `latest`
dist-tag. Prereleases are ignored. Specs that are not a plain version or range (`git`, `file:`,
`workspace:`, `npm:` aliases, tags, `||` ranges) are skipped. Up-to-date packages are listed too
(`u` hides them).

### Overrides

Overrides come from `overrides` (npm, bun), `resolutions` (yarn, bun) or `pnpm.overrides` (pnpm).
Only the field your package manager honours is read. They are listed under each package; press
`o` to hide them.

**Markers** next to a package name:

| Marker | Meaning |
|---|---|
| `⚑` | The package itself is overridden, and the update is compatible |
| `⚠` | The update conflicts with its override |
| `?` | The override can't be interpreted (URL, alias, odd range) |
| `↳` | An override applies somewhere in the package's installed dependency tree (bold if it forces a version outside what the parent declares) |
| `✱` | A scan found vulnerabilities (coloured by worst severity) |

Overrides are always cyan, bold when they conflict, so they can't be mistaken for vulnerabilities,
which are coloured by severity: critical magenta, high red, medium yellow, low blue.

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
An existing global override that is too low is raised instead. A finding whose vulnerable package an override already pins to the fixed version or higher says so: `✔ fixed by override qs → ^6.0.4: scan again to confirm` while the results are outdated, and `⚠ override … is set, but the last scan still lists this` when a current scan lists it anyway (the override isn't what is installed yet). Run Snyk and the audit again
afterwards (the old results are marked outdated).

**Unneeded overrides.** An override is flagged `✂ may be removed` when the installed tree shows it
no longer changes anything: nothing depends on the package, every dependent already asks for the
same spec, or every dependent already requires at least the override's version. They are also
listed in an "Unneeded overrides" section. Press `d` to remove the checked ones (or the one under
the cursor), and confirm in the dialog. The entry is deleted from `package.json` (empty containers
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
- A finding whose fix depsu can apply ends in green with the key that applies it:
  `⬆ fix: i installs express ^4.22.0` (upgrading the direct dependency fixes it) or
  `⬆ fix: p overrides qs to ^6.14.1` (only an override of the nested package does). Move onto the
  finding and press that key. Findings without a fix depsu can apply keep their note in grey.
- Findings are kept per project and per resolved package version, in memory and in the
  `--cache` file. The resolved version is the one `package-lock.json` pins, or else the one in
  `node_modules`, since that is what Snyk and `npm audit` look at; the range in `package.json`
  is never used. A Snyk finding is filed under the version Snyk names in it, and depsu warns
  when that differs from `node_modules`. A package whose version can't be determined (not
  installed, no npm lockfile) is not recorded. After an install
  or revert, a package shows the findings recorded for its new version if that version was
  scanned before. `↻ npm audit (n) hasn't scanned this version` names each scanner that has
  results, but none for the installed version, with the key that runs it. Findings are matched by the version of your direct
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
| `snyk.rs`, `policy.rs`, `audit.rs`, `vuln.rs` | Snyk CLI integration, the `.snyk` ignore rules, `npm audit` / `bun audit` integration, and the finding type they share. `tests/fixtures/` holds real and hand-written output |

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
