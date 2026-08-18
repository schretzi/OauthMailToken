# omt — OAuth Mail Token

Go port of the original Python "Mutt OAuth2 token management" script. Obtains
and prints a valid OAuth2 access token for IMAP/POP/SMTP (e.g. for use from
`.muttrc`'s `imap_authenticators`/`imap_pass_cmd`). Tokens are stored in the
OS keyring (macOS Keychain, Windows Credential Manager, or the Linux Secret
Service) instead of an encrypted file.

Licensed under **GPL-3.0-or-later**. This is a derivative work of Mutt's
`contrib/mutt_oauth2.py` — see [License and attribution](#license-and-attribution).

## Install

**Homebrew (macOS):**

```sh
brew install schretzi/tap/omt
```

This also installs the man pages (`man omt`) and shell completions.

**With Go:**

```sh
go install github.com/schretzi/oauthmailtoken/cmd/omt@latest
```

**From a release archive:** grab the tarball for your platform from the
[releases page](https://github.com/schretzi/OauthMailToken/releases); it
contains the binary plus `man/`, `completions/` and `docs/`.

## Build from source

```sh
go mod tidy   # resolves and locks dependency versions (needs network access once)
go build -o omt ./cmd/omt
```

Or, equivalently, `make build`.

## Test

```sh
go test ./...      # or: make test  (adds -race and coverage)
```

## Configure

Same `config.yaml` format as the Python version, looked up the same way (via
XDG base directories): `$XDG_CONFIG_HOME/omt/config.yaml`, falling back to
`$XDG_CONFIG_DIRS/omt/config.yaml` (default `/etc/xdg/omt/config.yaml`). On
macOS/Linux that's usually `~/.config/omt/config.yaml`. See `config.yaml` in
this repo for the expected structure (Google and Microsoft/o365 provider
examples, plus per-account settings).

## Usage

```sh
omt authorize me@gmail.com   # first run / re-authorize: shorthand for "--authorize"
omt me@gmail.com             # prints a valid access token, refreshing if needed
omt refresh me@gmail.com     # force a refresh-token exchange for just this account
omt refresh                  # ... or force it for every account that has a refresh token
omt list-accounts            # print the account names configured in config.yaml
omt status                   # authorization status for every configured account
omt status me@gmail.com      # ... or just one
omt token me@gmail.com       # print *only* the stored access token, for piping elsewhere
omt daemon                   # run in the foreground, keeping all tokens refreshed
omt version                  # version, commit and build date
omt --help                   # full command tree; "omt <command> --help" for one command
```

Per-command reference pages are generated from the command tree into
[`docs/`](docs/) (`make docs` regenerates them).

`token` is for embedding in another program, e.g.
`curl -H "Authorization: Bearer $(omt token me@gmail.com)" ...`: unlike the
default command, it never authorizes or refreshes - it's a read-only lookup
of whatever's currently in the keyring, and stdout is *only* the token (no
NOTICE lines, no refresh token, nothing). It fails (non-zero exit, message
on stderr) if the account was never authorized. If the stored token happens
to be expired, it's still printed (that's what's stored), but a warning goes
to stderr - run `omt refresh <account>` first if you want a guaranteed-valid
token.

`refresh` with no account forces a refresh-token exchange for every
configured account that currently has one stored - accounts that were never
authorized, or whose stored token has no refresh token, are skipped (printed
as `skipped: ...`, not treated as errors: refreshing "all that are possible"
is the point). It prints a summary table instead of a bare access token:

```
ACCOUNT             RESULT
me@gmail.com        refreshed (valid until 2026-08-15 15:32:10)
me@outlook.com      skipped: no refresh token (run "omt authorize me@outlook.com")
someone@else.com    skipped: not authorized yet
```

If at least one account's refresh actually fails (as opposed to being
skipped), `omt refresh` exits non-zero after printing the table, so it's
safe to use from a cron job/launchd timer to keep refresh tokens from going
stale - `omt refresh` is a no-op (and quick) for accounts that don't need it.

`status` prints one row per account (`ACCOUNT`, `PROVIDER`, `STATUS`,
`EXPIRES`, `REFRESH TOKEN`, `REFRESH EXPIRES`), e.g.:

```
ACCOUNT             PROVIDER  STATUS          EXPIRES                          REFRESH TOKEN  REFRESH EXPIRES
me@gmail.com        google    valid           2026-08-15 14:32:10 (in 41m2s)   yes            unknown
me@outlook.com      o365      expired         2026-08-14 09:11:03 (3h4m ago)   yes            unknown
someone@else.com    google    not authorized  -                                -              -
```

`STATUS` is one of `not authorized` (no token stored yet - run `authorize`),
`valid`, or `expired` (still has a refresh token unless `REFRESH TOKEN` says
`no`, in which case only `authorize` will fix it). `REFRESH EXPIRES` is the
refresh token's *own* expiration - a separate, usually much longer-lived,
timer than the access token's. Most providers, including Google and
Microsoft, don't actually report this in the token response at all (their
refresh tokens are effectively long-lived: valid until revoked or unused for
a long time, not on a fixed schedule), so `unknown` here is the expected,
common case, not a bug - it just means "the provider didn't tell us, ask it
again later with `status`/`refresh` after using it." If a provider *does*
report it, you'll see the same `<time> (in/ago ...)` format as `EXPIRES`, and
if that itself is in the past, only `authorize` (not `refresh`) will fix it.
`status` only reads what's already stored in the keyring - it never contacts
the provider or refreshes anything itself.

### Using it from mutt

`omt <account>` writes the token, and only the token, to stdout — every
notice, prompt and warning goes to stderr — so it can be used directly as a
password command:

```muttrc
set imap_authenticators = "oauthbearer:xoauth2"
set smtp_authenticators = "$imap_authenticators"

set imap_user = "me@gmail.com"
set imap_pass = `omt me@gmail.com`

# ... or, evaluated per connection rather than once at startup:
set imap_oauth_refresh_command = "omt me@gmail.com"
set smtp_oauth_refresh_command = "omt me@gmail.com"
```

Use the absolute path (`/opt/homebrew/bin/omt`) if mutt runs with a `$PATH`
that doesn't include it.

### `daemon`: keep tokens refreshed across sleep/wake, without relying on an external timer

`omt refresh` on a launchd/cron timer works, but `StartInterval`-style timers
don't fire while the machine is asleep and don't catch up missed ticks - they
just fire once, some time after wake. If the gap between "should have
refreshed" and "actually got refreshed" is long enough, tokens can sit
expired for a while after the laptop wakes up.

`omt daemon` runs in the foreground and does its own timing instead: on a
configurable interval (`global.daemon.interval` in `config.yaml`, a Go
duration string like `5m` or `90s`; defaults to `5m` if unset), it checks
every configured account's *currently stored* token and refreshes any whose
access token will expire within the next 5 minutes (fixed, not configurable -
this is the safety margin, not the check frequency). Accounts that were
never authorized, or have no refresh token stored, are silently skipped
(they need `omt authorize <account>`, which `daemon` never runs on its own).

```sh
./omt daemon                  # run until Ctrl-C/SIGTERM, using config.yaml's interval
```

`daemon` always prints every refresh it performs and every error it hits
(reading the keyring, or the refresh-token exchange itself failing) -
nothing else, by default. Set `global.debug: true` in `config.yaml` (or pass
`-d`/`--debug`) to also log each check it performs - which account, what it
found, and what it decided - one line per account per tick, plus a
start/end banner for the tick itself. Example (debug on):

```
omt daemon: starting, checking 4 account(s) every 5m0s, refreshing tokens expiring within 5m0s
[2026-08-15T09:00:00+02:00] omt daemon: tick start, checking 4 account(s)
[2026-08-15T09:00:00+02:00] omt daemon: me@gmail.com: access token valid for 41m2s, no refresh needed
[2026-08-15T09:00:00+02:00] omt daemon: me@outlook.com: access token expires in 3m10s (within 5m0s lookahead), refreshing
[2026-08-15T09:00:00+02:00] omt daemon: refreshed me@outlook.com (valid until 2026-08-15T10:00:00+02:00)
[2026-08-15T09:00:00+02:00] omt daemon: someone@else.com: not authorized yet, skipping
[2026-08-15T09:00:00+02:00] omt daemon: tick done
```

Run it as a long-lived background process (e.g. a launchd `KeepAlive` job
that just runs `omt daemon`, rather than a `StartInterval` job that re-runs
`omt refresh` periodically) to get self-healing refresh behavior that
doesn't depend on external timing at all - the daemon re-checks everything
itself as soon as it's running again after a sleep/wake cycle, instead of
waiting for the next scheduled tick.

Commands: no subcommand (the default: get a valid token, authorizing/
refreshing transparently as needed - what `.muttrc` should call), `authorize`
(shorthand for `--authorize`: always re-run the interactive flow), `refresh`
(optional account argument; force a refresh-token exchange for just that
account - fails if no token is stored yet, run `authorize` first - or for
every account that has one if omitted), `list-accounts` (no account
argument), `status` (optional account argument; all accounts if omitted),
`token` (mandatory account argument; print only the stored access token, see
above), `completion` (mandatory shell argument; print a shell completion
script, see below), `daemon` (no account argument; run in the foreground,
self-healing token refresh on a timer, see above), `version`. A subcommand,
if used, must be the first argument.

Flags: `-v/--verbose` (also prints the refresh token after obtaining new
tokens), `-d/--debug` (prints raw HTTP responses; for `daemon`, also turns on
its per-check log lines, same as `global.debug: true`), `-a/--authorize`
(force re-authorization; same effect as the `authorize` command, kept for
backwards compatibility), `--authflow authcode|localhostauthcode|devicecode`,
`-t/--test` (accepted for compatibility with the Python CLI; not implemented
— it wasn't implemented in the original script either).

Flags may appear before or after the account argument, so both
`omt -v me@gmail.com` and `omt me@gmail.com -v` work.

### Shell completion

The completion scripts are generated by cobra and cover subcommands, flags,
flag values (`--authflow`), and account names read straight out of
`config.yaml` — so completion always reflects the current config without
being regenerated, and without shelling out to `omt list-accounts` on every
TAB press.

If you installed via Homebrew, completions are already installed. Otherwise:

```sh
# bash - add to ~/.bashrc:
source <(omt completion bash)

# zsh - add to ~/.zshrc, after compinit has run:
autoload -Uz compinit && compinit
source <(omt completion zsh)

# fish:
omt completion fish | source
```

`omt completion --help` lists every supported shell (bash, zsh, fish,
powershell) and the per-shell install instructions.

### Choosing which browser opens for login

By default, interactive flows (`authorize`, or `refresh`/the default command
when no token exists yet) only print the authorization URL. Add an optional
`browser` section - globally under `global`, and/or per-account, overriding
the global default - to have `omt` also launch it automatically:

```yaml
global:
  browser:
    command: open          # macOS: `open -a <App> [--args ...] <url>`
    args: ["-a", "Safari"]
accounts:
  me@gmail.com:
    browser:
      command: open
      args: ["-a", "Zen Browser"]
  me@outlook.com:
    browser:
      command: open
      args: ["-a", "Zen Browser"]
```

The authorization URL is always appended as the final argument. Set
`browser: {disabled: true}` on an account to opt it out even when a global
default is configured. If neither an account nor the global section defines
`browser`, the behavior is unchanged: the URL is only printed. A failed
launch (e.g. wrong app name) is a non-fatal notice - the printed URL is
always still there to open manually. See `config.yaml` in this repo for a
worked example (Safari as the global default, Zen Browser for Gmail/Outlook).

**A note on Zen Browser specifically:** `-P <name>` (as used by Firefox to
pick a *profile*) is not the same thing as a Zen *workspace/space* - those
live inside a single profile. Passing `-P` with something that isn't an
actual Firefox profile name makes Zen show its profile-selector prompt
instead of opening directly, which is worse than not selecting anything.
As of this writing, Zen has no released command-line flag to jump straight
to a specific workspace - there's an open, not-yet-merged upstream pull
request adding `--space <name-or-uuid>`
([zen-browser/desktop#14104](https://github.com/zen-browser/desktop/pull/14104)).
Once that ships, `args` for a Zen account could become e.g.
`["-a", "Zen Browser", "--args", "--space", "gmail"]` (matching whatever you
named the workspace) - until then, `args: ["-a", "Zen Browser"]` just opens
Zen in whatever workspace was last active.

### Personal vs. work/school Microsoft accounts

Microsoft's v2.0 endpoints decide which account types may sign in based on
the **URL path segment** in `authorize_endpoint`/`devicecode_endpoint`/
`token_endpoint` (`common` | `organizations` | `consumers` | `<tenant-id>`) -
not the `tenant:` config field, which is only sent as an inert query/form
parameter and doesn't affect routing. `/common/` is meant to allow both
account types, but a personal Microsoft account (outlook.com, hotmail.com,
live.com, ...) can still land on "personal accounts are not allowed" there
depending on the app registration; Microsoft's documented fix is to use
`/consumers/` explicitly. `config.yaml` in this repo has both an `o365`
provider (work/school, `/common/`) and an `o365-consumers` provider
(personal, `/consumers/`) - point an account's `provider:` at whichever
matches it.

Using `/consumers/` only helps if the **app registration itself** is also
enabled for personal accounts - that's a separate Entra ID setting
("Supported account types") on the specific `client_id`, and it's not
something any URL or config value can work around. If you don't control the
app registration (e.g. you're using someone else's `client_id`, or you don't
have Entra ID admin access), you'll see `unauthorized_client: ... not
enabled for consumers` if it isn't. `config.yaml`'s `o365-consumers` example
uses Thunderbird's public client ID
(`9e5f94bc-e8a4-4e73-b8be-63364c29d753`), which *is* enabled for personal
accounts and needs no `client_secret` (a "public client" in OAuth2 terms -
`client_secret: ""` in config, which `omt` now omits from token requests
entirely rather than sending empty) - this is the same well-known-ID
workaround the mutt/neomutt community has long used for lack of an official
app ID of their own. That app's registration doesn't have an arbitrary
`http://localhost:<port>/` loopback redirect URI registered (only the
`nativeclient` one already in `redirect_uri`), so the matching account entry
uses `authflow: authcode` (manual code copy/paste from the browser address
bar) rather than `localhostauthcode`.

### Silent failures from the token endpoint

If a token endpoint responds with HTTP 200 but a body that has neither
`access_token` nor `error` (e.g. an interstitial/consent page served as 200,
or a misconfigured endpoint URL) - the symptom being "the browser page says
authorization succeeded, but `omt` prints nothing" - `omt` now treats that as
an error instead of silently continuing with an empty token. If you still hit
this after checking the provider/endpoint config, rerun with `-d/--debug` to
see the raw response body the endpoint actually sent.

### "Authorization redirect completed" but nothing gets stored

For the `localhostauthcode` flow, the browser page you land on after
authorizing is served by `omt` itself, from the *loopback* redirect - it
always says "redirect completed" once a request comes back, even if the
identity provider actually redirected with `error`/`error_description`
instead of a `code` (e.g. consent required, conditional access policies, or a
tenant that rejects the app registration entirely). Previously that error was
discarded and you'd just get a generic "did not obtain an authcode" (or,
depending on timing, nothing useful at all). `omt` now reads `error`/
`error_description` off that redirect and reports them - both in the browser
page and on the terminal - so you can see the actual reason (e.g. an AADSTS
error code from Microsoft) instead of just "not authorized" in `status`.

### Large tokens ("data passed to Set was too big")

Some providers - notably corporate/AAD (Microsoft work/school) tenants with
many group claims - issue access tokens too large for a single OS keyring
entry (Windows Credential Manager caps password data at 2560 bytes; macOS
Keychain tops out around 3000 bytes across service+account+password
combined). go-keyring surfaces this as `data passed to Set was too big`.
`omt` now transparently splits tokens that don't fit into multiple keyring
entries (and reassembles them on read) instead of failing or falling back to
a plaintext file - nothing to configure, this just works. If you hit this
error, rebuild and rerun; leftover entries from a previous failed/oversized
attempt clean themselves up on the next successful `authorize`/`refresh`. If
a stored token ever becomes unrecoverable (e.g. one of its chunks is
missing - can happen after an interrupted write), `omt` treats it the same
as "never authorized" rather than erroring out permanently: it prints a
NOTICE and `status`/`get` will show `not authorized` until you run
`authorize` again.

## Local pipeline (static analysis, security, dependencies)

`make pipeline` runs **exactly** what CI runs. If it is green locally, CI is
green — that is the whole point of it, so you never find out about a
formatting or lint failure from a red build on GitHub.

It runs: format check, `go vet`, `golangci-lint`, `gosec`, `govulncheck`,
`go mod` tidiness/verification, a `docs/` staleness check, tests with `-race`,
and a build.

```sh
make tools      # one-time: install golangci-lint, gosec, govulncheck
make hooks      # one-time per clone: install the git hooks (see below)
make pipeline   # the full gate: fmt + vet + lint + gosec + govulncheck + mod tidy/verify + test + build
```

Individual targets (`make help` lists them all):

| Target | What it does |
| --- | --- |
| `make fmt` | Reformat in place (gofumpt + goimports, via `golangci-lint fmt`) |
| `make fmt-check` | Fail if anything is unformatted |
| `make vet` | `go vet ./...` |
| `make lint` | `golangci-lint run` — enabled linters are listed in `.golangci.yml` |
| `make lint-fix` | Same, auto-fixing what it can |
| `make sec` | `gosec` (code-level security analysis) |
| `make vuln` | `govulncheck` (CVEs actually reachable from this code) |
| `make security` | `sec` + `vuln` — one alone misses the other angle |
| `make modcheck` | `go.mod`/`go.sum` tidiness + checksum verification |
| `make test` | Tests with `-race` and coverage |
| `make build` | Build `./cmd/omt` |
| `make docs` | Regenerate `docs/` from the cobra command tree |
| `make docs-check` | Fail if `docs/` is stale |
| `make release-check` | `goreleaser check` + a full snapshot build, publishing nothing |

Missing tools fail their target with an install hint rather than silently
skipping, so a "passing" pipeline never means "the check didn't run".

### Git hooks

Hooks are managed by [lefthook](https://lefthook.dev) (`lefthook.yml`) and
must be installed **once per clone** — a fresh clone has no hooks until you
run it:

```sh
make hooks     # == lefthook install
```

- **pre-commit** (fast, staged files only): `gitleaks protect` to block a
  commit that would introduce a secret, plus a format check and `go vet`.
  Secret detection matters most here: this repo deals in OAuth2 client
  secrets and tokens, and once one is pushed, rotating it is the only remedy.
- **pre-push**: `make pipeline` — the same checks CI runs. This is the gate
  that stops a red build reaching GitHub.

Skip either for one command with `--no-verify`.

Requires `lefthook` and `gitleaks` on your `$PATH` (`brew install lefthook
gitleaks`).

### CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request, splitting `make pipeline` across parallel jobs: build+test,
`golangci-lint` (including the formatting check), `gosec`, `govulncheck` +
`go mod tidy`/`go mod verify`, `goreleaser check`, and a full-history
`gitleaks` scan.
The golangci-lint version is pinned in both the Makefile and the workflow so
the two cannot drift. `.github/dependabot.yml` keeps Go module and Action
versions themselves up to date (weekly PRs).

## Notes on the port

- State moved from an encrypted token file to the OS keyring (same mechanism
  the Python version used via the `keyring` package); the keyring service
  name (`OauthMailToken`) and per-account entries are unchanged.
- The refresh-token grant intentionally omits the `tenant` parameter, matching
  the original script's (arguably inconsistent, but preserved) behavior.
- The refresh token is **no longer printed on every authorize/refresh**. The
  Python original echoed it unconditionally; it is now behind `-v/--verbose`
  (and on stderr). A refresh token is a long-lived credential — possession
  of it is enough to mint access tokens until it is revoked — so leaving it
  in terminal scrollback, and in anything capturing stderr, on every run was
  a needless exposure. It is still stored in the keyring either way; ask for
  it with `-v` when you actually want to see it.
- **stdout carries only the access token.** Every notice, prompt and progress
  message goes to stderr. This is what makes `imap_pass_cmd = omt me@x.com`
  and `$(omt token me@x.com)` safe: previously, a config without an explicit
  `keyring-backend` would print `Keyring Backend not set, ...` onto stdout
  and that line would be sent to the mail server as part of the bearer
  token. The reporting commands (`status`, `refresh` with no account,
  `list-accounts`, `completion`, `daemon`) still write their tables and logs
  to stdout — that output *is* their result.
- Package layout follows the standard Go project layout: `cmd/omt` is a thin
  `main` that only calls `cli.Main`, and everything else lives under
  `internal/` — `internal/cli` (the cobra command tree and the flows each
  command drives), `internal/config` (YAML + XDG lookup),
  `internal/token` (keyring storage + expiry check), `internal/oauth` (PKCE,
  authcode/localhostauthcode/devicecode/refresh flows, SASL string builder),
  `internal/browser` (launching the configured browser). Each package has
  unit tests; network-facing code is tested against `httptest` servers
  instead of the real Google/Microsoft endpoints.
- Every OAuth2 HTTP request carries a `context.Context` rooted in a
  SIGINT/SIGTERM handler, so Ctrl-C (or the daemon's shutdown signal) aborts
  an in-flight request against a wedged token endpoint instead of waiting
  out the 30s client timeout.
- The CLI is built on [cobra](https://github.com/spf13/cobra), replacing the
  original hand-rolled argparse-alike. Help text, man pages, the reference
  pages in `docs/`, and the shell completions are all generated from one
  command tree, so they cannot drift from the actual flags.

## License and attribution

**GPL-3.0-or-later.** See [`LICENSE`](LICENSE) for the full text and
[`NOTICE`](NOTICE) for the attribution and the full statement of changes.
`omt version` prints the short notice.

This program is a derivative work of the **Mutt OAuth2 token management
script** (`contrib/mutt_oauth2.py`), Copyright (C) 2020 Alexander Perlis,
licensed GPL version 2 *or, at your option, any later version*.

It is not a clean-room reimplementation. The OAuth2 flows, the `config.yaml`
format, the stored-token layout and a number of deliberate behavioural quirks
were carried over so existing users and config files keep working — several
functions still carry comments naming the Python routine they mirror. So the
GPL's terms apply to this work too, and everything above about being free to
rewrite it in Go and add features is exactly what the GPL grants.

### Why version 3, when upstream says version 2

The original's "or any later version" clause lets a derivative pick a later
GPL, and this one does — because it has to. `omt` links against Apache-2.0
licensed code (`spf13/cobra`, `inconshreveable/mousetrap`, and part of
`gopkg.in/yaml.v3`), and Apache-2.0's patent-termination and indemnification
terms are [incompatible with GPL version 2](https://www.gnu.org/licenses/license-list.html#apache2)
while being explicitly compatible with version 3. Since Go statically links
everything into one binary, distributing a GPLv2-only `omt` would not be
possible.

Dependency licenses (all GPLv3-compatible) are listed in [`NOTICE`](NOTICE).

### What this means for you

- You can use, study, modify and redistribute it, including commercially.
- If you distribute a modified version, you must release your source under
  the GPL as well, keep the copyright notices, and mark what you changed.
- It comes with **no warranty**.

## Migrating from the pre-cobra CLI

Everyday invocations are unchanged: `omt me@gmail.com`, `omt authorize
me@gmail.com`, `omt refresh`, `omt status`, `omt token me@gmail.com` and
`omt daemon` all behave as before, and flags still work on either side of
the account argument. Four things did change:

| Before | Now |
| --- | --- |
| Refresh token printed on every authorize/refresh | Only with `-v/--verbose` |
| `omt completion bash\|zsh` emitted a hand-written script | Cobra-generated; also supports `fish` and `powershell`. Re-source it (or reinstall via Homebrew) |
| Help text was a hand-maintained block | Generated: `omt --help`, `omt <command> --help`, `man omt` |
| — | New `omt version` subcommand |

Nothing about `config.yaml`, the keyring entries, or the OAuth2 flows
changed, so no re-authorization is needed.

## Releasing

Releases are cut by [goreleaser](https://goreleaser.com) from a **manually
triggered** workflow — pushing a tag alone never publishes anything.

```sh
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

Then: Actions → **Release** → *Run workflow*, and select `v1.2.3` in the
"Use workflow from" dropdown. The workflow builds linux/darwin/windows on
amd64 and arm64, attaches the archives, checksums and SBOMs to a GitHub
release, and pushes an updated Homebrew cask.

Validate the whole thing locally first, without publishing:

```sh
make release-check    # goreleaser check + a full snapshot build into dist/
```

### One-time Homebrew tap setup

The cask is published to a separate tap repository, which does not exist yet:

1. Create a public repo named **`homebrew-tap`** under your account (the
   `homebrew-` prefix is what makes `brew install schretzi/tap/omt` resolve).
2. Create a fine-grained personal access token with **Contents: read and
   write** on that repository only.
3. Add it to *this* repo under Settings → Secrets and variables → Actions as
   **`HOMEBREW_TAP_GITHUB_TOKEN`**. The default `GITHUB_TOKEN` cannot push to
   another repository, which is why a separate token is needed.

Until that is in place, the release job will fail at the "homebrew cask"
step — the GitHub release itself will already have been created, so you can
also just drop the `homebrew_casks` block from `.goreleaser.yaml` if you do
not want a tap.

Note that Homebrew installs casks on macOS only. Linux users take the release
tarball or `go install`.

## AI usage

This project was developed with [Claude Code](https://claude.com/claude-code).
Architecture decisions were made jointly, after researching how the real
libraries and OS keyring backends actually behave; the code was written by
the AI against a human-approved plan, and functionality was verified
end-to-end (against real Google/Microsoft endpoints and the real OS keyring)
rather than assumed to work.
