# omt — OAuth Mail Token

Go port of the original Python "Mutt OAuth2 token management" script. Obtains
and prints a valid OAuth2 access token for IMAP/POP/SMTP (e.g. for use from
`.muttrc`'s `imap_authenticators`/`imap_pass_cmd`). Tokens are stored in the
OS keyring (macOS Keychain, Windows Credential Manager, or the Linux Secret
Service) instead of an encrypted file.

## Build

```sh
go mod tidy   # resolves and locks dependency versions (needs network access once)
go build -o omt .
```

## Test

```sh
go test ./...
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
./omt authorize me@gmail.com   # first run / re-authorize: shorthand for "--authorize"
./omt me@gmail.com             # prints a valid access token, refreshing if needed
./omt refresh me@gmail.com     # force a refresh-token exchange for just this account
./omt refresh                  # ... or force it for every account that has a refresh token
./omt list-accounts            # print the account names configured in config.yaml
./omt status                   # authorization status for every configured account
./omt status me@gmail.com      # ... or just one
./omt token me@gmail.com       # print *only* the stored access token, for piping elsewhere
./omt daemon                   # run in the foreground, keeping all tokens refreshed
```

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
above), `completion` (mandatory `bash` or `zsh` argument; print a shell
completion script, see below), `daemon` (no account argument; run in the
foreground, self-healing token refresh on a timer, see above). A subcommand,
if used, must be the first argument.

Flags: `-v/--verbose`, `-d/--debug` (prints raw HTTP responses; for `daemon`,
also turns on its per-check log lines, same as `global.debug: true`),
`-a/--authorize` (force re-authorization; same effect as the `authorize`
command, kept for backwards compatibility),
`--authflow authcode|localhostauthcode|devicecode`, `-t/--test` (accepted for
compatibility with the Python CLI; not implemented — it wasn't implemented in
the original script either).

### Shell completion

`omt completion bash` / `omt completion zsh` print a completion script to
stdout - it completes subcommands, flags, and (by shelling out to
`omt list-accounts` at completion time) account names, so it always reflects
whatever's currently in `config.yaml` without needing to be regenerated.

```sh
# bash - add to ~/.bashrc:
source <(omt completion bash)

# zsh - add to ~/.zshrc, after compinit has run:
autoload -Uz compinit && compinit
source <(omt completion zsh)
```

Both are self-contained (the bash one doesn't need the `bash-completion`
package installed). Requires `omt` to be on `$PATH` when completing, since
account-name completion invokes it.

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

```sh
make tools   # one-time: install golangci-lint, gosec, govulncheck
make check   # fmt-check + go vet + golangci-lint + gosec + govulncheck + go mod tidy/verify + tests
make ci      # everything in `check`, plus a build - this is what GitHub Actions runs
```

Individual targets: `make fmt`, `make fmt-check`, `make vet`, `make lint`
(golangci-lint, config in `.golangci.yml`), `make sec` (gosec), `make vuln`
(govulncheck), `make modcheck` (go.mod/go.sum tidiness + checksum
verification), `make test`, `make build`. Run `make help`-style introspection
with `grep -h '##' Makefile` if you forget a target name, or just open the
Makefile - each target has a one-line `##` comment.

Missing tools fail their target with an install hint rather than silently
skipping (except in the pre-commit hook below, which treats golangci-lint as
optional so an uninstalled linter doesn't block every commit).

### Pre-commit hook

A tracked hook in `.githooks/pre-commit` runs gofmt, `go vet`, and (if
installed) golangci-lint against staged Go files before each commit. Enable
it once per clone with:

```sh
make hooks-install
```

This points Git at the tracked `.githooks/` directory (`git config
core.hooksPath .githooks`) instead of copying into the untracked
`.git/hooks/`, so the hook stays in version control. Skip it for a single
commit with `git commit --no-verify`.

### CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request: build+test, `golangci-lint`, `gosec`, and `govulncheck` +
`go mod tidy`/`go mod verify`, each as a separate job. `.github/dependabot.yml`
keeps Go module and Action versions themselves up to date (weekly PRs).

## Notes on the port

- State moved from an encrypted token file to the OS keyring (same mechanism
  the Python version used via the `keyring` package); the keyring service
  name (`OauthMailToken`) and per-account entries are unchanged.
- The refresh-token grant intentionally omits the `tenant` parameter, matching
  the original script's (arguably inconsistent, but preserved) behavior.
- `update_tokens` still unconditionally prints the refresh token to stdout
  after obtaining new tokens, matching the original.
- Package layout: `internal/config` (YAML + XDG lookup), `internal/token`
  (keyring storage + expiry check), `internal/oauth` (PKCE, authcode/
  localhostauthcode/devicecode/refresh flows, SASL string builder), with
  `main.go`/`args.go` as the CLI entry point. Each package has unit tests;
  network-facing code is tested against `httptest` servers instead of the
  real Google/Microsoft endpoints.
