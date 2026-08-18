# omt — OAuth Mail Token

CLI that obtains and prints a valid OAuth2 access token for IMAP/POP/SMTP,
storing state in the OS keyring. Go port of the Python "Mutt OAuth2 token
management" script.

## Go skills

Load `schretzi/schretzi-skills@golang-how-to` at the start of any Go coding,
review, debugging, or setup task here, and let it route to whatever the task
needs. These are reference material, not law: where a skill and the rules
below disagree, the rules below win, because they were derived from how this
program actually has to behave.

Worth loading for most changes here:

- `schretzi/schretzi-skills@golang-security` — this tool handles OAuth2
  client secrets, access tokens and refresh tokens.
- `schretzi/schretzi-skills@golang-lint` — `.golangci.yml` is the source of
  truth for enabled linters; `make pipeline` must stay green.
- `schretzi/schretzi-skills@golang-spf13-cobra` — the CLI is a cobra command
  tree; anything touching commands, flags, args or completion belongs there.

If a skill turns out to be wrong or missing something, fix it at the source
(`~/Workspace/Schretzi/schretzi-skills`) rather than working around it here.

## Licensing

This project is **GPL-3.0-or-later**, as a derivative work of Mutt's
`contrib/mutt_oauth2.py` (Copyright (C) 2020 Alexander Perlis,
GPL-2.0-or-later), exercising that licence's "or any later version" option.

- **Every new `.go` file needs the two-line header** — an
  `// SPDX-License-Identifier: GPL-3.0-or-later` line and the copyright line
  — separated from any package doc comment by a blank line, or it becomes
  part of the godoc.
- **Do not add a GPLv2-incompatible dependency's licence to the mix without
  checking.** Version 3 is required specifically because cobra and friends
  are Apache-2.0. Anything more restrictive than GPLv3-compatible cannot be
  linked in at all. Record new dependencies' licences in `NOTICE`.
- **Record user-visible behaviour changes relative to the Python original**
  in `NOTICE`'s statement of changes — GPLv3 §5(a) requires it.
- Do not relicense to a permissive licence. It is not ours to grant.

## Project rules

- **stdout carries only the command's result.** For the root command and
  `token`, that means the access token and nothing else — `omt <account>` is
  used directly as mutt's password command and inside
  `$(omt token <account>)`, so anything extra on stdout is sent to the mail
  server as part of the bearer token. Every notice, prompt, warning and
  progress message goes to stderr. In code: `app.outln`/`app.outf` for
  results, `app.infoln`/`app.infof` for everything else. Never `fmt.Println`
  or `os.Stdout` directly in a command implementation — the streams are
  fields on `app` so tests can capture them.
  The reporting commands (`status`, `refresh` with no account,
  `list-accounts`, `daemon`) are the exception: their tables and logs *are*
  their result and belong on stdout.
- **Never print a refresh token unless `--verbose`.** It is a long-lived
  credential. Same for anything else that would let a reader mint tokens.
- **`cmd/omt/main.go` stays thin** — it only calls `cli.Main`. All behaviour
  lives in `internal/`. `cli.Root()` must keep returning a *fresh* tree:
  `tools/gendocs` walks it, and cobra accumulates flag state per command
  instance, so a shared tree leaks values between runs and between tests.
- **Tests drive the real command tree** via the `execute` helper, not the
  command implementations directly, so parsing and dispatch stay covered.
- **Usage errors must exit 2.** Wrap argument validators in `usageArgs(...)`
  so bad input is classified as `*usageError` rather than a runtime failure.
- **Every OAuth2 HTTP call takes a `context.Context`** rooted in the
  SIGINT/SIGTERM handler set up in `cli.Main`.
- **Regenerate docs after changing the command tree**: `make docs`.
  `make pipeline` fails if `docs/` is stale.
- **Run `make pipeline` before pushing.** It runs exactly what CI runs. The
  pre-push git hook does this automatically once `make hooks` has been run.
- No viper: the config is a domain-specific `config.yaml` (providers +
  accounts) handled by `internal/config`, not a flag/env/file layering
  problem. Do not add it without a concrete need.
