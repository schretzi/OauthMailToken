## omt

Obtain and print a valid OAuth2 access token for a mail account

### Synopsis

omt obtains and prints a valid OAuth2 access token for IMAP/POP/SMTP,
for use from mutt's imap_pass_cmd (or anything else that wants a bearer
token). State is kept in the OS keyring.

Run with just an account name to print a valid access token, transparently
authorizing (if no token exists yet) or refreshing (if the access token
expired) as needed. Only the token is written to stdout; every notice and
prompt goes to stderr, so the output is safe to use directly as a password
command.

```
omt [flags] <account>
```

### Examples

```
  # what mutt calls
  omt me@gmail.com

  # first-time interactive authorization
  omt authorize me@gmail.com

  # use the token from a script
  curl -H "Authorization: Bearer $(omt token me@gmail.com)" ...
```

### Options

```
      --authflow string   OAuth2 flow to use for a first-time authorization: authcode | localhostauthcode | devicecode
  -a, --authorize         re-run the interactive authorization flow (same as "omt authorize")
  -d, --debug             log raw HTTP responses from the OAuth2 endpoints
  -h, --help              help for omt
  -t, --test              test IMAP/POP/SMTP endpoints (not yet implemented)
  -v, --verbose           increase verbosity
```

### SEE ALSO

* [omt authorize](omt_authorize.md)	 - Re-run the interactive authorization flow for an account
* [omt daemon](omt_daemon.md)	 - Run in the foreground, periodically refreshing tokens due to expire
* [omt list-accounts](omt_list-accounts.md)	 - Print the account names configured in config.yaml, one per line
* [omt refresh](omt_refresh.md)	 - Force a refresh-token exchange, even if the access token is still valid
* [omt status](omt_status.md)	 - Show authorization status for all accounts, or one
* [omt token](omt_token.md)	 - Print the stored access token for one account, and nothing else
* [omt version](omt_version.md)	 - Print the omt version, build info and licence

