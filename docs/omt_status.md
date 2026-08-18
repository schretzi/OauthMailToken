## omt status

Show authorization status for all accounts, or one

### Synopsis

Print a table showing, per account: whether it has been authorized, whether
its access token is still valid and when it expires, whether a refresh token
is stored, and that refresh token's own expiry if the provider reported one
(most do not).

A keyring problem on one account is reported in its row rather than failing
the whole command.

```
omt status [account] [flags]
```

### Options

```
  -h, --help   help for status
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account

