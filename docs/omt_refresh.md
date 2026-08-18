## omt refresh

Force a refresh-token exchange, even if the access token is still valid

### Synopsis

Exchange the stored refresh token for a new access token, whether or not the
current one has expired.

With no account, every configured account that has a refresh token stored is
refreshed and a one-line-per-account summary is printed. Accounts that were
never authorized, or that have no refresh token, are skipped rather than
treated as errors; the command still exits non-zero if an attempted refresh
actually failed.

```
omt refresh [account] [flags]
```

### Options

```
  -h, --help   help for refresh
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account

