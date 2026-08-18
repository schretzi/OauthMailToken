## omt token

Print the stored access token for one account, and nothing else

### Synopsis

Print the access token currently stored for the account, straight from the
keyring. Nothing else is written to stdout, so this is safe to embed in a
command substitution.

Unlike the root command, "token" never authorizes and never refreshes: it
reports exactly what is stored, and fails if the account was never
authorized. If the stored token has expired it is still printed, with a
warning on stderr.

```
omt token <account> [flags]
```

### Examples

```
  curl -H "Authorization: Bearer $(omt token me@gmail.com)" https://example.com
```

### Options

```
  -h, --help   help for token
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account

