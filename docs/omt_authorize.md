## omt authorize

Re-run the interactive authorization flow for an account

### Synopsis

Run the interactive OAuth2 authorization flow for the account and store the
resulting tokens, whether or not a valid token already exists.

Which flow is used comes from the account's "authflow" setting in
config.yaml, or from --authflow, or - if neither is set - from an
interactive prompt.

```
omt authorize <account> [flags]
```

### Options

```
      --authflow string   OAuth2 flow to use for a first-time authorization: authcode | localhostauthcode | devicecode
  -h, --help              help for authorize
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account

