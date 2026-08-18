## omt daemon

Run in the foreground, periodically refreshing tokens due to expire

### Synopsis

Check every configured account on a timer (global.daemon.interval in
config.yaml, default 5m) and refresh any access token that will expire
within the next 5 minutes. Runs until interrupted (Ctrl-C/SIGTERM).

This exists because an external timer (cron, launchd's StartInterval) does
not fire while the machine is asleep and does not catch up missed ticks - it
fires once, some time after wake - which can leave tokens expired for a
while. The daemon checks expiry itself on every tick rather than relying on
ticking at exactly the right moment.

Refreshes and errors are always printed; with global.debug: true (or
-d/--debug) each individual check is printed too.

```
omt daemon [flags]
```

### Options

```
  -h, --help   help for daemon
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account

