## omt service stop

Unload the LaunchAgent

### Synopsis

Unload the job.

This is a real stop, not a kill: the plist uses KeepAlive/SuccessfulExit so
launchd does not immediately restart it. The job comes back at next login, or
on `service start`.

```
omt service stop [flags]
```

### Options

```
  -h, --help   help for stop
```

### Options inherited from parent commands

```
      --binary string   path to the omt executable to run (default: the running one)
  -d, --debug           log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose         increase verbosity
```

### SEE ALSO

* [omt service](omt_service.md)	 - Manage the omt LaunchAgent

