## omt service install

Write the LaunchAgent plist and load it

### Synopsis

Write ~/Library/LaunchAgents/com.schretzi.omt.plist and load it.

Idempotent: an already-loaded job is unloaded and reloaded, so this is also
how you apply a change to the plist.

```
omt service install [flags]
```

### Options

```
  -h, --help   help for install
```

### Options inherited from parent commands

```
      --binary string   path to the omt executable to run (default: the running one)
  -d, --debug           log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose         increase verbosity
```

### SEE ALSO

* [omt service](omt_service.md)	 - Manage the omt LaunchAgent

