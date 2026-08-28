## omt service

Manage the omt LaunchAgent

### Synopsis

Manage the launchd job that runs omt in the background.

  label   com.schretzi.omt
  plist   ~/Library/LaunchAgents/com.schretzi.omt.plist
  log     ~/Library/Logs/omt.log
  stderr  ~/Library/Logs/omt.err.log

Both logs are rotated by newsyslog, configured in MacbookSetup under
etc/newsyslog.d/omt.conf.

### Options

```
      --binary string   path to the omt executable to run (default: the running one)
  -h, --help            help for service
```

### Options inherited from parent commands

```
  -d, --debug     log raw HTTP responses from the OAuth2 endpoints
  -v, --verbose   increase verbosity
```

### SEE ALSO

* [omt](omt.md)	 - Obtain and print a valid OAuth2 access token for a mail account
* [omt service install](omt_service_install.md)	 - Write the LaunchAgent plist and load it
* [omt service restart](omt_service_restart.md)	 - Unload and reload the LaunchAgent
* [omt service start](omt_service_start.md)	 - Load the LaunchAgent
* [omt service status](omt_service_status.md)	 - Show whether the LaunchAgent is installed, loaded and running
* [omt service stop](omt_service_stop.md)	 - Unload the LaunchAgent
* [omt service uninstall](omt_service_uninstall.md)	 - Unload the LaunchAgent and remove its plist

