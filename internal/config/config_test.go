package config

import (
	"os"
	"path/filepath"
	"testing"
)

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

const sampleYAML = `
global:
  storage: keyring
  keyring-backend: system
  debug: true
  daemon:
    interval: 90s
  browser:
    command: open
    args: ["-a", "Safari"]
  google:
    authorize_endpoint: https://accounts.google.com/o/oauth2/auth
    devicecode_endpoint: https://oauth2.googleapis.com/device/code
    token_endpoint: https://accounts.google.com/o/oauth2/token
    redirect_uri: urn:ietf:wg:oauth:2.0:oob
    scope: https://mail.google.com/
    client_id: googleclientid
    client_secret: googleclientsecret
    sasl_method: OAUTHBEARER
  o365:
    authorize_endpoint: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
    token_endpoint: https://login.microsoftonline.com/common/oauth2/v2.0/token
    redirect_uri: https://login.microsoftonline.com/common/oauth2/nativeclient
    tenant: common
    scope: "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"
    client_id: o365clientid
    client_secret: o365clientsecret
    sasl_method: XOAUTH2
accounts:
  someone@gmail.com:
    provider: google
    authflow: localhostauthcode
    browser:
      command: open
      args: ["-a", "Zen Browser", "--args", "-P", "gmail-profile"]
  someone@outlook.com:
    provider: o365
  someone@disabled.example.com:
    provider: google
    browser:
      disabled: true
`

func TestLoadParsesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Global == nil {
		t.Fatal("expected Global section to be set")
	}
	if cfg.Global.Storage != "keyring" {
		t.Errorf("Storage = %q, want %q", cfg.Global.Storage, "keyring")
	}
	if cfg.Global.KeyringBackend != "system" {
		t.Errorf("KeyringBackend = %q, want %q", cfg.Global.KeyringBackend, "system")
	}
	if !cfg.Global.Debug {
		t.Error("expected Debug to be true")
	}
	if cfg.Global.Daemon == nil || cfg.Global.Daemon.Interval != "90s" {
		t.Errorf("Daemon = %+v, want Interval %q", cfg.Global.Daemon, "90s")
	}

	google, ok := cfg.Global.Providers["google"]
	if !ok {
		t.Fatal("expected google provider to be present")
	}
	if google.ClientID != "googleclientid" {
		t.Errorf("google.ClientID = %q, want %q", google.ClientID, "googleclientid")
	}
	if google.Tenant != "" {
		t.Errorf("google.Tenant = %q, want empty", google.Tenant)
	}

	o365, ok := cfg.Global.Providers["o365"]
	if !ok {
		t.Fatal("expected o365 provider to be present")
	}
	if o365.Tenant != "common" {
		t.Errorf("o365.Tenant = %q, want %q", o365.Tenant, "common")
	}

	acc, ok := cfg.Accounts["someone@gmail.com"]
	if !ok {
		t.Fatal("expected someone@gmail.com account to be present")
	}
	if acc.Provider != "google" || acc.Authflow != "localhostauthcode" {
		t.Errorf("unexpected account config: %+v", acc)
	}
	if acc.Browser == nil || acc.Browser.Command != "open" {
		t.Fatalf("expected someone@gmail.com to have a browser override, got %+v", acc.Browser)
	}
	if len(acc.Browser.Args) != 5 || acc.Browser.Args[4] != "gmail-profile" {
		t.Errorf("unexpected browser args: %v", acc.Browser.Args)
	}

	if cfg.Global.Browser == nil || cfg.Global.Browser.Command != "open" {
		t.Fatalf("expected global browser default, got %+v", cfg.Global.Browser)
	}

	provider, err := cfg.Provider("someone@gmail.com")
	if err != nil {
		t.Fatalf("Provider returned error: %v", err)
	}
	if provider.ClientID != "googleclientid" {
		t.Errorf("Provider().ClientID = %q, want %q", provider.ClientID, "googleclientid")
	}
}

func TestEffectiveBrowser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Account-level override wins over the global default.
	b := cfg.EffectiveBrowser("someone@gmail.com")
	if b == nil || b.Command != "open" || len(b.Args) == 0 || b.Args[len(b.Args)-1] != "gmail-profile" {
		t.Errorf("someone@gmail.com: expected gmail-profile override, got %+v", b)
	}

	// No account-level browser -> falls back to the global default.
	b = cfg.EffectiveBrowser("someone@outlook.com")
	if b == nil || b.Command != "open" || len(b.Args) != 2 || b.Args[1] != "Safari" {
		t.Errorf("someone@outlook.com: expected global Safari default, got %+v", b)
	}

	// Account explicitly disables browser auto-open, even though a global
	// default exists.
	b = cfg.EffectiveBrowser("someone@disabled.example.com")
	if b != nil {
		t.Errorf("someone@disabled.example.com: expected nil (disabled), got %+v", b)
	}

	// Unknown account, no global default configured at all.
	bare := &Config{Global: &GlobalSection{}, Accounts: map[string]AccountConfig{}}
	if b := bare.EffectiveBrowser("nobody@example.com"); b != nil {
		t.Errorf("expected nil with no config at all, got %+v", b)
	}

	// Global default disabled, account has no override.
	disabledGlobal := &Config{
		Global:   &GlobalSection{Browser: &BrowserConfig{Command: "open", Disabled: true}},
		Accounts: map[string]AccountConfig{"x@example.com": {}},
	}
	if b := disabledGlobal.EffectiveBrowser("x@example.com"); b != nil {
		t.Errorf("expected nil with globally-disabled browser, got %+v", b)
	}
}

func TestLoadDaemonAndDebugDefaultToZeroValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("global:\n  storage: keyring\naccounts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Global.Debug {
		t.Error("expected Debug to default to false")
	}
	if cfg.Global.Daemon != nil {
		t.Errorf("expected Daemon to default to nil, got %+v", cfg.Global.Daemon)
	}
}

func TestProviderUnknownAccount(t *testing.T) {
	cfg := &Config{Global: &GlobalSection{}, Accounts: map[string]AccountConfig{}}
	if _, err := cfg.Provider("nobody@example.com"); err == nil {
		t.Fatal("expected error for unknown account")
	}
}

func TestLocateConfigFileFound(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "omt"), 0o700); err != nil {
		t.Fatal(err)
	}
	withEnv(t, "XDG_CONFIG_HOME", home)
	withEnv(t, "XDG_CONFIG_DIRS", filepath.Join(t.TempDir(), "unused"))

	path, err := LocateConfigFile("omt")
	if err != nil {
		t.Fatalf("LocateConfigFile returned error: %v", err)
	}
	want := filepath.Join(home, "omt", "config.yaml")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestLocateConfigFileNotFound(t *testing.T) {
	withEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	withEnv(t, "XDG_CONFIG_DIRS", t.TempDir())

	if _, err := LocateConfigFile("omt"); err == nil {
		t.Fatal("expected error when no omt config dir exists")
	}
}
