package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileIsActuallyLoaded(t *testing.T) {
	p := writeCfg(t, `{"username":"FromFile","tcp_port":9001}`)
	cfg, err := Load([]string{"--config", p}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "FromFile" || cfg.TCPPort != 9001 {
		t.Fatalf("file ignored: %+v", cfg)
	}
}

func TestPrecedence(t *testing.T) {
	p := writeCfg(t, `{"username":"file","tcp_port":9001,"log_level":"debug"}`)
	cfg, err := Load([]string{"-c=" + p, "-u", "flag"}, env(map[string]string{
		"P2P_USERNAME": "env", "P2P_TCP_PORT": "9002",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "flag" { // flag > env > file
		t.Errorf("username = %q, want flag", cfg.Username)
	}
	if cfg.TCPPort != 9002 { // env > file
		t.Errorf("tcp_port = %d, want 9002", cfg.TCPPort)
	}
	if cfg.LogLevel != "debug" { // file > default
		t.Errorf("log_level = %q, want debug", cfg.LogLevel)
	}
}

func TestConfigPathFromEnvAndMissingExplicitFile(t *testing.T) {
	p := writeCfg(t, `{"username":"viaenv"}`)
	cfg, err := Load(nil, env(map[string]string{"P2P_CONFIG_FILE": p}))
	if err != nil || cfg.Username != "viaenv" {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	if _, err := Load([]string{"--config", filepath.Join(t.TempDir(), "nope.json")}, env(nil)); err == nil {
		t.Fatal("an explicitly requested config file that is missing must be an error")
	}
}

func TestBadValuesAreRejected(t *testing.T) {
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"bad env int":        {env: map[string]string{"P2P_TCP_PORT": "eighty"}},
		"bad env bool":       {env: map[string]string{"P2P_NOTIFICATIONS": "maybe"}},
		"port out of range":  {args: []string{"-p", "70000"}},
		"unknown flag":       {args: []string{"--nope"}},
		"stray argument":     {args: []string{"hello"}},
		"control chars name": {args: []string{"-u", "bad\x1b[2Jname"}},
		"long name":          {args: []string{"-u", strings.Repeat("a", 33)}},
		"bad broadcast":      {args: []string{"--broadcast-addr", "not-an-ip"}},
		"range overflow":     {args: []string{"--discovery-port", "65530", "--discovery-range", "20"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(tc.args, env(tc.env)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestHelp(t *testing.T) {
	if _, err := Load([]string{"-h"}, env(nil)); !errors.Is(err, ErrHelp) {
		t.Fatalf("got %v, want ErrHelp", err)
	}
}

func TestDatabasePathDefaultsIntoDataDir(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load([]string{"--data-dir", dir}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "lazy-chat.db"); cfg.Database.Path != want {
		t.Fatalf("db path = %q, want %q", cfg.Database.Path, want)
	}
}

func TestDefaultConfigHasNoSideEffects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	DefaultConfig()
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("DefaultConfig created files: %v", entries)
	}
}
