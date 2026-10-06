package update

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withoutPSModulePath drops PSModulePath. CI runs tests from PowerShell 7, whose
// module path would otherwise be inherited by Windows PowerShell 5.1 (what the
// installer runs under for real users), which then cannot find its own modules.
func withoutPSModulePath(env []string) []string {
	var out []string
	for _, e := range env {
		if !strings.HasPrefix(strings.ToUpper(e), "PSMODULEPATH=") {
			out = append(out, e)
		}
	}
	return out
}

func runPowerShell(t *testing.T, srv *httptest.Server, dir string, extra ...string) (string, error) {
	t.Helper()
	script, _ := filepath.Abs("../../scripts/install.ps1")
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Invoke-Expression ([IO.File]::ReadAllText($env:LAZYCHAT_SCRIPT))")
	cmd.Env = append(withoutPSModulePath(os.Environ()),
		"LAZYCHAT_SCRIPT="+script,
		"LAZYCHAT_BASE_URL="+srv.URL,
		"LAZYCHAT_KEY_URL="+srv.URL+"/key.pub",
		"LAZYCHAT_INSTALL_DIR="+dir,
		"LAZYCHAT_NO_PATH=1",     // never touch the real user PATH from a test
		"LAZYCHAT_NO_FIREWALL=1", // nor the real firewall (the fake program could not run anyway)
	)
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallPowerShellScript(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("no powershell")
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("unsupported CPU")
	}

	t.Run("installs after verifying checksum and signature", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, "windows", arch)
		dir := filepath.Join(t.TempDir(), "bin")
		out, err := runPowerShell(t, srv, dir)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, want := range []string{"Signature verified", "Checksum verified"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q:\n%s", want, out)
			}
		}
		if got := read(t, filepath.Join(dir, "lazy-chat.exe")); !strings.Contains(got, "v1.4.0") {
			t.Fatalf("installed %q", got)
		}
	})

	t.Run("upgrade replaces the previous version", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, "windows", arch)
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "lazy-chat.exe"), []byte("old"), 0o755)
		if out, err := runPowerShell(t, srv, dir); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if got := read(t, filepath.Join(dir, "lazy-chat.exe")); !strings.Contains(got, "v1.4.0") {
			t.Fatalf("installed %q", got)
		}
		if _, err := os.Stat(filepath.Join(dir, "lazy-chat.exe.old")); err == nil {
			t.Fatal("old copy left behind")
		}
	})

	refusals := map[string]func(f *fakeRelease){
		"archive tampered": func(f *fakeRelease) {
			n := ArchiveName(f.tag, "windows", arch)
			f.files[n] = append(append([]byte(nil), f.files[n]...), 0)
		},
		"checksums tampered": func(f *fakeRelease) { f.files[checksumsName] = append(f.files[checksumsName], []byte("# x\n")...) },
		"wrong signer":       func(f *fakeRelease) { f.files[signatureName] = sign(t, newKey(t), f.files[checksumsName]) },
		"no checksum for this archive": func(f *fakeRelease) {
			f.files[checksumsName] = []byte("00  other.zip\n")
			f.files[signatureName] = sign(t, f.key, f.files[checksumsName])
		},
	}
	for name, tamper := range refusals {
		t.Run("refuses: "+name, func(t *testing.T) {
			f := newFakeRelease(t, "v1.4.0", []byte("unused"))
			srv := serveInstallRelease(t, f, "windows", arch)
			f.mu.Lock() // the server's handlers read these files concurrently
			tamper(f)
			f.mu.Unlock()
			dir := filepath.Join(t.TempDir(), "bin")
			out, err := runPowerShell(t, srv, dir)
			if err == nil {
				t.Fatalf("installed despite the problem:\n%s", out)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "lazy-chat.exe")); statErr == nil {
				t.Fatal("a program was installed anyway")
			}
		})
	}

	t.Run("bad version", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, "windows", arch)
		if out, err := runPowerShell(t, srv, t.TempDir(), "LAZYCHAT_VERSION=latest"); err == nil {
			t.Fatalf("accepted:\n%s", out)
		}
	})
}

// The firewall step must never break an installation: here the installed
// "program" cannot even run, and the install still succeeds.
func TestInstallPowerShellFirewallStepIsNeverFatal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("no powershell")
	}
	f := newFakeRelease(t, "v1.4.0", []byte("unused"))
	srv := serveInstallRelease(t, f, "windows", map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH])
	dir := t.TempDir()
	out, err := runPowerShell(t, srv, dir, "LAZYCHAT_NO_FIREWALL=")
	if err != nil {
		t.Fatalf("the install failed because of the firewall step: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Windows Firewall") || !strings.Contains(out, "Installed:") {
		t.Fatalf("output:\n%s", out)
	}
}
