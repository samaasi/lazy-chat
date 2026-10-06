package update

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// serveInstallRelease serves a release the way GitHub lays it out:
//
//	/latest                      redirects to /tag/<tag>
//	/download/<tag>/<file>       the assets
//	/key.pub                     the release public key
func serveInstallRelease(t *testing.T, f *fakeRelease, goos, goarch string) *httptest.Server {
	t.Helper()
	// Rebuild the archive for the platform the script will ask for.
	name := ArchiveName(f.tag, goos, goarch)
	if goos == "windows" {
		f.files[name] = zipOf(t, "lazy-chat.exe", []byte("MZ fake windows program "+f.tag))
	} else {
		f.files[name] = tarGz(t, "lazy-chat", []byte("#!/bin/sh\necho lazy-chat "+f.tag+"\n"))
	}
	f.resign()

	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/"+f.tag, http.StatusFound)
	})
	mux.HandleFunc("/tag/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/download/"+f.tag+"/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/download/"+f.tag+"/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	mux.HandleFunc("/key.pub", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runInstall(t *testing.T, srv *httptest.Server, dir string, extra ...string) (string, error) {
	t.Helper()
	script, _ := filepath.Abs("../../scripts/install.sh")
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(),
		"LAZYCHAT_BASE_URL="+srv.URL,
		"LAZYCHAT_KEY_URL="+srv.URL+"/key.pub",
		"LAZYCHAT_INSTALL_DIR="+dir,
	)
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func needShellTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"sh", "curl", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("install.sh targets macOS and Linux; install.ps1 is for Windows")
	}
}

func hostPlatform(t *testing.T) (goos, goarch string) {
	t.Helper()
	out, err := exec.Command("uname", "-sm").Output()
	if err != nil {
		t.Skip("no uname")
	}
	f := strings.Fields(string(out))
	goos = strings.ToLower(f[0])
	switch f[1] {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	default:
		t.Skip("unsupported CPU " + f[1])
	}
	return
}

func TestInstallScript(t *testing.T) {
	needShellTools(t)
	goos, goarch := hostPlatform(t)

	t.Run("installs after verifying checksum and signature", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, goos, goarch)
		dir := filepath.Join(t.TempDir(), "bin")
		out, err := runInstall(t, srv, dir)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if _, err := exec.LookPath("openssl"); err == nil && !strings.Contains(out, "Signature verified") {
			t.Fatalf("signature not checked although openssl exists:\n%s", out)
		}
		if !strings.Contains(out, "Checksum verified") {
			t.Fatalf("checksum not checked:\n%s", out)
		}
		got, err := exec.Command(filepath.Join(dir, "lazy-chat")).Output()
		if err != nil || !strings.Contains(string(got), "v1.4.0") {
			t.Fatalf("installed program: %q %v", got, err)
		}
		if leftovers, _ := filepath.Glob(filepath.Join(dir, ".lazy-chat.new.*")); len(leftovers) != 0 {
			t.Fatalf("left temp files: %v", leftovers)
		}
	})

	t.Run("pinned version", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, goos, goarch)
		out, err := runInstall(t, srv, t.TempDir(), "LAZYCHAT_VERSION=v1.4.0")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	})

	refusals := map[string]func(f *fakeRelease){
		"archive tampered": func(f *fakeRelease) {
			n := ArchiveName(f.tag, goos, goarch)
			f.files[n] = append(append([]byte(nil), f.files[n]...), 0)
		},
		"checksums tampered": func(f *fakeRelease) {
			f.files[checksumsName] = append(f.files[checksumsName], []byte("# x\n")...)
		},
		"wrong signer": func(f *fakeRelease) {
			f.files[signatureName] = sign(t, newKey(t), f.files[checksumsName])
		},
		"no checksum for this archive": func(f *fakeRelease) {
			f.files[checksumsName] = []byte("00  other.tar.gz\n")
			f.files[signatureName] = sign(t, f.key, f.files[checksumsName])
		},
	}
	for name, tamper := range refusals {
		t.Run("refuses: "+name, func(t *testing.T) {
			if _, err := exec.LookPath("openssl"); err != nil && (name == "checksums tampered" || name == "wrong signer") {
				t.Skip("signature checks need openssl")
			}
			f := newFakeRelease(t, "v1.4.0", []byte("unused"))
			srv := serveInstallRelease(t, f, goos, goarch)
			f.mu.Lock() // the server's handlers read these files concurrently
			tamper(f)
			f.mu.Unlock()
			dir := filepath.Join(t.TempDir(), "bin")
			out, err := runInstall(t, srv, dir)
			if err == nil {
				t.Fatalf("installed despite the problem:\n%s", out)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "lazy-chat")); statErr == nil {
				t.Fatal("a program was installed anyway")
			}
		})
	}

	t.Run("upgrade replaces the previous version", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, goos, goarch)
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "lazy-chat"), []byte("#!/bin/sh\necho old\n"), 0o755)
		if out, err := runInstall(t, srv, dir); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		got, _ := exec.Command(filepath.Join(dir, "lazy-chat")).Output()
		if !strings.Contains(string(got), "v1.4.0") {
			t.Fatalf("still the old version: %q", got)
		}
	})

	t.Run("bad inputs", func(t *testing.T) {
		f := newFakeRelease(t, "v1.4.0", []byte("unused"))
		srv := serveInstallRelease(t, f, goos, goarch)
		for _, v := range []string{"latest", "1.4.0", "v1.4", "v1.4.0; rm -rf /", "../../etc"} {
			if out, err := runInstall(t, srv, t.TempDir(), "LAZYCHAT_VERSION="+v); err == nil {
				t.Errorf("version %q accepted:\n%s", v, out)
			}
		}
		// A server that is down.
		srv.Close()
		if _, err := runInstall(t, srv, t.TempDir()); err == nil {
			t.Error("installed from a dead server")
		}
	})
}
