package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var bg = context.Background()

func TestVersionOrdering(t *testing.T) {
	order := []string{"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta", "v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0", "v10.0.0"}
	for i, a := range order {
		for j, b := range order {
			got, err := Newer(a, b)
			if err != nil {
				t.Fatal(err)
			}
			if want := i > j; got != want {
				t.Errorf("Newer(%s, %s) = %v, want %v", a, b, got, want)
			}
		}
	}
	if n, _ := Newer("1.2.3", "v1.2.3+build5"); n {
		t.Error("build metadata must not matter")
	}
	for _, bad := range []string{"", "dev", "v1", "v1.2", "v1.2.3.4", "v1.2.x", "v01.2.3", "v1.2.3-", "v-1.2.3"} {
		if _, err := Newer(bad, "v1.0.0"); err == nil {
			t.Errorf("%q was accepted as a version", bad)
		}
	}
}

// ---- A fake release server ---------------------------------------------------

type fakeRelease struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	tag    string
	files  map[string][]byte
	latest apiRelease
	srv    *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, key *ecdsa.PrivateKey, blob []byte) []byte {
	t.Helper()
	d := sha256.Sum256(blob)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(sig))
}

func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "README.md", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func zipOf(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(name)
	_, _ = w.Write(content)
	_ = zw.Close()
	return buf.Bytes()
}

// newFakeRelease publishes `tag` for this platform with a binary whose
// contents are `payload`, signed with a fresh key.
func newFakeRelease(t *testing.T, tag string, payload []byte) *fakeRelease {
	t.Helper()
	f := &fakeRelease{t: t, key: newKey(t), tag: tag, files: map[string][]byte{}, hits: map[string]int{}}
	name := ArchiveName(tag, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		f.files[name] = zipOf(t, "lazy-chat_x/"+BinaryName(runtime.GOOS), payload)
	} else {
		f.files[name] = tarGz(t, "lazy-chat_x/"+BinaryName(runtime.GOOS), payload)
	}
	f.resign()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+DefaultRepo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		l := f.latest
		l.Tag = f.tag
		for n := range f.files {
			l.Assets = append(l.Assets, struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			}{n, f.srv.URL + "/dl/" + n})
		}
		_ = json.NewEncoder(w).Encode(l)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := strings.TrimPrefix(r.URL.Path, "/dl/")
		f.hits[n]++
		b, ok := f.files[n]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// resign rewrites checksums.txt and its signature from the current files.
func (f *fakeRelease) resign() {
	var sums strings.Builder
	for n, b := range f.files {
		if n == checksumsName || n == signatureName {
			continue
		}
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	f.files[checksumsName] = []byte(sums.String())
	f.files[signatureName] = sign(f.t, f.key, f.files[checksumsName])
}

func (f *fakeRelease) updater(current string) *Updater {
	return &Updater{
		Repo: DefaultRepo, Current: current, APIBase: f.srv.URL, Client: f.srv.Client(), Key: &f.key.PublicKey,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, AllowInsecure: true,
		Probe: func(context.Context, string, string) error { return nil },
	}
}

func installedExe(t *testing.T, content string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), BinaryName(runtime.GOOS))
	if err := os.WriteFile(exe, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func leftovers(t *testing.T, exe string) []string {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(exe))
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lazy-chat-update-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// ---- Checking --------------------------------------------------------------------

func TestCheck(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("new"))
	for _, tc := range []struct {
		current string
		newer   bool
	}{{"v1.3.9", true}, {"v1.4.0", false}, {"v1.5.0", false}, {"v1.4.0-rc.1", true}} {
		rel, err := f.updater(tc.current).Check(bg)
		if err != nil || (rel != nil) != tc.newer {
			t.Errorf("current %s: %v %v", tc.current, rel, err)
		}
	}
	// A development build is never "out of date" by accident.
	if _, err := f.updater("dev").Check(bg); err == nil {
		t.Log("dev builds cannot be compared") // reported as an error the caller skips
	}
}

func TestPrereleasesAndDraftsAreNotOffered(t *testing.T) {
	f := newFakeRelease(t, "v2.0.0", []byte("x"))
	f.latest.Prerelease = true
	if _, err := f.updater("v1.0.0").Check(bg); err == nil {
		t.Fatal("a prerelease was offered")
	}
	f.latest = apiRelease{Draft: true}
	if _, err := f.updater("v1.0.0").Check(bg); err == nil {
		t.Fatal("a draft was offered")
	}
	f.latest = apiRelease{}
	f.tag = "not-a-version"
	if _, err := f.updater("v1.0.0").Check(bg); err == nil {
		t.Fatal("a release with a junk tag was accepted")
	}
}

// ---- Installing ---------------------------------------------------------------------

func TestInstallReplacesTheExecutable(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("NEW BINARY"))
	exe := installedExe(t, "OLD BINARY")
	u := f.updater("v1.3.0")
	var probed string
	u.Probe = func(_ context.Context, bin, want string) error {
		probed = want
		if read(t, bin) != "NEW BINARY" {
			t.Error("probe saw something other than the verified binary")
		}
		return nil
	}
	rel, err := u.Check(bg)
	if err != nil || rel == nil {
		t.Fatal(rel, err)
	}
	if err := u.Install(bg, rel, exe); err != nil {
		t.Fatal(err)
	}
	if read(t, exe) != "NEW BINARY" {
		t.Fatal("executable not replaced")
	}
	if probed != "1.4.0" {
		t.Fatalf("probed for %q", probed)
	}
	if l := leftovers(t, exe); len(l) != 0 {
		t.Fatalf("staging files left behind: %v", l)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(exe); fi.Mode().Perm()&0o111 == 0 {
			t.Fatal("the new executable is not executable")
		}
	}
	CleanupOld(exe)
	if _, err := os.Stat(exe + oldSuffix); !os.IsNotExist(err) {
		t.Fatal("the old executable was not cleaned up")
	}
}

func TestInstallRefusesAnythingThatIsNotAuthentic(t *testing.T) {
	attacks := map[string]func(f *fakeRelease){
		"archive swapped after signing": func(f *fakeRelease) {
			n := ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)
			f.files[n] = append(append([]byte(nil), f.files[n]...), 0)
		},
		"checksums edited after signing": func(f *fakeRelease) {
			f.files[checksumsName] = append(f.files[checksumsName], []byte("# edited\n")...)
		},
		"signed by someone else": func(f *fakeRelease) {
			f.files[signatureName] = sign(t, newKey(t), f.files[checksumsName])
		},
		"garbage signature": func(f *fakeRelease) { f.files[signatureName] = []byte("!!!not base64!!!") },
		"empty signature":   func(f *fakeRelease) { f.files[signatureName] = nil },
		"signature missing": func(f *fakeRelease) { delete(f.files, signatureName) },
		"checksums missing": func(f *fakeRelease) { delete(f.files, checksumsName) },
		"no checksum for this platform": func(f *fakeRelease) {
			f.files[checksumsName] = []byte("00  other_file.tar.gz\n")
			f.files[signatureName] = sign(t, f.key, f.files[checksumsName])
		},
		"malformed checksum": func(f *fakeRelease) {
			n := ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)
			f.files[checksumsName] = []byte("zz  " + n + "\n")
			f.files[signatureName] = sign(t, f.key, f.files[checksumsName])
		},
		"no build for this platform": func(f *fakeRelease) { delete(f.files, ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)) },
		"archive without the program": func(f *fakeRelease) {
			n := ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)
			if strings.HasSuffix(n, ".zip") {
				f.files[n] = zipOf(t, "something-else.exe", []byte("x"))
			} else {
				f.files[n] = tarGz(t, "something-else", []byte("x"))
			}
			f.resign() // authentic, but not what it claims to be
		},
		"empty program": func(f *fakeRelease) {
			n := ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)
			if strings.HasSuffix(n, ".zip") {
				f.files[n] = zipOf(t, BinaryName(runtime.GOOS), nil)
			} else {
				f.files[n] = tarGz(t, BinaryName(runtime.GOOS), nil)
			}
			f.resign()
		},
		"not an archive": func(f *fakeRelease) {
			f.files[ArchiveName(f.tag, runtime.GOOS, runtime.GOARCH)] = []byte("plain text")
			f.resign()
		},
	}
	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			f := newFakeRelease(t, "v1.4.0", []byte("EVIL"))
			attack(f)
			exe := installedExe(t, "OLD BINARY")
			u := f.updater("v1.3.0")
			rel, err := u.Latest(bg)
			if err != nil {
				t.Fatal(err)
			}
			if err := u.Install(bg, rel, exe); err == nil {
				t.Fatal("the update was installed")
			}
			if read(t, exe) != "OLD BINARY" {
				t.Fatal("the existing executable was modified")
			}
			if l := leftovers(t, exe); len(l) != 0 {
				t.Fatalf("staging files left behind: %v", l)
			}
		})
	}
}

func TestInstallFailsClosedWithoutAKey(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("x"))
	u := f.updater("v1.3.0")
	u.Key = nil
	rel, _ := u.Latest(bg)
	exe := installedExe(t, "OLD")
	if err := u.Install(bg, rel, exe); !errors.Is(err, ErrNoReleaseKey) {
		t.Fatalf("got %v", err)
	}
	if _, err := ReleaseKey(); !errors.Is(err, ErrNoReleaseKey) {
		t.Skipf("a real release key is embedded: %v", err)
	}
}

func TestInstallRefusesDowngradeAndSameVersion(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("x"))
	exe := installedExe(t, "OLD")
	for _, cur := range []string{"v1.4.0", "v2.0.0"} {
		u := f.updater(cur)
		rel, _ := u.Latest(bg)
		if err := u.Install(bg, rel, exe); err == nil {
			t.Fatalf("installed v1.4.0 over %s", cur)
		}
	}
	if read(t, exe) != "OLD" {
		t.Fatal("modified")
	}
}

func TestFailedProbeKeepsTheOldVersion(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("won't run"))
	u := f.updater("v1.3.0")
	u.Probe = func(context.Context, string, string) error { return errors.New("exec format error") }
	exe := installedExe(t, "OLD")
	rel, _ := u.Latest(bg)
	if err := u.Install(bg, rel, exe); err == nil || !strings.Contains(err.Error(), "exec format") {
		t.Fatalf("got %v", err)
	}
	if read(t, exe) != "OLD" || len(leftovers(t, exe)) != 0 {
		t.Fatal("a program that does not run replaced the working one, or left debris")
	}
}

func TestOnlyHTTPSIsAcceptedInProduction(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("x"))
	u := f.updater("v1.3.0")
	u.AllowInsecure = false
	if _, err := u.Latest(bg); err == nil {
		t.Fatal("plain http accepted")
	}
	// A release that points its assets at an http:// URL is refused too.
	u.AllowInsecure = true
	rel, _ := u.Latest(bg)
	u.AllowInsecure = false
	rel.assets = map[string]string{ArchiveName("v1.4.0", runtime.GOOS, runtime.GOARCH): "http://example.invalid/x"}
	if _, err := u.Fetch(bg, rel, t.TempDir()); err == nil {
		t.Fatal("http asset accepted")
	}
}

func TestOversizedResponsesAreRejected(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("x"))
	u := f.updater("v1.3.0")
	rel, _ := u.Latest(bg)
	f.files[signatureName] = bytes.Repeat([]byte("A"), maxSigBody+10)
	if _, err := u.Fetch(bg, rel, t.TempDir()); err == nil {
		t.Fatal("an oversized signature was read")
	}
}

func TestReplaceRestoresOnFailure(t *testing.T) {
	exe := installedExe(t, "OLD")
	if err := Replace(exe, filepath.Join(filepath.Dir(exe), "does-not-exist")); err == nil {
		t.Fatal("replaced with a file that is not there")
	}
	if read(t, exe) != "OLD" {
		t.Fatal("the original is gone after a failed replace")
	}
}

func TestPublicKeyParsing(t *testing.T) {
	k := newKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := ParsePublicKey(pemBytes)
	if err != nil || !got.Equal(&k.PublicKey) {
		t.Fatalf("round trip: %v", err)
	}
	for name, bad := range map[string][]byte{"placeholder": []byte("NO RELEASE KEY YET"), "empty": nil, "wrong type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "garbage der": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384})); err == nil {
		t.Error("a P-384 key was accepted")
	}
}

func TestManagedBy(t *testing.T) {
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", filepath.Join(t.TempDir(), "gopath"))
	cases := map[string]string{
		"/opt/homebrew/Cellar/lazy-chat/1.0/bin/lazy-chat":      "Homebrew",
		"/usr/local/Cellar/lazy-chat/1.0/bin/lazy-chat":         "Homebrew",
		"/home/u/.linuxbrew/bin/lazy-chat":                      "Homebrew",
		"C:/Users/u/scoop/apps/lazy-chat/current/lazy-chat.exe": "Scoop",
		"/usr/local/bin/lazy-chat":                              "",
		"/home/u/bin/lazy-chat":                                 "",
	}
	for p, want := range cases {
		if got, cmd := ManagedBy(p); got != want || (want != "" && cmd == "") {
			t.Errorf("%s: %q %q", p, got, cmd)
		}
	}
	gp := os.Getenv("GOPATH")
	if got, _ := ManagedBy(filepath.Join(gp, "bin", "lazy-chat")); got != "go install" {
		t.Errorf("GOPATH/bin not recognised: %q", got)
	}
}

// The real probe really runs the downloaded program.
func TestRealProbeRunsTheDownloadedProgram(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	_ = os.WriteFile(src, []byte("package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"lazy-chat v9.9.9\") }\n"), 0o644)
	bin := filepath.Join(dir, "probe"+map[bool]string{true: ".exe", false: ""}[runtime.GOOS == "windows"])
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := execProbe(bg, bin, "9.9.9"); err != nil {
		t.Fatal(err)
	}
	if err := execProbe(bg, bin, "1.0.0"); err == nil {
		t.Fatal("a program reporting another version passed the probe")
	}
	notExe := filepath.Join(dir, "junk")
	_ = os.WriteFile(notExe, []byte("not a program"), 0o755)
	if err := execProbe(bg, notExe, "9.9.9"); err == nil {
		t.Fatal("something that is not a program passed the probe")
	}
}

// Full path with the real probe: install a genuinely different program.
func TestInstallEndToEndWithARealProgram(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain")
	}
	dir := t.TempDir()
	build := func(version, out string) {
		src := filepath.Join(dir, version+".go")
		_ = os.WriteFile(src, []byte("package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"lazy-chat "+version+"\") }\n"), 0o644)
		if b, err := exec.Command("go", "build", "-o", out, src).CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
	}
	ext := map[bool]string{true: ".exe", false: ""}[runtime.GOOS == "windows"]
	oldBin, newBin := filepath.Join(dir, "old"+ext), filepath.Join(dir, "new"+ext)
	build("v1.0.0", oldBin)
	build("v1.1.0", newBin)
	payload, _ := os.ReadFile(newBin)

	f := newFakeRelease(t, "v1.1.0", payload)
	u := f.updater("v1.0.0")
	u.Probe = nil // the real one
	rel, _ := u.Latest(bg)
	exe := filepath.Join(dir, "lazy-chat"+ext)
	old, _ := os.ReadFile(oldBin)
	_ = os.WriteFile(exe, old, 0o755)
	if err := u.Install(bg, rel, exe); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(exe, "--version").Output()
	if err != nil || !strings.Contains(string(out), "v1.1.0") {
		t.Fatalf("after the update the program says %q (%v)", out, err)
	}
}

func TestStartupCheckIsCachedAndNeverFails(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("x"))
	state := filepath.Join(t.TempDir(), "sub", "update-check.json")
	now := time.Now()
	u := f.updater("v1.3.0")

	if got := u.Available(bg, state, CheckInterval, now); got != "v1.4.0" {
		t.Fatalf("got %q", got)
	}
	// Within the interval the answer comes from the cache: no second request.
	f.mu.Lock()
	f.srv.Config.Handler = http.NotFoundHandler()
	f.mu.Unlock()
	if got := u.Available(bg, state, CheckInterval, now.Add(time.Hour)); got != "v1.4.0" {
		t.Fatalf("cached: %q", got)
	}
	// After upgrading, the cache no longer claims an update.
	u.Current = "v1.4.0"
	if got := u.Available(bg, state, CheckInterval, now.Add(time.Hour)); got != "" {
		t.Fatalf("after upgrade: %q", got)
	}
	// Past the interval it asks again, and a failure is silent.
	u.Current = "v1.3.0"
	if got := u.Available(bg, state, CheckInterval, now.Add(48*time.Hour)); got != "" {
		t.Fatalf("failed check: %q", got)
	}
	// Development builds and a clock that went backwards do not misbehave.
	dev := f.updater("dev")
	if got := dev.Available(bg, state, CheckInterval, now); got != "" {
		t.Fatalf("dev: %q", got)
	}
	_ = os.WriteFile(state, []byte("{not json"), 0o600)
	if got := u.Available(bg, state, CheckInterval, now); got != "" {
		t.Fatalf("corrupt state: %q", got)
	}
}

func runCommand(t *testing.T, u *Updater, exe string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = Command(bg, args, &o, &e, u, exe)
	return code, o.String(), e.String()
}

func TestUpdateCommand(t *testing.T) {
	f := newFakeRelease(t, "v1.4.0", []byte("NEW"))

	t.Run("check only", func(t *testing.T) {
		exe := installedExe(t, "OLD")
		code, out, _ := runCommand(t, f.updater("v1.3.0"), exe, "--check")
		if code != 0 || !strings.Contains(out, "v1.4.0") || read(t, exe) != "OLD" {
			t.Fatalf("%d %q %q", code, out, read(t, exe))
		}
	})
	t.Run("up to date", func(t *testing.T) {
		exe := installedExe(t, "OLD")
		code, out, _ := runCommand(t, f.updater("v1.4.0"), exe)
		if code != 0 || !strings.Contains(out, "up to date") {
			t.Fatalf("%d %q", code, out)
		}
	})
	t.Run("installs", func(t *testing.T) {
		exe := installedExe(t, "OLD")
		code, out, e := runCommand(t, f.updater("v1.3.0"), exe)
		if code != 0 || read(t, exe) != "NEW" || !strings.Contains(out, "Updated to v1.4.0") {
			t.Fatalf("%d %q %q", code, out, e)
		}
	})
	t.Run("refuses a development build", func(t *testing.T) {
		code, _, e := runCommand(t, f.updater("dev"), installedExe(t, "OLD"))
		if code == 0 || !strings.Contains(e, "development build") {
			t.Fatalf("%d %q", code, e)
		}
	})
	t.Run("leaves package-managed installs alone", func(t *testing.T) {
		exe := filepath.Join(t.TempDir(), "Cellar", "lazy-chat", BinaryName(runtime.GOOS))
		_ = os.MkdirAll(filepath.Dir(exe), 0o755)
		_ = os.WriteFile(exe, []byte("OLD"), 0o755)
		code, _, e := runCommand(t, f.updater("v1.3.0"), exe)
		if code == 0 || !strings.Contains(e, "brew upgrade lazy-chat") || read(t, exe) != "OLD" {
			t.Fatalf("%d %q", code, e)
		}
		if code, _, _ := runCommand(t, f.updater("v1.3.0"), exe, "--force"); code != 0 || read(t, exe) != "NEW" {
			t.Fatal("--force did not update")
		}
	})
	t.Run("fails closed without a key", func(t *testing.T) {
		u := f.updater("v1.3.0")
		u.Key = nil
		exe := installedExe(t, "OLD")
		code, _, e := runCommand(t, u, exe)
		if code == 0 || !strings.Contains(e, "release signing key") || read(t, exe) != "OLD" {
			t.Fatalf("%d %q", code, e)
		}
	})
	t.Run("reports a failed install and keeps the old one", func(t *testing.T) {
		g := newFakeRelease(t, "v1.4.0", []byte("EVIL"))
		g.files[checksumsName] = append(g.files[checksumsName], 'x')
		exe := installedExe(t, "OLD")
		code, _, e := runCommand(t, g.updater("v1.3.0"), exe)
		if code == 0 || !strings.Contains(e, "was not changed") || read(t, exe) != "OLD" {
			t.Fatalf("%d %q", code, e)
		}
	})
	t.Run("bad arguments", func(t *testing.T) {
		if code, _, _ := runCommand(t, f.updater("v1.3.0"), installedExe(t, "OLD"), "extra"); code != 2 {
			t.Fatalf("code %d", code)
		}
		if code, _, _ := runCommand(t, f.updater("v1.3.0"), installedExe(t, "OLD"), "--nope"); code != 2 {
			t.Fatalf("code %d", code)
		}
	})
}

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"v1.2.3": true, "1.2.3": true, "v1.2.3-rc.1": true,
		"dev": false, "": false, "(devel)": false,
		"v0.0.0-20261006101153-4111c3257cf9":       false,
		"v0.0.0-20261006101153-4111c3257cf9+dirty": false,
		"v1.2.4-0.20261006101153-4111c3257cf9":     false,
		"v1.2.3+dirty":                             false,
	} {
		if got := IsRelease(v); got != want {
			t.Errorf("IsRelease(%q) = %v", v, got)
		}
	}
}
