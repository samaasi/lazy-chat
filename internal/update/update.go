// Package update checks for new releases and installs them safely.
//
// Trust comes from one place: a signature over the release's checksums file,
// made in CI with a private key that never leaves it, verified here against a
// public key compiled into the binary. The download host, the GitHub API and
// the network in between are therefore untrusted: a tampered archive fails its
// checksum, and a tampered checksum list fails its signature. The program only
// ever updates when the user asks; it merely tells them one is available.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository releases are published to.
const DefaultRepo = "samaasi/lazy-chat"

const (
	checksumsName = "checksums.txt"
	signatureName = "checksums.txt.sig"

	maxAPIBody      = 1 << 20
	maxChecksumBody = 1 << 20
	maxSigBody      = 8 << 10
	maxArchive      = 100 << 20
	maxBinary       = 200 << 20
)

// Release is a published version and the files attached to it.
type Release struct {
	Version string // as tagged, e.g. v1.2.3
	Notes   string
	URL     string // human-readable release page
	assets  map[string]string
}

// Updater finds and installs releases. Use New for the official repository.
type Updater struct {
	Repo    string // owner/name
	Current string // version running now
	APIBase string // https://api.github.com
	Client  *http.Client
	Key     *ecdsa.PublicKey

	GOOS, GOARCH string

	// Probe runs the downloaded binary to make sure it starts and reports the
	// expected version before it replaces the current one. Nil uses the real one.
	Probe func(ctx context.Context, binary, want string) error
	// AllowInsecure permits plain http, for tests against a local server.
	AllowInsecure bool
}

// New returns an Updater for the official repository using the embedded key.
//
// If this build has no usable release key the Updater can still look for new
// versions but refuses to install any (Fetch fails closed with ErrNoReleaseKey).
func New(current string) *Updater {
	key, _ := ReleaseKey()
	return &Updater{
		Repo: DefaultRepo, Current: current, APIBase: "https://api.github.com",
		Client: &http.Client{Timeout: 5 * time.Minute}, Key: key,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
}

type apiRelease struct {
	Tag        string `json:"tag_name"`
	Body       string `json:"body"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (u *Updater) checkURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("bad URL %q", raw)
	}
	if parsed.Scheme != "https" && !(u.AllowInsecure && parsed.Scheme == "http") {
		return fmt.Errorf("refusing non-HTTPS URL %q", raw)
	}
	return nil
}

func (u *Updater) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	if err := u.checkURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lazy-chat-updater")
	req.Header.Set("Accept", "application/octet-stream, application/vnd.github+json")
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && strings.HasSuffix(rawURL, "/releases/latest") {
		return nil, errors.New("no release has been published yet")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: larger than the %d byte limit", rawURL, limit)
	}
	return body, nil
}

// Latest returns the newest published (non-draft, non-prerelease) release.
func (u *Updater) Latest(ctx context.Context) (*Release, error) {
	body, err := u.get(ctx, strings.TrimSuffix(u.APIBase, "/")+"/repos/"+u.Repo+"/releases/latest", maxAPIBody)
	if err != nil {
		return nil, fmt.Errorf("could not look up the latest release: %w", err)
	}
	var r apiRelease
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unreadable release information: %w", err)
	}
	if r.Draft || r.Prerelease {
		return nil, errors.New("the latest release is not a stable release")
	}
	if _, err := parseVersion(r.Tag); err != nil {
		return nil, fmt.Errorf("the latest release has an unusable tag: %w", err)
	}
	rel := &Release{Version: r.Tag, Notes: r.Body, URL: r.HTMLURL, assets: map[string]string{}}
	for _, a := range r.Assets {
		rel.assets[a.Name] = a.URL
	}
	return rel, nil
}

// Check returns the latest release if it is newer than the running version, or
// nil if this version is current (or newer, as for a development build).
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	rel, err := u.Latest(ctx)
	if err != nil {
		return nil, err
	}
	newer, err := Newer(rel.Version, u.Current)
	if err != nil {
		return nil, fmt.Errorf("cannot compare %q with %q: %w", rel.Version, u.Current, err)
	}
	if !newer {
		return nil, nil
	}
	return rel, nil
}

// ArchiveName is the release asset for a platform, e.g. lazy-chat_1.2.3_linux_arm64.tar.gz.
func ArchiveName(tag, goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return "lazy-chat_" + strings.TrimPrefix(tag, "v") + "_" + goos + "_" + goarch + ext
}

// BinaryName is the executable's file name on a platform.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "lazy-chat.exe"
	}
	return "lazy-chat"
}

// VerifySignature checks that sig (base64, as written by `cosign sign-blob`)
// is a valid signature of blob by key.
func VerifySignature(key *ecdsa.PublicKey, blob, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return errors.New("the release signature is not valid base64")
	}
	digest := sha256.Sum256(blob)
	if !ecdsa.VerifyASN1(key, digest[:], raw) {
		return errors.New("the release signature does not match: refusing to trust this release")
	}
	return nil
}

// checksumFor finds name's SHA-256 in a `sha256sum`-style list.
func checksumFor(list []byte, name string) ([]byte, error) {
	for _, line := range strings.Split(string(list), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			sum, err := hex.DecodeString(f[0])
			if err != nil || len(sum) != sha256.Size {
				return nil, fmt.Errorf("malformed checksum for %s", name)
			}
			return sum, nil
		}
	}
	return nil, fmt.Errorf("the release lists no checksum for %s", name)
}

// Fetch downloads rel's archive for this platform, verifies the signed
// checksums and the archive against them, and extracts the executable into
// dir. It returns the path of the extracted, verified file. Nothing existing in
// dir is touched.
func (u *Updater) Fetch(ctx context.Context, rel *Release, dir string) (string, error) {
	if u.Key == nil {
		return "", ErrNoReleaseKey
	}
	archiveName := ArchiveName(rel.Version, u.GOOS, u.GOARCH)
	archiveURL, ok := rel.assets[archiveName]
	if !ok {
		return "", fmt.Errorf("release %s has no build for %s/%s", rel.Version, u.GOOS, u.GOARCH)
	}
	sumsURL, sigURL := rel.assets[checksumsName], rel.assets[signatureName]
	if sumsURL == "" || sigURL == "" {
		return "", fmt.Errorf("release %s is not signed (missing %s or %s)", rel.Version, checksumsName, signatureName)
	}

	sums, err := u.get(ctx, sumsURL, maxChecksumBody)
	if err != nil {
		return "", err
	}
	sig, err := u.get(ctx, sigURL, maxSigBody)
	if err != nil {
		return "", err
	}
	if err := VerifySignature(u.Key, sums, sig); err != nil {
		return "", err
	}
	want, err := checksumFor(sums, archiveName)
	if err != nil {
		return "", err
	}

	archive, err := u.get(ctx, archiveURL, maxArchive)
	if err != nil {
		return "", err
	}
	if got := sha256.Sum256(archive); !bytes.Equal(got[:], want) {
		return "", fmt.Errorf("%s does not match its signed checksum: refusing to install", archiveName)
	}

	bin, err := extract(archive, archiveName, BinaryName(u.GOOS))
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".lazy-chat-update-*")
	if err != nil {
		return "", permissionHint(dir, err)
	}
	name := f.Name()
	_, werr := f.Write(bin)
	cerr := f.Close()
	if err := errors.Join(werr, cerr, os.Chmod(name, 0o755)); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// extract pulls the named executable out of a tar.gz or zip archive. Only a
// regular file with exactly that base name is considered, wherever it sits.
func extract(archive []byte, archiveName, binary string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("unreadable archive: %w", err)
		}
		for _, zf := range zr.File {
			if zf.FileInfo().Mode().IsRegular() && path.Base(zf.Name) == binary {
				rc, err := zf.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return readCapped(rc)
			}
		}
		return nil, fmt.Errorf("%s is not in the archive", binary)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("unreadable archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s is not in the archive", binary)
		}
		if err != nil {
			return nil, fmt.Errorf("unreadable archive: %w", err)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == binary {
			return readCapped(tr)
		}
	}
}

func readCapped(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBinary+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBinary {
		return nil, errors.New("the executable in the archive is implausibly large")
	}
	if len(b) == 0 {
		return nil, errors.New("the executable in the archive is empty")
	}
	return b, nil
}

// execProbe runs `binary --version` and expects it to name the wanted version.
func execProbe(ctx context.Context, binary, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("the downloaded program does not run on this system: %w", err)
	}
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("the downloaded program reports %q, expected %s", strings.TrimSpace(string(out)), want)
	}
	return nil
}

// Install downloads, verifies and swaps in rel, replacing the executable at
// exe. The running process is unaffected; the new version is used next start.
func (u *Updater) Install(ctx context.Context, rel *Release, exe string) error {
	newer, err := Newer(rel.Version, u.Current)
	if err != nil {
		return err
	}
	if !newer {
		return fmt.Errorf("%s is not newer than %s: refusing to downgrade", rel.Version, u.Current)
	}
	// Stage next to the target so the final rename stays on one filesystem.
	staged, err := u.Fetch(ctx, rel, filepath.Dir(exe))
	if err != nil {
		return err
	}
	defer os.Remove(staged) // a no-op once it has been moved into place
	probe := u.Probe
	if probe == nil {
		probe = execProbe
	}
	if err := probe(ctx, staged, strings.TrimPrefix(rel.Version, "v")); err != nil {
		return err
	}
	return Replace(exe, staged)
}
