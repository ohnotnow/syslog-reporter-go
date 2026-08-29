package selfupdate

// Tests drive runSelfUpdate against an httptest stand-in for the GitHub
// API, a temp file standing in for the running binary, and an injected
// platform tuple.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRelease stands up an httptest server that mimics enough of the
// GitHub API surface for self-update: the /releases/latest JSON, the
// binary asset, and the SHA256SUMS asset.
type fakeRelease struct {
	srv *httptest.Server
}

func newFakeRelease(t *testing.T, tag, assetName string, assetBytes []byte, badChecksum bool) *fakeRelease {
	t.Helper()
	mux := http.NewServeMux()

	sum := sha256.Sum256(assetBytes)
	hexSum := hex.EncodeToString(sum[:])
	if badChecksum {
		hexSum = strings.Repeat("0", 64)
	}
	sums := fmt.Sprintf("%s  %s\n", hexSum, assetName)

	fr := &fakeRelease{}

	mux.HandleFunc("/asset/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		w.Write(assetBytes)
	})
	mux.HandleFunc("/asset/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sums))
	})

	fr.srv = httptest.NewServer(mux)

	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		body := ghRelease{
			TagName: tag,
			Body:    "release notes",
			Assets: []ghAsset{
				{Name: assetName, URL: fr.srv.URL + "/asset/" + assetName},
				{Name: "SHA256SUMS", URL: fr.srv.URL + "/asset/SHA256SUMS"},
			},
		}
		json.NewEncoder(w).Encode(body)
	})

	t.Cleanup(fr.srv.Close)
	return fr
}

func seedTarget(t *testing.T, content []byte) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "syslog-reporter")
	if err := os.WriteFile(target, content, 0o755); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return target
}

// The first safety property: a bad checksum refuses the update AND leaves
// the on-disk binary byte-identical.
func TestSelfUpdateChecksumMismatchRefuses(t *testing.T) {
	original := []byte("original binary")
	target := seedTarget(t, original)
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-linux-amd64", []byte("payload"), true)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdout:         &out,
		currentVersion: "v0.1.0",
		assumeYes:      true,
	})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got code=%d err=%v", code, err)
	}
	if code == 0 {
		t.Error("checksum mismatch must not exit 0")
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, original) {
		t.Errorf("target modified despite checksum failure: %q", got)
	}
}

func TestSelfUpdateHappyPath(t *testing.T) {
	target := seedTarget(t, []byte("old binary"))
	newBinary := []byte("new binary content")
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-linux-amd64", newBinary, false)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdout:         &out,
		currentVersion: "v0.1.0",
		assumeYes:      true,
	})
	if err != nil || code != 0 {
		t.Fatalf("runSelfUpdate: code=%d err=%v\nstdout=%q", code, err, out.String())
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, newBinary) {
		t.Errorf("binary not replaced: got %q", got)
	}
	if !strings.Contains(out.String(), "Updated to v9.9.9") {
		t.Errorf("expected confirmation, got %q", out.String())
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("mode = %o, want 0755", info.Mode().Perm())
		}
	}
}

func TestSelfUpdateAlreadyLatest(t *testing.T) {
	original := []byte("original")
	target := seedTarget(t, original)
	fr := newFakeRelease(t, "v0.1.0", "syslog-reporter-linux-amd64", []byte("unused"), false)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdout:         &out,
		currentVersion: "v0.1.0",
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, original) {
		t.Errorf("target modified despite being up to date: %q", got)
	}
	if !strings.Contains(out.String(), "Already up to date") {
		t.Errorf("expected up-to-date message, got %q", out.String())
	}
}

func TestSelfUpdateDevBuildRefusesWithoutNetwork(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(500)
	}))
	defer srv.Close()

	original := []byte("dev binary")
	target := seedTarget(t, original)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         srv.URL,
		httpClient:     srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdout:         &out,
		currentVersion: "dev",
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if hits != 0 {
		t.Errorf("dev build made %d HTTP requests; expected 0", hits)
	}
	if !strings.Contains(out.String(), "dev build") {
		t.Errorf("expected dev-build message, got %q", out.String())
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, original) {
		t.Errorf("dev binary was modified: %q", got)
	}
}

func TestSelfUpdateUnwriteableDirFailsBeforeDownload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("0555 permissions are not enforced on Windows the same way")
	}

	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	target := filepath.Join(locked, "syslog-reporter")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}

	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		hits++
		json.NewEncoder(w).Encode(ghRelease{
			TagName: "v9.9.9",
			Assets: []ghAsset{
				{Name: "syslog-reporter-linux-amd64", URL: "http://example.invalid/never-hit"},
				{Name: "SHA256SUMS", URL: "http://example.invalid/never-hit"},
			},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(500)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         srv.URL + "/releases/latest",
		httpClient:     srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdout:         &out,
		currentVersion: "v0.1.0",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("expected cannot-write error, got code=%d err=%v", code, err)
	}
	if hits != 1 {
		t.Errorf("got %d HTTP hits; expected exactly 1 (the release lookup)", hits)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Errorf("target was modified: %q", got)
	}
}

func TestSelfUpdateCheckExitCodes(t *testing.T) {
	t.Run("up to date exits 0", func(t *testing.T) {
		fr := newFakeRelease(t, "v0.1.0", "syslog-reporter-linux-amd64", []byte("x"), false)
		var out bytes.Buffer
		code, err := runSelfUpdate(selfUpdateConfig{
			apiURL:         fr.srv.URL + "/releases/latest",
			httpClient:     fr.srv.Client(),
			targetPath:     filepath.Join(t.TempDir(), "syslog-reporter"),
			osName:         "linux",
			arch:           "amd64",
			stdout:         &out,
			currentVersion: "v0.1.0",
			checkOnly:      true,
		})
		if err != nil || code != 0 {
			t.Fatalf("code=%d err=%v", code, err)
		}
		if !strings.Contains(out.String(), "up to date") {
			t.Errorf("expected up-to-date output, got %q", out.String())
		}
	})

	t.Run("newer available exits 1 without downloading", func(t *testing.T) {
		fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-linux-amd64", []byte("payload"), false)
		dir := t.TempDir()
		var out bytes.Buffer
		code, err := runSelfUpdate(selfUpdateConfig{
			apiURL:         fr.srv.URL + "/releases/latest",
			httpClient:     fr.srv.Client(),
			targetPath:     filepath.Join(dir, "syslog-reporter"),
			osName:         "linux",
			arch:           "amd64",
			stdout:         &out,
			currentVersion: "v0.1.0",
			checkOnly:      true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != 1 {
			t.Errorf("code = %d, want 1", code)
		}
		if !strings.Contains(out.String(), "v9.9.9 is available") {
			t.Errorf("expected available-version output, got %q", out.String())
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("expected empty target dir under --check, got %v", entries)
		}
	})

	t.Run("lookup failure exits 2", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
		}))
		defer srv.Close()
		var out bytes.Buffer
		code, err := runSelfUpdate(selfUpdateConfig{
			apiURL:         srv.URL,
			httpClient:     srv.Client(),
			targetPath:     filepath.Join(t.TempDir(), "syslog-reporter"),
			osName:         "linux",
			arch:           "amd64",
			stdout:         &out,
			currentVersion: "v0.1.0",
			checkOnly:      true,
		})
		if err == nil {
			t.Fatal("expected lookup failure")
		}
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
	})
}

func TestSelfUpdatePromptDefaultDeclines(t *testing.T) {
	original := []byte("old")
	target := seedTarget(t, original)
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-linux-amd64", []byte("new"), false)

	for name, input := range map[string]string{"n": "n\n", "empty": "\n", "eof": ""} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			code, err := runSelfUpdate(selfUpdateConfig{
				apiURL:         fr.srv.URL + "/releases/latest",
				httpClient:     fr.srv.Client(),
				targetPath:     target,
				osName:         "linux",
				arch:           "amd64",
				stdin:          strings.NewReader(input),
				stdout:         &out,
				currentVersion: "v0.1.0",
			})
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			got, _ := os.ReadFile(target)
			if !bytes.Equal(got, original) {
				t.Errorf("binary modified despite decline: %q", got)
			}
			if !strings.Contains(out.String(), "Aborted") {
				t.Errorf("expected aborted output, got %q", out.String())
			}
		})
	}
}

func TestSelfUpdatePromptYesShowsNotesAndSwaps(t *testing.T) {
	target := seedTarget(t, []byte("old"))
	newBin := []byte("new")
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-linux-amd64", newBin, false)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     target,
		osName:         "linux",
		arch:           "amd64",
		stdin:          strings.NewReader("y\n"),
		stdout:         &out,
		currentVersion: "v0.1.0",
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, newBin) {
		t.Errorf("binary not replaced: %q", got)
	}
	for _, want := range []string{"v0.1.0 -> v9.9.9", "Release notes:", "Proceed?"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt output missing %q: %q", want, out.String())
		}
	}
}

func TestSelfUpdateHomebrewRedirectsWithoutFormula(t *testing.T) {
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-darwin-arm64", []byte("bin"), false)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     "/opt/homebrew/bin/syslog-reporter",
		osName:         "darwin",
		arch:           "arm64",
		stdout:         &out,
		currentVersion: "v0.1.0",
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	output := out.String()
	if !strings.Contains(output, "Homebrew") {
		t.Errorf("expected Homebrew mention, got %q", output)
	}
	// There is no formula for this tool; the hint must stay generic.
	if strings.Contains(output, "brew upgrade syslog") {
		t.Errorf("invented a formula name: %q", output)
	}
}

func TestSelfUpdateGoInstallRedirectHintsCmdPath(t *testing.T) {
	fr := newFakeRelease(t, "v9.9.9", "syslog-reporter-darwin-arm64", []byte("bin"), false)

	var out bytes.Buffer
	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         fr.srv.URL + "/releases/latest",
		httpClient:     fr.srv.Client(),
		targetPath:     "/Users/somebody/go/bin/syslog-reporter",
		osName:         "darwin",
		arch:           "arm64",
		stdout:         &out,
		currentVersion: "v0.1.0",
		home:           "/Users/somebody",
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	want := "go install github.com/ohnotnow/syslog-reporter-go/cmd/syslog-reporter@latest"
	if !strings.Contains(out.String(), want) {
		t.Errorf("expected %q hint, got %q", want, out.String())
	}
}

func TestAssetNameForMatchesReleaseMatrix(t *testing.T) {
	tests := []struct {
		goos, goarch string
		want         string
	}{
		{"darwin", "arm64", "syslog-reporter-darwin-arm64"},
		{"darwin", "amd64", "syslog-reporter-darwin-amd64"},
		{"linux", "amd64", "syslog-reporter-linux-amd64"},
		{"linux", "arm64", "syslog-reporter-linux-arm64"},
		{"windows", "amd64", "syslog-reporter-windows-amd64.exe"},
		{"windows", "arm64", "syslog-reporter-windows-arm64.exe"},
		{"freebsd", "amd64", ""},
		{"darwin", "386", ""},
	}
	for _, tt := range tests {
		if got := assetNameFor(tt.goos, tt.goarch); got != tt.want {
			t.Errorf("assetNameFor(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

func TestLookupChecksumHandlesBothModes(t *testing.T) {
	sums := strings.Join([]string{
		"abcd1234  syslog-reporter-darwin-arm64",
		"feedface *syslog-reporter-windows-amd64.exe", // text-mode entry
		"",
	}, "\n")
	if got, err := lookupChecksum(sums, "syslog-reporter-darwin-arm64"); err != nil || got != "abcd1234" {
		t.Errorf("binary-mode: got %q, %v", got, err)
	}
	if got, err := lookupChecksum(sums, "syslog-reporter-windows-amd64.exe"); err != nil || got != "feedface" {
		t.Errorf("text-mode: got %q, %v", got, err)
	}
	if _, err := lookupChecksum(sums, "syslog-reporter-plan9-amd64"); err == nil {
		t.Error("expected error for missing entry")
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.0.1", "v1.0.0", true},
		{"v1.1.0", "v1.0.9", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.0.1", false},
		{"nightly", "v1.0.0", false},
		{"v1.0.0", "dev", false},
	}
	for _, c := range cases {
		if got := isNewer(c.latest, c.current); got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}
