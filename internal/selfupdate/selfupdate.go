package selfupdate

// The `self-update` command: download the latest release binary for this
// platform, verify it against the published SHA256SUMS, and atomically
// replace the running executable. Only ever runs as an explicit
// invocation; nothing in the batch pipeline may trigger it.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Run executes `syslog-reporter self-update` and returns the process exit
// code. Flags:
//
//	--check    Report whether an update is available without downloading.
//	           Exits 0 when current, 1 when newer is available, 2 on
//	           lookup failure.
//	--yes/-y   Skip the confirmation prompt.
func Run(args []string) int {
	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var check, yes bool
	fs.BoolVar(&check, "check", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println("usage: syslog-reporter self-update [--check] [--yes]")
			return 0
		}
		fmt.Fprintf(os.Stderr, "syslog-reporter: self-update: %v\n", err)
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-reporter: resolve executable: %v\n", err)
		return 1
	}
	if real, lerr := filepath.EvalSymlinks(exe); lerr == nil {
		exe = real
	}

	home, _ := os.UserHomeDir()

	code, err := runSelfUpdate(selfUpdateConfig{
		apiURL:         buildAPIURL(RepoURL),
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		targetPath:     exe,
		osName:         runtime.GOOS,
		arch:           runtime.GOARCH,
		stdin:          os.Stdin,
		stdout:         os.Stdout,
		stderr:         os.Stderr,
		currentVersion: Version,
		gopath:         os.Getenv("GOPATH"),
		home:           home,
		checkOnly:      check,
		assumeYes:      yes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-reporter: %v\n", err)
	}
	return code
}

// selfUpdateConfig bundles the moving parts of a self-update run so tests
// can substitute an httptest server, a temp file standing in for the
// running binary, and a known platform tuple.
type selfUpdateConfig struct {
	apiURL         string
	httpClient     *http.Client
	targetPath     string
	osName         string
	arch           string
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
	currentVersion string
	gopath         string
	home           string
	checkOnly      bool
	assumeYes      bool
}

// runSelfUpdate does the work and returns the exit code alongside any
// error worth printing. In --check mode the code carries the answer
// (0 current, 1 newer available, 2 lookup failed); otherwise non-zero
// means the update did not happen.
func runSelfUpdate(cfg selfUpdateConfig) (int, error) {
	// Dev builds short-circuit before any network call: replacing a
	// hand-built binary with a release one is almost never what the user
	// wants, and there is no version to compare against anyway.
	if cfg.currentVersion == "dev" {
		if cfg.checkOnly {
			fmt.Fprintln(cfg.stdout, "syslog-reporter is a dev build - version check skipped.")
			return 0, nil
		}
		fmt.Fprintln(cfg.stdout, "syslog-reporter is a dev build - self-update is disabled.")
		fmt.Fprintln(cfg.stdout, "Rebuild from source, or install a release binary.")
		return 0, nil
	}

	rel, err := fetchLatestRelease(cfg.httpClient, cfg.apiURL)
	if err != nil {
		wrapped := fmt.Errorf("fetch latest release: %w", err)
		if cfg.checkOnly {
			return 2, wrapped
		}
		return 1, wrapped
	}

	if !isNewer(rel.TagName, cfg.currentVersion) {
		fmt.Fprintf(cfg.stdout, "Already up to date (%s).\n", cfg.currentVersion)
		return 0, nil
	}

	// --check stops here: report and exit 1. No download, no prompt, no
	// swap - just a non-zero exit so scripts can act on it.
	if cfg.checkOnly {
		fmt.Fprintf(cfg.stdout, "syslog-reporter %s is installed; %s is available.\n",
			cfg.currentVersion, rel.TagName)
		return 1, nil
	}

	// A newer version exists. Before touching anything, ask whether this
	// binary even belongs to us: Homebrew and 'go install' manage their
	// own copies, and a self-update would silently sidestep them.
	pmHint, pmAct := detectPackageManager(cfg.targetPath, cfg.osName, cfg.gopath, cfg.home)
	if pmAct == pmRedirect {
		fmt.Fprintf(cfg.stdout, "This install looks %s-managed.\n", pmHint.manager)
		fmt.Fprintf(cfg.stdout, "A newer version (%s) is available - update with:\n  %s\n",
			rel.TagName, pmHint.command)
		return 0, nil
	}

	assetName := assetNameFor(cfg.osName, cfg.arch)
	if assetName == "" {
		return 1, fmt.Errorf("no release asset for platform %s/%s", cfg.osName, cfg.arch)
	}

	binAsset, ok := findAsset(rel.Assets, assetName)
	if !ok {
		return 1, fmt.Errorf("release %s does not include asset %q", rel.TagName, assetName)
	}
	sumsAsset, ok := findAsset(rel.Assets, "SHA256SUMS")
	if !ok {
		return 1, fmt.Errorf("release %s does not include SHA256SUMS", rel.TagName)
	}

	// Bail out before the download if we can't write to the install dir,
	// so a sudo-owned location fails fast instead of after a multi-MB
	// download.
	dir := filepath.Dir(cfg.targetPath)
	if !canWrite(dir) {
		return 1, fmt.Errorf("cannot write to %s - re-run with sudo, or visit %s/releases/latest",
			dir, RepoURL)
	}

	if !cfg.assumeYes {
		ok, err := confirmUpdate(cfg, rel, assetName)
		if err != nil {
			return 1, err
		}
		if !ok {
			fmt.Fprintln(cfg.stdout, "Aborted.")
			return 0, nil
		}
	}

	binBytes, err := downloadAsset(cfg.httpClient, binAsset.URL)
	if err != nil {
		return 1, fmt.Errorf("download %s: %w", assetName, err)
	}
	sumsBytes, err := downloadAsset(cfg.httpClient, sumsAsset.URL)
	if err != nil {
		return 1, fmt.Errorf("download SHA256SUMS: %w", err)
	}

	expected, err := lookupChecksum(string(sumsBytes), assetName)
	if err != nil {
		return 1, err
	}
	sum := sha256.Sum256(binBytes)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expected) {
		return 1, fmt.Errorf("checksum mismatch for %s: expected %s, got %s",
			assetName, expected, actual)
	}

	if pmAct == pmWarn && cfg.stderr != nil {
		fmt.Fprintf(cfg.stderr,
			"warning: syslog-reporter lives in %s, which is normally managed by your system package manager.\n",
			filepath.Dir(cfg.targetPath))
		fmt.Fprintln(cfg.stderr, "self-update will sidestep that - proceeding anyway.")
	}

	if err := atomicSwap(cfg.targetPath, binBytes); err != nil {
		return 1, fmt.Errorf("replace binary: %w", err)
	}

	fmt.Fprintf(cfg.stdout, "Updated to %s.\n", rel.TagName)
	return 0, nil
}

// confirmUpdate prints a summary, the release notes, and a y/N prompt,
// then reads a single line from stdin. Default (empty input or anything
// not 'y'/'yes') is no.
func confirmUpdate(cfg selfUpdateConfig, rel *ghRelease, assetName string) (bool, error) {
	fmt.Fprintf(cfg.stdout, "syslog-reporter %s -> %s\n", cfg.currentVersion, rel.TagName)
	fmt.Fprintf(cfg.stdout, "Asset: %s\n", assetName)

	body := strings.TrimSpace(rel.Body)
	if body != "" {
		fmt.Fprintln(cfg.stdout)
		fmt.Fprintln(cfg.stdout, "Release notes:")
		fmt.Fprintln(cfg.stdout, body)
	}

	fmt.Fprintln(cfg.stdout)
	fmt.Fprint(cfg.stdout, "Proceed? [y/N]: ")

	if cfg.stdin == nil {
		return false, nil
	}
	reader := bufio.NewReader(cfg.stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// pmAction classifies what self-update should do when the running binary
// looks like it was installed by a package manager.
type pmAction int

const (
	pmNone     pmAction = iota // self-installed; proceed normally
	pmRedirect                 // package manager owns this; print hint and exit
	pmWarn                     // system bin we'll touch anyway, but warn
)

// pmHint is the human-facing pair of strings emitted alongside a redirect.
type pmHint struct {
	manager string
	command string
}

// detectPackageManager classifies path against well-known install
// locations. goos, gopath, and home are passed in so tests can drive the
// function without touching real environment variables.
//
// Heuristics, not gates: false positives just route the user to a tool
// that already does the right thing; false negatives fall through to a
// regular self-update. There is no Homebrew formula for this tool, so a
// Homebrew-looking path gets a generic hint, not an invented formula name.
func detectPackageManager(path, goos, gopath, home string) (pmHint, pmAction) {
	p := filepath.ToSlash(path)

	if strings.HasPrefix(p, "/opt/homebrew/") ||
		strings.Contains(p, "/Cellar/") ||
		strings.Contains(p, "/homebrew/") ||
		strings.Contains(p, "/linuxbrew/") {
		return pmHint{manager: "Homebrew", command: "update it through Homebrew"}, pmRedirect
	}

	goBin := ""
	switch {
	case gopath != "":
		goBin = filepath.ToSlash(filepath.Join(gopath, "bin"))
	case home != "":
		goBin = filepath.ToSlash(filepath.Join(home, "go", "bin"))
	}
	if goBin != "" && (p == goBin || strings.HasPrefix(p, goBin+"/")) {
		return pmHint{
			manager: "'go install'",
			command: "go install github.com/ohnotnow/syslog-reporter-go/cmd/syslog-reporter@latest",
		}, pmRedirect
	}

	if goos == "linux" {
		dir := filepath.ToSlash(filepath.Dir(p))
		if dir == "/usr/bin" || dir == "/usr/local/bin" {
			return pmHint{}, pmWarn
		}
	}

	return pmHint{}, pmNone
}

// canWrite reports whether the calling process can create files in dir,
// by creating (and immediately removing) a tempfile - the only portable
// answer that works across POSIX and Windows.
func canWrite(dir string) bool {
	f, err := os.CreateTemp(dir, ".syslog-reporter-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// assetNameFor returns the release asset filename the workflow publishes
// for a given GOOS/GOARCH, or "" if the platform isn't built. Mirrors the
// build matrix in .github/workflows/release.yml - keep the two in sync.
func assetNameFor(goos, goarch string) string {
	switch goos {
	case "windows":
		if goarch == "amd64" || goarch == "arm64" {
			return "syslog-reporter-windows-" + goarch + ".exe"
		}
	case "darwin":
		if goarch == "amd64" || goarch == "arm64" {
			return "syslog-reporter-darwin-" + goarch
		}
	case "linux":
		if goarch == "amd64" || goarch == "arm64" {
			return "syslog-reporter-linux-" + goarch
		}
	}
	return ""
}

func findAsset(assets []ghAsset, name string) (ghAsset, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a, true
		}
	}
	return ghAsset{}, false
}

func downloadAsset(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// lookupChecksum scans a SHA256SUMS file for a line matching name and
// returns its hex digest. Each line is '<hex><space><space-or-asterisk><name>'
// (binary mode uses two spaces, text mode uses ' *'); strings.Fields
// flattens both into the same two-field split.
func lookupChecksum(sums, name string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fname := strings.TrimPrefix(fields[1], "*")
		if fname == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %q in SHA256SUMS", name)
}

// atomicSwap replaces the file at target with content. On POSIX it writes
// a sibling temp file and renames over the target - atomic at the
// filesystem level. On Windows the running .exe cannot be overwritten, so
// the current binary is renamed to <target>.old first; that file is left
// behind for the OS or the next self-update invocation to clean up.
func atomicSwap(target string, content []byte) error {
	dir := filepath.Dir(target)
	base := filepath.Base(target)

	tmp, err := os.CreateTemp(dir, base+".new-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		oldPath := target + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(target, oldPath); err != nil {
			return err
		}
	}

	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}
