package selfupdate

// Version plumbing and the GitHub latest-release lookup shared by
// `--version` and `self-update`.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	// Version is stamped by the release build via
	// -ldflags "-X github.com/ohnotnow/syslog-reporter-go/internal/selfupdate.Version=...".
	Version = "dev"
	RepoURL = "https://github.com/ohnotnow/syslog-reporter-go"
)

// ghAsset is a single binary attached to a GitHub release.
type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// ghRelease is the slice of the GitHub /releases/latest payload we care
// about: tag for version comparison, body for release notes, and assets so
// self-update can find the right binary.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Body    string    `json:"body"`
	Assets  []ghAsset `json:"assets"`
}

// VersionCheck runs the post-version-line latest-release check for
// `--version`: on a release build it looks up the latest tag (short timeout
// so an unreachable network never makes the flag feel hung) and says
// whether a newer one exists. Dev builds and lookup failures print nothing.
func VersionCheck(w io.Writer) {
	if Version == "dev" {
		return
	}
	latest, err := checkLatestRelease()
	if err != nil {
		return
	}
	if isNewer(latest, Version) {
		fmt.Fprintf(w, "A newer version (%s) is available.\n", latest)
		fmt.Fprintf(w, "Visit %s/releases/latest to update, or run `syslog-reporter self-update`.\n", RepoURL)
	} else {
		fmt.Fprintln(w, "You are running the latest version.")
	}
}

// fetchLatestRelease asks the GitHub API for the latest published release
// at apiURL. The caller supplies the http.Client so it can pick a timeout:
// `--version` wants a short one, `self-update` needs longer for a
// multi-megabyte binary download.
func fetchLatestRelease(client *http.Client, apiURL string) (*ghRelease, error) {
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func checkLatestRelease() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	rel, err := fetchLatestRelease(client, buildAPIURL(RepoURL))
	if err != nil {
		return "", err
	}
	return rel.TagName, nil
}

func buildAPIURL(repoURL string) string {
	path := strings.TrimPrefix(repoURL, "https://github.com/")
	path = strings.TrimPrefix(path, "http://github.com/")
	path = strings.TrimSuffix(path, "/")
	return "https://api.github.com/repos/" + path + "/releases/latest"
}

// isNewer compares two vMAJOR.MINOR.PATCH tags; anything unparseable
// compares as not-newer, so a weird tag never triggers an update.
func isNewer(latest, current string) bool {
	parse := func(v string) (int, int, int, bool) {
		v = strings.TrimPrefix(v, "v")
		parts := strings.Split(v, ".")
		if len(parts) != 3 {
			return 0, 0, 0, false
		}
		major, err1 := strconv.Atoi(parts[0])
		minor, err2 := strconv.Atoi(parts[1])
		patch, err3 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			return 0, 0, 0, false
		}
		return major, minor, patch, true
	}

	lMaj, lMin, lPat, lok := parse(latest)
	cMaj, cMin, cPat, cok := parse(current)
	if !lok || !cok {
		return false
	}

	if lMaj != cMaj {
		return lMaj > cMaj
	}
	if lMin != cMin {
		return lMin > cMin
	}
	return lPat > cPat
}
