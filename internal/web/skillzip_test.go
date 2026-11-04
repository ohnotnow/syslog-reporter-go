package web

// Tests for the skill download (ait srg-xDjoC.6).

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
	"testing/fstest"

	"github.com/ohnotnow/syslog-reporter-go/skills"
)

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = b
	}
	return files
}

func TestSkillZipMatchesTheRepoCopy(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	client := signedIn(t, ts.URL, lib, "opsuser")
	resp, err := client.Get(ts.URL + "/skill.zip")
	if err != nil {
		t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want, err := os.ReadFile("../../skills/syslog-reporter/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	got := unzip(t, data)["syslog-reporter/SKILL.md"]
	if !bytes.Equal(got, want) {
		t.Error("zipped SKILL.md differs from skills/syslog-reporter/SKILL.md")
	}
	if _, err := skills.FS.ReadFile("syslog-reporter/SKILL.md"); err != nil {
		t.Errorf("embedded FS: %v", err)
	}
}

func TestSkillZipCarriesEveryFile(t *testing.T) {
	fsys := fstest.MapFS{
		"syslog-reporter/SKILL.md":           {Data: []byte("skill")},
		"syslog-reporter/reference/notes.md": {Data: []byte("notes")},
		"other/ignored.md":                   {Data: []byte("not ours")},
	}
	data, err := skillZip(fsys)
	if err != nil {
		t.Fatal(err)
	}
	files := unzip(t, data)
	if len(files) != 2 || string(files["syslog-reporter/reference/notes.md"]) != "notes" {
		t.Errorf("zip holds %v", files)
	}
}

func TestSkillZipNeedsALogin(t *testing.T) {
	ts := newLocalServer(t, newAuthTestStore(t))
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/skill.zip")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("anonymous: %d, want a redirect to login", resp.StatusCode)
	}
	s := newTestServer(t, Config{})
	if rec := get(t, s, "/skill.zip"); rec.Code != http.StatusForbidden {
		t.Errorf("mode none: %d, want 403", rec.Code)
	}
}
