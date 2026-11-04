package web

// The skill download (ait srg-xDjoC.6): the syslog-reporter Claude Code
// skill as a zip of syslog-reporter/..., built from the copy compiled into
// this binary, so the skill always matches the API it talks to. Unzipped
// into ~/.claude/skills/ it lands at the folder name Claude Code expects,
// and any reference files the skill gains later come along unasked.

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"net/http"

	"github.com/ohnotnow/syslog-reporter-go/skills"
)

const skillDir = "syslog-reporter"

// skillZip builds the archive from fsys, paths rooted at skillDir/.
func skillZip(fsys fs.FS) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := fs.WalkDir(fsys, skillDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: path, Method: zip.Deflate})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) handleSkillZip(w http.ResponseWriter, r *http.Request) {
	if s.auth.CurrentUser(r) == nil {
		http.Error(w, "The skill download needs a login: run serve with --auth local.", http.StatusForbidden)
		return
	}
	data, err := skillZip(skills.FS)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="syslog-reporter-skill.zip"`)
	w.Write(data)
}
