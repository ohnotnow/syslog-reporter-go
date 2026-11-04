package reporter

// Tests for the noise review store (migration 9). Fictional hosts and
// programs only.

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newNoiseStore(t *testing.T) (*LibraryStore, int64) {
	t.Helper()
	s, err := OpenLibraryStore(filepath.Join(t.TempDir(), "noise.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	uid, err := s.CreateUser("opsuser", "ops@example.test", "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return s, uid
}

func noiseDay(t *testing.T, d string) time.Time {
	t.Helper()
	day, err := time.Parse("2006-01-02", d)
	if err != nil {
		t.Fatal(err)
	}
	return day
}

func testShapes(programs ...string) []NoiseShape {
	var out []NoiseShape
	for i, p := range programs {
		out = append(out, NoiseShape{Program: p, Template: p + " did a thing <n> times",
			Example: p + "[42]: " + p + " did a thing 3 times", ExampleHost: "web1.example.test",
			Lines: 10 + i, Hosts: 1 + i})
	}
	return out
}

// sampleAll draws the whole pool (order is random, so compare as a set).
func sampleAll(t *testing.T, s *LibraryStore, notBefore time.Time, skip func(NoiseShape) bool) map[string]NoiseShape {
	t.Helper()
	got, err := s.SampleNoiseShapes(1000, notBefore, skip)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]NoiseShape{}
	for _, sh := range got {
		out[sh.Program] = sh
	}
	return out
}

func TestReplaceNoiseShapesKeepsTheNewestDay(t *testing.T) {
	s, _ := newNoiseStore(t)
	if ok, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-03"), testShapes("fwupd", "motd")); err != nil || !ok {
		t.Fatalf("first write: %v %v", ok, err)
	}
	if ok, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-01"), testShapes("olddaemon")); err != nil || ok {
		t.Fatalf("older day should be a no-op, got %v %v", ok, err)
	}
	pool := sampleAll(t, s, time.Time{}, nil)
	if len(pool) != 2 || pool["fwupd"].Lines != 10 || pool["motd"].Hosts != 2 || pool["fwupd"].ExampleHost != "web1.example.test" {
		t.Fatalf("pool after older write = %+v", pool)
	}
	if !pool["fwupd"].Day.Equal(noiseDay(t, "2026-11-03")) {
		t.Errorf("day = %v", pool["fwupd"].Day)
	}
	// The same day (a re-run) replaces; so does a newer one.
	if ok, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-03"), testShapes("cron")); err != nil || !ok {
		t.Fatalf("same-day rewrite: %v %v", ok, err)
	}
	if pool := sampleAll(t, s, time.Time{}, nil); len(pool) != 1 || pool["cron"].Program != "cron" {
		t.Fatalf("pool after same-day rewrite = %+v", pool)
	}
	if ok, _ := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-04"), testShapes("sshd", "cron")); !ok {
		t.Fatal("newer day refused")
	}
	if day, ok, err := s.NoiseShapesDay(); err != nil || !ok || !day.Equal(noiseDay(t, "2026-11-04")) {
		t.Errorf("NoiseShapesDay = %v %v %v", day, ok, err)
	}
}

func TestSampleNoiseShapesSkipsRecentVerdictsAndSkipped(t *testing.T) {
	s, uid := newNoiseStore(t)
	if _, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-03"), testShapes("fwupd", "motd", "cron", "sshd")); err != nil {
		t.Fatal(err)
	}
	pool := sampleAll(t, s, time.Time{}, nil)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	// fwupd judged noise today, motd not noise 40 days ago.
	if err := s.RecordNoiseVerdicts(uid, []NoiseShape{pool["fwupd"]}, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordNoiseVerdicts(uid, nil, []NoiseShape{pool["motd"]}, now.AddDate(0, 0, -40)); err != nil {
		t.Fatal(err)
	}
	got := sampleAll(t, s, now.AddDate(0, 0, -30), func(sh NoiseShape) bool { return sh.Program == "sshd" })
	if len(got) != 2 {
		t.Fatalf("want motd and cron, got %+v", got)
	}
	if _, ok := got["motd"]; !ok {
		t.Error("an old verdict should not keep a shape out")
	}
	if _, ok := got["fwupd"]; ok {
		t.Error("a recent verdict should keep a shape out")
	}
	if _, ok := got["sshd"]; ok {
		t.Error("skip should keep a shape out")
	}
	// n caps the draw; a spent pool returns fewer without error.
	if few, err := s.SampleNoiseShapes(1, time.Time{}, nil); err != nil || len(few) != 1 {
		t.Errorf("n=1: %d shapes, %v", len(few), err)
	}
	if none, err := s.SampleNoiseShapes(10, time.Time{}, func(NoiseShape) bool { return true }); err != nil || len(none) != 0 {
		t.Errorf("all skipped: %d shapes, %v", len(none), err)
	}
}

func TestNoiseShapeByID(t *testing.T) {
	s, _ := newNoiseStore(t)
	if _, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-03"), testShapes("fwupd")); err != nil {
		t.Fatal(err)
	}
	one := sampleAll(t, s, time.Time{}, nil)["fwupd"]
	got, err := s.NoiseShape(one.ID)
	if err != nil || got.Template != one.Template || got.Example != one.Example {
		t.Fatalf("NoiseShape(%d) = %+v, %v", one.ID, got, err)
	}
	if _, err := s.NoiseShape(one.ID + 99); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("missing id: want sql.ErrNoRows, got %v", err)
	}
}

func TestNoiseVerdictCheckRefusesUnknownVerdicts(t *testing.T) {
	s, uid := newNoiseStore(t)
	_, err := s.db.Exec(`INSERT INTO noise_verdicts (program, template, verdict, user_id, created_at)
		VALUES ('fwupd', 'x', 'maybe', ?, '2026-11-04T00:00:00Z')`, uid)
	if err == nil {
		t.Error("CHECK let 'maybe' through")
	}
}

func TestNoiseModelViewRoundTrip(t *testing.T) {
	s, _ := newNoiseStore(t)
	if v, err := s.NoiseModelView("fwupd", "ready"); err != nil || v != nil {
		t.Fatalf("absent view = %+v, %v", v, err)
	}
	score := 0.03
	if err := s.SaveNoiseModelView("fwupd", "ready", NoiseModelView{Score: &score, ScoreModel: "azure/test",
		Explanation: "Firmware daemon start-up.", ExplainModel: "azure/chat"}); err != nil {
		t.Fatal(err)
	}
	v, err := s.NoiseModelView("fwupd", "ready")
	if err != nil || v == nil || v.Score == nil || *v.Score != 0.03 || v.ScoreModel != "azure/test" ||
		v.Explanation != "Firmware daemon start-up." || v.ExplainModel != "azure/chat" || v.Refused || v.CreatedAt.IsZero() {
		t.Fatalf("view = %+v, %v", v, err)
	}
	// A refusal replaces it, with no score.
	if err := s.SaveNoiseModelView("fwupd", "ready", NoiseModelView{Refused: true, ScoreModel: "azure/test"}); err != nil {
		t.Fatal(err)
	}
	v, _ = s.NoiseModelView("fwupd", "ready")
	if v.Score != nil || !v.Refused || v.Explanation != "" {
		t.Errorf("refused view = %+v", v)
	}
}

// Removing a reviewer keeps their verdicts (so the shapes stay out of the
// draw) and must not trip the foreign key.
func TestRemoveUserKeepsTheirNoiseVerdicts(t *testing.T) {
	s, uid := newNoiseStore(t)
	if _, err := s.ReplaceNoiseShapes(noiseDay(t, "2026-11-03"), testShapes("fwupd", "motd")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.RecordNoiseVerdicts(uid, []NoiseShape{sampleAll(t, s, time.Time{}, nil)["fwupd"]}, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser("opsuser"); err != nil {
		t.Fatalf("RemoveUser with verdicts: %v", err)
	}
	if got := sampleAll(t, s, now.AddDate(0, 0, -30), nil); len(got) != 1 || got["motd"].Program != "motd" {
		t.Errorf("after removal the verdict should still keep fwupd out: %+v", got)
	}
	var nulls int
	s.db.QueryRow("SELECT count(*) FROM noise_verdicts WHERE user_id IS NULL").Scan(&nulls)
	if nulls != 1 {
		t.Errorf("%d unattributed verdicts, want 1", nulls)
	}
}
