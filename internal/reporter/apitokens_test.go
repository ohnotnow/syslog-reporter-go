package reporter

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func newTokenUser(t *testing.T, lib *LibraryStore, name string) int64 {
	t.Helper()
	id, err := lib.CreateUser(name, name+"@example.test", "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func TestAPITokenRoundTrip(t *testing.T) {
	lib := newTestLibrary(t)
	uid := newTokenUser(t, lib, "opsuser")
	raw, created, err := lib.CreateAPIToken(uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 || raw[:8] != created.Prefix {
		t.Fatalf("raw = %q, prefix = %q", raw, created.Prefix)
	}
	got, err := lib.APITokenByHash(HashAPIToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || got.UserID != uid || got.Username != "opsuser" {
		t.Errorf("token = %+v", got)
	}
	if got.LastUsedAt != nil || got.ExpiresAt != nil || got.Revoked {
		t.Errorf("fresh token should be unused, unexpiring, active: %+v", got)
	}
	if !got.Usable(time.Now()) {
		t.Error("fresh token should be usable")
	}
	if _, err := lib.APITokenByHash(HashAPIToken("not-a-token")); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown hash err = %v, want sql.ErrNoRows", err)
	}
}

func TestAPITokenTouchRecordsLastUse(t *testing.T) {
	lib := newTestLibrary(t)
	uid := newTokenUser(t, lib, "opsuser")
	raw, created, err := lib.CreateAPIToken(uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 8, 10, 30, 0, 0, time.UTC)
	if err := lib.TouchAPIToken(created.ID, at); err != nil {
		t.Fatal(err)
	}
	got, err := lib.APITokenByHash(HashAPIToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
		t.Errorf("last used = %v, want %v", got.LastUsedAt, at)
	}
}

func TestAPITokenExpiryAndRevocation(t *testing.T) {
	lib := newTestLibrary(t)
	uid := newTokenUser(t, lib, "opsuser")
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	_, expiring, err := lib.CreateAPIToken(uid, &expires)
	if err != nil {
		t.Fatal(err)
	}
	if !expiring.Usable(expires.Add(-time.Hour)) {
		t.Error("should be usable before expiry")
	}
	if expiring.Usable(expires.Add(time.Second)) {
		t.Error("should not be usable after expiry")
	}

	raw, active, err := lib.CreateAPIToken(uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := lib.RevokeAPIToken(active.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.ID != active.ID || !revoked.Revoked {
		t.Errorf("revoked = %+v", revoked)
	}
	got, err := lib.APITokenByHash(HashAPIToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Usable(time.Now()) {
		t.Error("revoked token must not be usable")
	}
	if _, err := lib.RevokeAPIToken(active.Prefix); err == nil {
		t.Error("revoking an already revoked prefix should fail (no active match)")
	}
}

func TestAPITokenRevokeRefusesShortOrAmbiguousPrefix(t *testing.T) {
	lib := newTestLibrary(t)
	uid := newTokenUser(t, lib, "opsuser")
	if _, err := lib.RevokeAPIToken("abc"); err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Errorf("short prefix err = %v", err)
	}
	// Force a prefix collision directly: the odds of minting one are 1 in 4 billion.
	_, first, err := lib.CreateAPIToken(uid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.db.Exec(
		`INSERT INTO api_tokens (user_id, token_hash, token_prefix, created_at) VALUES (?, 'other-hash', ?, ?)`,
		uid, first.Prefix, "2026-09-08T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.RevokeAPIToken(first.Prefix); err == nil || !strings.Contains(err.Error(), "share the prefix") {
		t.Errorf("ambiguous prefix err = %v", err)
	}
}

func TestAPITokenListShowsEveryTokenOldestFirst(t *testing.T) {
	lib := newTestLibrary(t)
	a := newTokenUser(t, lib, "alpha")
	b := newTokenUser(t, lib, "bravo")
	_, first, _ := lib.CreateAPIToken(a, nil)
	_, second, _ := lib.CreateAPIToken(b, nil)
	if _, err := lib.RevokeAPIToken(second.Prefix); err != nil {
		t.Fatal(err)
	}
	tokens, err := lib.ListAPITokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0].ID != first.ID || tokens[1].ID != second.ID {
		t.Fatalf("tokens = %+v", tokens)
	}
	if tokens[0].Username != "alpha" || tokens[1].Username != "bravo" || !tokens[1].Revoked {
		t.Errorf("tokens = %+v / %+v", tokens[0], tokens[1])
	}
}

func TestMigrateV1FileGainsAPITokens(t *testing.T) {
	// A database stamped at version 1 (pre-token release) must reach the
	// current version and keep its rows.
	lib := newTestLibrary(t)
	uid := newTokenUser(t, lib, "opsuser")
	if _, err := lib.db.Exec("DROP TABLE api_tokens"); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.db.Exec("UPDATE schema_version SET version = 1"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(lib.db); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	if v := schemaVersion(t, lib.db); v != 2 {
		t.Errorf("schema version = %d, want 2", v)
	}
	if _, _, err := lib.CreateAPIToken(uid, nil); err != nil {
		t.Errorf("token table missing after upgrade: %v", err)
	}
}
