package main

// Tests for the user add core (ait srg-2KY5X.4). Fictional users only.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// testPassword passes the password policy; fictional, like the users.
const testPassword = "violet-kettle-harbour-42"

func TestUserAddRefusesAPolicyFailure(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	err := userAdd(db, "opsuser", "opsuser@example.test", "short", false)
	if err == nil || !strings.Contains(err.Error(), "at least 15 characters") {
		t.Fatalf("short password: got %v", err)
	}
	lib, err := reporter.OpenLibraryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	if u, _ := lib.UserByUsername("opsuser"); u != nil {
		t.Error("a refused password still created the user")
	}
}

func TestUserAddWritesABcryptHash(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	if err := userAdd(db, "opsuser", "opsuser@example.test", testPassword, false); err != nil {
		t.Fatal(err)
	}
	lib, err := reporter.OpenLibraryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	user, err := lib.UserByUsername("opsuser")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("user not written")
	}
	if !user.PasswordHash.Valid {
		t.Fatal("password hash is NULL")
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash.String), []byte(testPassword)); err != nil {
		t.Error("stored hash does not verify the password")
	}
	if cost, err := bcrypt.Cost([]byte(user.PasswordHash.String)); err != nil || cost != bcrypt.DefaultCost {
		t.Errorf("bcrypt cost = %d (%v), want %d", cost, err, bcrypt.DefaultCost)
	}
	if !user.Forenames.Valid && !user.Surname.Valid {
		// Names stay NULL for OIDC to fill in later; nothing to assert.
	} else {
		t.Errorf("forenames/surname should be NULL, got %v / %v", user.Forenames, user.Surname)
	}
}

func TestUserAddAdminFlag(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	if err := userAdd(db, "boss", "boss@example.test", testPassword, true); err != nil {
		t.Fatal(err)
	}
	if err := userAdd(db, "opsuser", "opsuser@example.test", testPassword, false); err != nil {
		t.Fatal(err)
	}
	lib, err := reporter.OpenLibraryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	for name, want := range map[string]bool{"boss": true, "opsuser": false} {
		u, err := lib.UserByUsername(name)
		if err != nil || u == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if u.IsAdmin != want {
			t.Errorf("%s IsAdmin = %v, want %v", name, u.IsAdmin, want)
		}
	}
}

func TestUserAddDuplicatesNameTheField(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	if err := userAdd(db, "opsuser", "opsuser@example.test", testPassword, false); err != nil {
		t.Fatal(err)
	}
	err := userAdd(db, "opsuser", "different@example.test", testPassword, false)
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("duplicate username: got %v", err)
	}
	err = userAdd(db, "different", "opsuser@example.test", testPassword, false)
	if err == nil || !strings.Contains(err.Error(), "email") {
		t.Errorf("duplicate email: got %v", err)
	}
}

func TestTokenCreateMintsForAnExistingUserOnly(t *testing.T) {
	db := filepath.Join(t.TempDir(), "tokens.db")
	if err := userAdd(db, "opsuser", "opsuser@example.test", testPassword, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tokenCreate(db, "nobody", nil); err == nil || !strings.Contains(err.Error(), `no user "nobody"`) {
		t.Errorf("unknown user err = %v", err)
	}
	raw, tok, err := tokenCreate(db, "opsuser", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 || tok.Username != "opsuser" || tok.Prefix != raw[:8] {
		t.Errorf("raw = %q, token = %+v", raw, tok)
	}
	lib, err := reporter.OpenLibraryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	if _, err := lib.APITokenByHash(reporter.HashAPIToken(raw)); err != nil {
		t.Errorf("token not stored: %v", err)
	}
}

func TestTokenCreateRefusesAMissingStore(t *testing.T) {
	db := filepath.Join(t.TempDir(), "absent.db")
	if _, _, err := tokenCreate(db, "opsuser", nil); err == nil {
		t.Error("expected the missing-database refusal")
	}
}

func TestParseExpiryIsEndOfDayAndRefusesThePast(t *testing.T) {
	if got, err := parseExpiry(""); err != nil || got != nil {
		t.Errorf("empty = %v, %v", got, err)
	}
	future := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	got, err := parseExpiry(future)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format("2006-01-02 15:04:05") != future+" 23:59:59" {
		t.Errorf("expiry = %v, want end of %s", got, future)
	}
	if _, err := parseExpiry("2020-01-01"); err == nil {
		t.Error("past date accepted")
	}
	if _, err := parseExpiry("next tuesday"); err == nil {
		t.Error("garbage date accepted")
	}
}
