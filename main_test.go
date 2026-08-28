package main

// Tests for the user add core (ait srg-2KY5X.4). Fictional users only.

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func TestUserAddWritesABcryptHash(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	if err := userAdd(db, "opsuser", "opsuser@example.test", "correct horse"); err != nil {
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
		[]byte(user.PasswordHash.String), []byte("correct horse")); err != nil {
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

func TestUserAddDuplicatesNameTheField(t *testing.T) {
	db := filepath.Join(t.TempDir(), "users.db")
	if err := userAdd(db, "opsuser", "opsuser@example.test", "pw"); err != nil {
		t.Fatal(err)
	}
	err := userAdd(db, "opsuser", "different@example.test", "pw")
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("duplicate username: got %v", err)
	}
	err = userAdd(db, "different", "opsuser@example.test", "pw")
	if err == nil || !strings.Contains(err.Error(), "email") {
		t.Errorf("duplicate email: got %v", err)
	}
}
