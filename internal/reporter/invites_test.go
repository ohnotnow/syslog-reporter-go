package reporter

import (
	"errors"
	"testing"
	"time"
)

var inviteNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func newInviteUsers(t *testing.T) (*LibraryStore, int64, int64) {
	t.Helper()
	s := newTestLibrary(t)
	admin, err := s.CreateUser("boss", "boss@example.test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.CreateUser("newbie", "newbie@example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	return s, admin, user
}

func TestInviteSetsThePasswordOnce(t *testing.T) {
	s, admin, user := newInviteUsers(t)
	raw, err := s.CreateInvite(user, admin, inviteNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Errorf("raw token %q, want 64 hex characters", raw)
	}
	u, id, err := s.InviteByToken(raw, inviteNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "newbie" {
		t.Errorf("link is for %q, want newbie", u.Username)
	}
	if err := s.ConsumeInvite(id, "newhash", inviteNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	u, _ = s.UserByUsername("newbie")
	if u.PasswordHash.String != "newhash" {
		t.Errorf("password hash = %q", u.PasswordHash.String)
	}
	if _, _, err := s.InviteByToken(raw, inviteNow.Add(time.Hour)); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("second lookup: %v, want ErrInviteInvalid", err)
	}
	if err := s.ConsumeInvite(id, "otherhash", inviteNow.Add(time.Hour)); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("second consume: %v, want ErrInviteInvalid", err)
	}
	u, _ = s.UserByUsername("newbie")
	if u.PasswordHash.String != "newhash" {
		t.Errorf("a second consume changed the hash to %q", u.PasswordHash.String)
	}
}

func TestInviteExpiresAfterSevenDays(t *testing.T) {
	s, admin, user := newInviteUsers(t)
	raw, err := s.CreateInvite(user, admin, inviteNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.InviteByToken(raw, inviteNow.Add(InviteLifetime-time.Second)); err != nil {
		t.Errorf("just inside the lifetime: %v", err)
	}
	if _, _, err := s.InviteByToken(raw, inviteNow.Add(InviteLifetime)); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("at expiry: %v, want ErrInviteInvalid", err)
	}
}

func TestNewerInviteRetiresTheOlder(t *testing.T) {
	s, admin, user := newInviteUsers(t)
	older, err := s.CreateInvite(user, admin, inviteNow)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := s.CreateInvite(user, admin, inviteNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.InviteByToken(older, inviteNow.Add(time.Hour)); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("older link: %v, want ErrInviteInvalid", err)
	}
	if _, _, err := s.InviteByToken(newer, inviteNow.Add(time.Hour)); err != nil {
		t.Errorf("newer link: %v", err)
	}
}

func TestUnknownInvite(t *testing.T) {
	s, _, _ := newInviteUsers(t)
	if _, _, err := s.InviteByToken("nonsense", inviteNow); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("unknown link: %v, want ErrInviteInvalid", err)
	}
}

// Both sides of user_invites reference users: removing the person a link
// is for, or the admin who issued links, must not trip the foreign key.
func TestRemoveUserWithInvites(t *testing.T) {
	s, admin, user := newInviteUsers(t)
	other, err := s.CreateUser("other", "other@example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateInvite(user, admin, inviteNow); err != nil {
		t.Fatal(err)
	}
	raw, err := s.CreateInvite(other, admin, inviteNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser("newbie"); err != nil {
		t.Fatalf("remove the invited user: %v", err)
	}
	if err := s.RemoveUser("boss"); err != nil {
		t.Fatalf("remove the issuing admin: %v", err)
	}
	if _, _, err := s.InviteByToken(raw, inviteNow); err != nil {
		t.Errorf("a removed admin's link for someone else should still work: %v", err)
	}
}
