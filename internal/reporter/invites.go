package reporter

// One-time "set your password" links (ait srg-xDjoC.3). An admin issues one
// for a new account, or as a password reset; the person it is for opens it
// and chooses their own password, so the admin never knows it. A link is
// 32 random bytes as 64 hex characters, shown once; the store keeps its
// sha256 (HashAPIToken), works once, and lapses after InviteLifetime.
// Issuing a new link for a user retires their older unused ones, so only
// the newest works.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const InviteLifetime = 7 * 24 * time.Hour

// ErrInviteInvalid covers an unknown, used and expired link alike: the
// person holding it can do nothing different in each case.
var ErrInviteInvalid = errors.New("this link has expired or been used")

// CreateInvite issues a link for userID on behalf of the admin createdBy
// and returns the raw token, which is not recoverable afterwards.
func (s *LibraryStore) CreateInvite(userID, createdBy int64, now time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating link: %w", err)
	}
	raw := hex.EncodeToString(b)
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE user_invites SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
		now.Format(time.RFC3339), userID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO user_invites (user_id, token_hash, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, HashAPIToken(raw), createdBy, now.Format(time.RFC3339),
		now.Add(InviteLifetime).Format(time.RFC3339)); err != nil {
		return "", err
	}
	return raw, tx.Commit()
}

// InviteByToken returns the user a usable link is for, and the link's id
// for ConsumeInvite; ErrInviteInvalid when it is unknown, used or expired.
func (s *LibraryStore) InviteByToken(raw string, now time.Time) (*User, int64, error) {
	var id, userID int64
	var expires string
	var used sql.NullString
	err := s.db.QueryRow(
		"SELECT id, user_id, expires_at, used_at FROM user_invites WHERE token_hash = ?",
		HashAPIToken(raw)).Scan(&id, &userID, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrInviteInvalid
	}
	if err != nil {
		return nil, 0, err
	}
	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return nil, 0, fmt.Errorf("invite %d: bad expires_at %q", id, expires)
	}
	if used.Valid || !now.Before(exp) {
		return nil, 0, ErrInviteInvalid
	}
	u, err := s.UserByID(userID)
	if err != nil {
		return nil, 0, err
	}
	if u == nil {
		return nil, 0, ErrInviteInvalid
	}
	return u, id, nil
}

// ConsumeInvite sets the user's password hash and marks the link used, in
// one transaction. A link already used (a double submit) is
// ErrInviteInvalid and changes nothing.
func (s *LibraryStore) ConsumeInvite(inviteID int64, passwordHash string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE user_invites SET used_at = ? WHERE id = ? AND used_at IS NULL",
		now.UTC().Format(time.RFC3339), inviteID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrInviteInvalid
	}
	if _, err := tx.Exec(
		"UPDATE users SET password_hash = ? WHERE id = (SELECT user_id FROM user_invites WHERE id = ?)",
		passwordHash, inviteID); err != nil {
		return err
	}
	return tx.Commit()
}
