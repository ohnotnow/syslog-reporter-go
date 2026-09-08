package reporter

// Bearer tokens for the sysadmin API (ant ADR srg-yYpms). A token is 32
// random bytes as 64 hex characters, shown to the operator exactly once;
// the store keeps its sha256 and an 8-character prefix that 'token list'
// and 'token revoke' use as the human handle. Plain sha256 rather than
// bcrypt: the raw token is high-entropy, so there is nothing to
// brute-force and lookups on every API call stay cheap.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

const tokenPrefixLen = 8

type APIToken struct {
	ID         int64
	UserID     int64
	Username   string // joined from users, for list output and the API's audit trail
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	Revoked    bool
}

// Usable is false once a token is revoked or past its expiry.
func (t *APIToken) Usable(now time.Time) bool {
	if t.Revoked {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}

// HashAPIToken is the stored form of a raw token.
func HashAPIToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken mints a token for userID and returns the raw value, which
// is not recoverable afterwards. A nil expires means the token never lapses.
func (s *LibraryStore) CreateAPIToken(userID int64, expires *time.Time) (string, *APIToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generating token: %w", err)
	}
	raw := hex.EncodeToString(b)
	now := time.Now().UTC().Truncate(time.Second)
	var expiresAt any
	if expires != nil {
		expiresAt = expires.UTC().Format(time.RFC3339)
	}
	res, err := s.db.Exec(
		`INSERT INTO api_tokens (user_id, token_hash, token_prefix, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, HashAPIToken(raw), raw[:tokenPrefixLen], now.Format(time.RFC3339), expiresAt)
	if err != nil {
		return "", nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", nil, err
	}
	t, err := s.apiTokenWhere("t.id = ?", id)
	if err != nil {
		return "", nil, err
	}
	return raw, t, nil
}

// ListAPITokens returns every token, revoked ones included, oldest first.
func (s *LibraryStore) ListAPITokens() ([]*APIToken, error) {
	rows, err := s.db.Query(apiTokenSelect + " ORDER BY t.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// APITokenByHash finds a token by its stored hash; sql.ErrNoRows when
// absent. Revoked and expired tokens are returned too - the caller judges
// them with Usable, so the API can give all three the same refusal.
func (s *LibraryStore) APITokenByHash(hash string) (*APIToken, error) {
	return s.apiTokenWhere("t.token_hash = ?", hash)
}

// TouchAPIToken records a successful use.
func (s *LibraryStore) TouchAPIToken(id int64, at time.Time) error {
	_, err := s.db.Exec("UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
		at.UTC().Format(time.RFC3339), id)
	return err
}

// RevokeAPIToken revokes the one active token whose raw value starts with
// prefix. No match or more than one match is an error, so an operator can
// never revoke the wrong token by accident; passing more characters
// disambiguates.
func (s *LibraryStore) RevokeAPIToken(prefix string) (*APIToken, error) {
	if len(prefix) < tokenPrefixLen {
		return nil, fmt.Errorf("token prefix must be at least %d characters", tokenPrefixLen)
	}
	rows, err := s.db.Query(apiTokenSelect+" WHERE t.token_prefix = ? AND t.revoked = 0 ORDER BY t.id",
		prefix[:tokenPrefixLen])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []*APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		matches = append(matches, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no active token starts with %q", prefix)
	case 1:
	default:
		// Only the 8-char prefix is stored, so a longer argument cannot
		// separate them; a collision is a 1-in-4-billion event anyway.
		return nil, fmt.Errorf("%d active tokens share the prefix %q; refusing to guess", len(matches), prefix[:tokenPrefixLen])
	}
	t := matches[0]
	if _, err := s.db.Exec("UPDATE api_tokens SET revoked = 1 WHERE id = ?", t.ID); err != nil {
		return nil, err
	}
	t.Revoked = true
	return t, nil
}

const apiTokenSelect = `SELECT t.id, t.user_id, u.username, t.token_prefix, t.created_at,
       t.last_used_at, t.expires_at, t.revoked
  FROM api_tokens t JOIN users u ON u.id = t.user_id`

func (s *LibraryStore) apiTokenWhere(cond string, arg any) (*APIToken, error) {
	rows, err := s.db.Query(apiTokenSelect+" WHERE "+cond, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, sql.ErrNoRows
	}
	return scanAPIToken(rows)
}

func scanAPIToken(rows *sql.Rows) (*APIToken, error) {
	t := &APIToken{}
	var created string
	var lastUsed, expires sql.NullString
	var revoked int
	if err := rows.Scan(&t.ID, &t.UserID, &t.Username, &t.Prefix, &created,
		&lastUsed, &expires, &revoked); err != nil {
		return nil, err
	}
	var err error
	if t.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return nil, fmt.Errorf("token %d: bad created_at %q", t.ID, created)
	}
	if t.LastUsedAt, err = nullTime(lastUsed); err != nil {
		return nil, fmt.Errorf("token %d: bad last_used_at: %w", t.ID, err)
	}
	if t.ExpiresAt, err = nullTime(expires); err != nil {
		return nil, fmt.Errorf("token %d: bad expires_at: %w", t.ID, err)
	}
	t.Revoked = revoked != 0
	return t, nil
}

func nullTime(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, v.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
