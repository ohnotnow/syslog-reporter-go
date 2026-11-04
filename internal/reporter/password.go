package reporter

// The password policy (ait srg-xDjoC.2, ant ADR srg-nKiHN): every password
// set from the CLI or the web must look like something a password manager
// made. It follows NIST SP 800-63B rather than composition rules, which
// breed "Password1!": a length floor, a list of known passwords, and no
// passwords built from the account's own name. Existing passwords are not
// re-checked at login; the policy only applies when one is set.

import (
	_ "embed"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// MinPasswordChars is NIST's floor for a password that is the only
	// factor, as it is here.
	MinPasswordChars = 15
	// MaxPasswordBytes stays under bcrypt's 72-byte limit, past which it
	// silently ignores the rest.
	MaxPasswordBytes = 64
)

//go:embed common-passwords.txt
var commonPasswordsText string

var commonPasswords = sync.OnceValue(func() map[string]bool {
	set := map[string]bool{}
	for line := range strings.Lines(commonPasswordsText) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		set[line] = true
	}
	return set
})

// CheckPassword returns nil for an acceptable password, or an error whose
// message can be shown to the person choosing it. The first failing rule
// wins: too short, too long, a known password, or one containing the
// username or the email's local part.
func CheckPassword(password, username, email string) error {
	if utf8.RuneCountInString(password) < MinPasswordChars {
		return errors.New("Use at least 15 characters - a password manager's generated password is ideal.")
	}
	if len(password) > MaxPasswordBytes {
		return errors.New("Use at most 64 characters.")
	}
	lower := strings.ToLower(password)
	if commonPasswords()[lower] {
		return errors.New("That password is on a list of commonly used passwords. Please choose another.")
	}
	local, _, _ := strings.Cut(email, "@")
	for _, part := range []string{username, local} {
		if utf8.RuneCountInString(part) >= 3 && strings.Contains(lower, strings.ToLower(part)) {
			return errors.New("The password must not contain your username or email address.")
		}
	}
	return nil
}
