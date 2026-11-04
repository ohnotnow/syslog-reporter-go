package reporter

import (
	"strings"
	"testing"
)

func TestCheckPassword(t *testing.T) {
	cases := []struct {
		name, password, want string // want "" = accepted; else a message fragment
	}{
		{"14 random characters", "q7Rv2mXk9pLz4w", "at least 15"},
		{"15 random characters", "q7Rv2mXk9pLz4wB", ""},
		{"multi-byte runes count as characters", "ééééééééééééééé", ""},
		{"64 bytes", strings.Repeat("k7", 32), ""},
		{"65 bytes", strings.Repeat("k7", 32) + "x", "at most 64"},
		{"multi-byte runes count as bytes for the cap", strings.Repeat("é", 33), "at most 64"},
		{"on the list", "qwertyuiopasdfghjkl", "commonly used"},
		{"on the list, other case", "QWERTYUIOPASDFGHJKL", "commonly used"},
		{"contains the username", "xx-opsuser-harbour-42", "username or email"},
		{"contains the username, other case", "xx-OPSUSER-harbour-42", "username or email"},
		{"contains the email local part", "xx-ops.person-kettle", "username or email"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckPassword(c.password, "opsuser", "ops.person@example.test")
			if c.want == "" {
				if err != nil {
					t.Errorf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestCheckPasswordIgnoresShortNameParts(t *testing.T) {
	// A two-letter username would otherwise refuse half of all passwords.
	if err := CheckPassword("violet-kettle-harbour-42", "ar", "ab@example.test"); err != nil {
		t.Errorf("refused: %v", err)
	}
}

func TestCommonPasswordsSkipsTheHeader(t *testing.T) {
	set := commonPasswords()
	if len(set) < 10000 {
		t.Errorf("only %d entries loaded", len(set))
	}
	for p := range set {
		if strings.HasPrefix(p, "# ") {
			t.Fatalf("header line loaded as an entry: %q", p)
		}
	}
}
