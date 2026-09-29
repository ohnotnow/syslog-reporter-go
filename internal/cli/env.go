package cli

import (
	"fmt"
	"os"
	"strings"
)

// ParseBoolEnv reads an on/off environment variable strictly: the usual
// truthy and falsy spellings work, anything else errors instead of
// silently meaning off.
func ParseBoolEnv(key string) (bool, error) {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "", "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q is not a boolean (use 1/true/yes/on or 0/false/no/off)", key, os.Getenv(key))
	}
}
