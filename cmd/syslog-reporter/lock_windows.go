//go:build windows

package main

// lockDaily is a no-op on Windows: daily is a cron job for unix boxes, and
// the release matrix builds Windows only so the other commands work there.
func lockDaily(path string) (unlock func(), held bool, err error) {
	return func() {}, false, nil
}
