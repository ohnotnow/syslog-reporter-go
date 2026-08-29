package main

// Help-text pins (ait srg-prklV): where env vars ARE a command's interface,
// the help must name them, and that must not silently rot.

import (
	"strings"
	"testing"
)

func TestServeHelpNamesItsEnvironmentInterface(t *testing.T) {
	help := serveHelpIntro + serveHelpEnv
	for _, name := range []string{
		"SYSLOG_WEB_LISTEN", "SYSLOG_AUTH_MODE", "SYSLOG_WEB_TLS_CERT", "SYSLOG_DB_PATH",
	} {
		if !strings.Contains(help, name) {
			t.Errorf("serve help missing %s", name)
		}
	}
}

func TestRunHelpNamesModelAndSMTPVars(t *testing.T) {
	for _, name := range []string{
		"SYSLOG_DEFAULT_MODEL", "SYSLOG_SMTP_SERVER", "SYSLOG_SMTP_RECIPIENTS", "SYSLOG_DB_PATH",
	} {
		if !strings.Contains(runHelpEnv, name) {
			t.Errorf("run help missing %s", name)
		}
	}
}

func TestMgmtHelpNamesItsRecipientsVar(t *testing.T) {
	if !strings.Contains(mgmtHelpEnv, "SYSLOG_MGMT_RECIPIENTS") {
		t.Error("mgmt-report help missing SYSLOG_MGMT_RECIPIENTS")
	}
}
