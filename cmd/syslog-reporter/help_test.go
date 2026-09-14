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
		"SYSLOG_DEFAULT_MODEL", "SYSLOG_LOGSCAN_MODEL", "SYSLOG_ISSUE_MODEL",
		"SYSLOG_SMTP_SERVER", "SYSLOG_SMTP_RECIPIENTS", "SYSLOG_DB_PATH",
	} {
		if !strings.Contains(runHelpEnv, name) {
			t.Errorf("run help missing %s", name)
		}
	}
}

func TestDigestHelpNamesItsModelVar(t *testing.T) {
	for _, name := range []string{"SYSLOG_DIGEST_MODEL", "SYSLOG_ISSUE_MODEL", "SYSLOG_SMTP_RECIPIENTS"} {
		if !strings.Contains(digestHelpEnv, name) {
			t.Errorf("digest help missing %s", name)
		}
	}
}

func TestMgmtHelpNamesItsRecipientsVar(t *testing.T) {
	if !strings.Contains(mgmtHelpEnv, "SYSLOG_MGMT_RECIPIENTS") {
		t.Error("mgmt-report help missing SYSLOG_MGMT_RECIPIENTS")
	}
}

// The subcommand help texts are read on a terminal (ait srg-ml8x3): every
// line fits 80 columns and the sections are separated by blank lines.
func TestSubcommandHelpFitsATerminal(t *testing.T) {
	for name, text := range map[string]string{"user": userHelp, "token": tokenHelp, "knowns": knownsHelp} {
		for i, line := range strings.Split(text, "\n") {
			if len(line) > 79 {
				t.Errorf("%s help line %d is %d columns: %q", name, i+1, len(line), line)
			}
		}
		if strings.Count(text, "\n\n") < 3 {
			t.Errorf("%s help needs blank lines between intro, usage, subcommands and prose", name)
		}
		if !strings.Contains(text, "usage: syslog-reporter "+name+" <") {
			t.Errorf("%s help is missing the one-line usage", name)
		}
	}
}
