package reporter

import (
	"strings"
	"testing"
)

func TestMaskSecrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"web01 puppet-agent[1]: '/opt/agent link --key=0123abcd4567ef --host=sensor.example.test --port=443' returned 2",
			"web01 puppet-agent[1]: '/opt/agent link --key=<redacted> --host=sensor.example.test --port=443' returned 2",
		},
		{"app[2]: calling --api-key s3cr3t now", "app[2]: calling --api-key <redacted> now"},
		{"app[3]: api_key=abc123&user=bob", "app[3]: api_key=<redacted>&user=bob"},
		{"app[4]: password: hunter2", "app[4]: password: <redacted>"},
		{"app[5]: DB_PASSWORD=hunter2 started", "app[5]: DB_PASSWORD=<redacted> started"},
		{"app[6]: Authorization: Bearer eyJhbGciOi.x.y", "app[6]: Authorization: Bearer <redacted>"},
		{"app[7]: fetching https://svc:hunter2@repo.example.test/x", "app[7]: fetching https://svc:<redacted>@repo.example.test/x"},
		// Left alone: not secrets.
		{"named[8]: verify failed due to bad signature (keyid=19277)", "named[8]: verify failed due to bad signature (keyid=19277)"},
		{"sshd[9]: Accepted publickey for backup from 192.0.2.7 port 50122", "sshd[9]: Accepted publickey for backup from 192.0.2.7 port 50122"},
		{"agent[10]: --proxy_port=8080 --host=a.example.test", "agent[10]: --proxy_port=8080 --host=a.example.test"},
	}
	for _, c := range cases {
		if got := MaskSecrets(c.in); got != c.want {
			t.Errorf("MaskSecrets(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// The email layouts quote the example masked (the library keeps it raw).
func TestEmailExamplesAreMasked(t *testing.T) {
	line := "web01 puppet-agent[1]: 'agent link --key=0123abcd4567ef' returned 2"
	issue := &Issue{Issue: "Key in log", Severity: "high", ExampleLogEntry: line}
	anomaly := &ExplainedAnomaly{ExampleLine: line}
	for name, out := range map[string]string{
		"issue attachment": issue.ToMarkdown(),
		"anomaly":          anomaly.ToMarkdown(),
	} {
		if strings.Contains(out, "0123abcd4567ef") || !strings.Contains(out, "--key=<redacted>") {
			t.Errorf("%s does not mask the key:\n%s", name, out)
		}
	}
	if issue.ExampleLogEntry != line {
		t.Errorf("rendering changed the stored example: %q", issue.ExampleLogEntry)
	}
}
