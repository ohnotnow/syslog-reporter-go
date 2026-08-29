package reporter

// Tests for the digest HTML rendering (ait srg-kOKT9).

import (
	"strings"
	"testing"
)

func TestRenderDigestHTML(t *testing.T) {
	md := "# Syslog digest - Friday 29 August 2026\n\n" +
		"## 1. Disk filling on /var\n\n" +
		"**Severity:** high\n\n" +
		"**Have a look:**\n\n```\ndf -h /var\n```\n\n" +
		"---\n\n" +
		"Full findings are in the attached report (**email_attachment.md**).\n"
	html, err := RenderDigestHTML(md, "test-version")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"<h1>Syslog digest - Friday 29 August 2026</h1>",
		"<h2>1. Disk filling on /var</h2>",
		"<strong>Severity:</strong>",
		"df -h /var",
		"<pre>",
		"test-version",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

// The digest body embeds LLM-written prose: raw HTML in it must arrive
// escaped, never live. goldmark's default (no WithUnsafe) guarantees it;
// this pins that we never turn it on.
func TestRenderDigestHTMLEscapesRawHTML(t *testing.T) {
	html, err := RenderDigestHTML("hello <script>alert(1)</script> world\n", "v")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("raw HTML from the markdown body must be escaped")
	}
}

// Code-block comment lines carry the investigation narrative: they get
// a styled span, model-padded leading whitespace dropped, while command
// lines keep their spacing and stay unwrapped.
func TestRenderDigestHTMLStylesCodeComments(t *testing.T) {
	md := "```\n" +
		"# Check the journal\n" +
		"journalctl -u sshd | tail -20\n" +
		" # padded comment from the model\n" +
		"  sed 's/#keep me/x/' file\n" +
		"```\n"
	html, err := RenderDigestHTML(md, "v")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<span class="cmt"># Check the journal</span>`,
		`<span class="cmt"># padded comment from the model</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if !strings.Contains(html, "journalctl -u sshd | tail -20\n") ||
		strings.Contains(html, `"cmt">journalctl`) {
		t.Error("command lines must render unwrapped and unchanged")
	}
	// An indented command containing '#' mid-line is not a comment; its
	// leading whitespace is real shell text and must survive.
	if !strings.Contains(html, "  sed 's/#keep me/x/' file") {
		t.Error("indented non-comment line was altered")
	}
}

// GFM without Typographer: hyphens must never be smartened into the
// dashes this project bans.
func TestRenderDigestHTMLKeepsPlainHyphens(t *testing.T) {
	html, err := RenderDigestHTML("a range 3--5 - and a spaced hyphen\n", "v")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "3--5 - and") {
		t.Error("hyphens were transformed; Typographer must stay off")
	}
}
