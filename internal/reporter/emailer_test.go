package reporter

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
)

func testEmailAgent() *EmailAgent {
	return &EmailAgent{
		BodyText: "# Digest\n\nAll quiet on the estate.\n",
		Attachments: []EmailAttachment{
			{Filename: "email_attachment.md", Text: "# Full report\n\nLots of detail café.\n"},
		},
		Recipients: "team-a@example.ac.uk, team-b@example.ac.uk",
		Subject:    "Syslog Report",
		SMTPServer: "localhost:1025",
		Sender:     "reporter@example.ac.uk",
	}
}

func TestBuildMessageHeadersAndParts(t *testing.T) {
	agent := testEmailAgent()
	raw, err := agent.BuildMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("message does not parse: %v", err)
	}
	// The sender fills From and To; recipients are envelope-only, like
	// smtplib's send_message which deletes the Bcc header before sending.
	if got := msg.Header.Get("From"); got != agent.Sender {
		t.Errorf("From = %q", got)
	}
	if got := msg.Header.Get("To"); got != agent.Sender {
		t.Errorf("To = %q, want the sender", got)
	}
	if got := msg.Header.Get("Bcc"); got != "" {
		t.Errorf("Bcc header must not be transmitted, got %q", got)
	}
	if got := msg.Header.Get("Subject"); got != "Syslog Report" {
		t.Errorf("Subject = %q", got)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v)", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])

	body, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	// The quoted-printable writer emits CRLF line endings, the correct MIME
	// wire format; the text is otherwise unchanged.
	decodedBody, _ := io.ReadAll(quotedprintable.NewReader(body))
	if string(decodedBody) != strings.ReplaceAll(agent.BodyText, "\n", "\r\n") {
		t.Errorf("body round-trip mismatch: %q", decodedBody)
	}

	attachment, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if ct := attachment.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("attachment Content-Type = %q", ct)
	}
	if fn := attachment.FileName(); fn != "email_attachment.md" {
		t.Errorf("attachment filename = %q", fn)
	}
	b64, _ := io.ReadAll(attachment)
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b64), "\n", ""))
	if err != nil {
		t.Fatalf("attachment is not valid base64: %v", err)
	}
	if string(decoded) != agent.Attachments[0].Text {
		t.Errorf("attachment round-trip mismatch: %q", decoded)
	}
}

func TestBuildMessageWithoutAttachment(t *testing.T) {
	agent := testEmailAgent()
	agent.Attachments = nil
	raw, err := agent.BuildMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, _, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mediaType != "text/plain" {
		t.Errorf("attachment-less message should be plain text, got %q", mediaType)
	}
	decoded, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if string(decoded) != strings.ReplaceAll(agent.BodyText, "\n", "\r\n") {
		t.Errorf("body round-trip mismatch: %q", decoded)
	}
}

func TestRecipientList(t *testing.T) {
	agent := testEmailAgent()
	got := agent.recipientList()
	want := []string{"team-a@example.ac.uk", "team-b@example.ac.uk"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("recipientList = %v, want %v", got, want)
	}
}

func TestNewEmailAgentRequiresRecipients(t *testing.T) {
	t.Setenv("SYSLOG_SMTP_RECIPIENTS", "")
	if _, err := NewEmailAgent("body", "<html></html>", "attachment", ""); err == nil {
		t.Error("expected an error with no recipients anywhere")
	}
	t.Setenv("SYSLOG_SMTP_RECIPIENTS", "fallback@example.ac.uk")
	agent, err := NewEmailAgent("body", "<html></html>", "attachment", "")
	if err != nil {
		t.Fatal(err)
	}
	if agent.Recipients != "fallback@example.ac.uk" {
		t.Errorf("env fallback not used: %q", agent.Recipients)
	}
	// An explicit recipients argument wins over the env var.
	agent, err = NewEmailAgent("body", "<html></html>", "attachment", "explicit@example.ac.uk")
	if err != nil {
		t.Fatal(err)
	}
	if agent.Recipients != "explicit@example.ac.uk" {
		t.Errorf("explicit recipients lost: %q", agent.Recipients)
	}
}

// TestDailyDigestMessageShape pins the srg-kOKT9 daily email: a
// multipart/mixed whose first part is a text+HTML alternative (the plain
// alternative being the body markdown verbatim), followed by BOTH
// markdown files as attachments.
func TestDailyDigestMessageShape(t *testing.T) {
	body := "# Digest\n\nAll quiet on the estate.\n"
	full := "# Full report\n\nLots of detail café.\n"
	agent, err := NewEmailAgent(body, "<html><body>rendered</body></html>", full,
		"team-a@example.ac.uk")
	if err != nil {
		t.Fatal(err)
	}
	agent.Sender = "reporter@example.ac.uk"
	raw, err := agent.BuildMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("message does not parse: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v)", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])

	content, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	altType, altParams, err := mime.ParseMediaType(content.Header.Get("Content-Type"))
	if err != nil || altType != "multipart/alternative" {
		t.Fatalf("first part = %q, want multipart/alternative (%v)", altType, err)
	}
	ar := multipart.NewReader(content, altParams["boundary"])
	plain, err := ar.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	decodedPlain, _ := io.ReadAll(quotedprintable.NewReader(plain))
	if string(decodedPlain) != strings.ReplaceAll(body, "\n", "\r\n") {
		t.Errorf("plain alternative is not the body markdown verbatim: %q", decodedPlain)
	}
	htmlPart, err := ar.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if ct := htmlPart.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("second alternative = %q, want text/html", ct)
	}

	wantFiles := []string{"email_body.md", "email_attachment.md"}
	wantTexts := []string{body, full}
	for i, wantName := range wantFiles {
		att, err := mr.NextPart()
		if err != nil {
			t.Fatalf("attachment %d: %v", i, err)
		}
		if fn := att.FileName(); fn != wantName {
			t.Errorf("attachment %d filename = %q, want %q", i, fn, wantName)
		}
		b64, _ := io.ReadAll(att)
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b64), "\n", ""))
		if err != nil {
			t.Fatalf("attachment %d is not valid base64: %v", i, err)
		}
		if string(decoded) != wantTexts[i] {
			t.Errorf("attachment %d round-trip mismatch: %q", i, decoded)
		}
	}
}

func TestWrapBase64LineLength(t *testing.T) {
	long := strings.Repeat("markdown report content ", 50)
	for _, line := range strings.Split(string(wrapBase64([]byte(long))), "\n") {
		if len(line) > 76 {
			t.Fatalf("base64 line longer than 76 chars: %d", len(line))
		}
	}
}
