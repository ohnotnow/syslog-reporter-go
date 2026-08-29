package reporter

// Grew from a port of agents/emailer.py: recipients on the envelope only
// (BCC) with the sender in the visible To header, and send failures print
// a message rather than crash so a cron run still leaves the report files
// behind. Since ait srg-kOKT9 the daily digest rides as a text+HTML
// alternative pair (the text/plain alternative IS the body markdown, so
// text-only clients keep the original experience) with both markdown
// files attached; the management report reuses the same builder with no
// attachments.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
)

// EmailAttachment is one text/markdown attachment.
type EmailAttachment struct {
	Filename string
	Text     string
}

type EmailAgent struct {
	BodyText    string // always sent; the sole body when HTMLBody is empty
	HTMLBody    string // when set, body becomes multipart/alternative
	Attachments []EmailAttachment
	Recipients  string // comma-separated
	Subject     string
	SMTPServer  string
	Sender      string
}

// NewEmailAgent builds the daily digest email: markdown digest as the
// plain body, its HTML rendering as the preferred alternative, and both
// markdown files attached for copy/paste or feeding to an agent.
func NewEmailAgent(bodyText, htmlBody, attachmentText, recipients string) (*EmailAgent, error) {
	if recipients == "" {
		recipients = os.Getenv("SYSLOG_SMTP_RECIPIENTS")
	}
	if recipients == "" {
		return nil, errors.New("no recipients specified for email agent")
	}
	return &EmailAgent{
		BodyText: bodyText,
		HTMLBody: htmlBody,
		Attachments: []EmailAttachment{
			{Filename: "email_body.md", Text: bodyText},
			{Filename: "email_attachment.md", Text: attachmentText},
		},
		Recipients: recipients,
		Subject:    "Syslog Report",
		SMTPServer: os.Getenv("SYSLOG_SMTP_SERVER"),
		Sender:     os.Getenv("SYSLOG_SMTP_SENDER"),
	}, nil
}

// recipientList splits the comma-separated recipients into envelope
// addresses.
func (e *EmailAgent) recipientList() []string {
	var out []string
	for _, r := range strings.Split(e.Recipients, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// contentHeader and contentBody describe the message's readable content:
// plain text alone, or a multipart/alternative of plain and HTML. The two
// are produced together so BuildMessage can place them at the top level
// (no attachments) or nest them as the first part of a multipart/mixed.
func (e *EmailAgent) content() (textproto.MIMEHeader, []byte, error) {
	if e.HTMLBody == "" {
		var buf strings.Builder
		if err := writeQuotedPrintable(&buf, e.BodyText); err != nil {
			return nil, nil, err
		}
		return textproto.MIMEHeader{
			"Content-Type":              {"text/plain; charset=\"utf-8\""},
			"Content-Transfer-Encoding": {"quoted-printable"},
		}, []byte(buf.String()), nil
	}

	var parts strings.Builder
	mw := multipart.NewWriter(&parts)
	for _, alt := range []struct{ ctype, text string }{
		{"text/plain", e.BodyText},
		{"text/html", e.HTMLBody},
	} {
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {alt.ctype + "; charset=\"utf-8\""},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, nil, err
		}
		qp := quotedprintable.NewWriter(part)
		if _, err := qp.Write([]byte(alt.text)); err != nil {
			return nil, nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, nil, err
	}
	return textproto.MIMEHeader{
		"Content-Type": {fmt.Sprintf("multipart/alternative; boundary=%q", mw.Boundary())},
	}, []byte(parts.String()), nil
}

// BuildMessage assembles the email. Recipients travel only on the SMTP
// envelope, so the message shows the sender in To and no BCC header.
func (e *EmailAgent) BuildMessage() ([]byte, error) {
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\n", e.Sender)
	fmt.Fprintf(&msg, "To: %s\n", e.Sender)
	fmt.Fprintf(&msg, "Subject: %s\n", e.Subject)
	msg.WriteString("MIME-Version: 1.0\n")

	header, body, err := e.content()
	if err != nil {
		return nil, err
	}

	if len(e.Attachments) == 0 {
		for _, key := range []string{"Content-Type", "Content-Transfer-Encoding"} {
			if v := header.Get(key); v != "" {
				fmt.Fprintf(&msg, "%s: %s\n", key, v)
			}
		}
		msg.WriteString("\n")
		msg.Write(body)
		return []byte(msg.String()), nil
	}

	var parts strings.Builder
	mw := multipart.NewWriter(&parts)
	contentPart, err := mw.CreatePart(header)
	if err != nil {
		return nil, err
	}
	if _, err := contentPart.Write(body); err != nil {
		return nil, err
	}
	for _, att := range e.Attachments {
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"text/markdown; charset=\"utf-8\""},
			"Content-Disposition": {
				fmt.Sprintf("attachment; filename=%q", att.Filename)},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(wrapBase64([]byte(att.Text))); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=%q\n\n", mw.Boundary())
	msg.WriteString(parts.String())
	return []byte(msg.String()), nil
}

func writeQuotedPrintable(w *strings.Builder, text string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(text)); err != nil {
		return err
	}
	return qp.Close()
}

// wrapBase64 encodes data and folds the output at 76 characters per RFC 2045.
func wrapBase64(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for len(encoded) > 76 {
		out.WriteString(encoded[:76])
		out.WriteByte('\n')
		encoded = encoded[76:]
	}
	out.WriteString(encoded)
	return []byte(out.String())
}

// Run sends the message to recipients as BCC. The error matters to cron:
// callers must fail the process on it, or a lost morning report looks like
// a success.
func (e *EmailAgent) Run() error {
	msg, err := e.BuildMessage()
	if err != nil {
		return fmt.Errorf("building email: %w", err)
	}
	addr := e.SMTPServer
	if !strings.Contains(addr, ":") {
		addr += ":25"
	}
	// The sender appears in To and gets a copy; the real recipients ride the
	// envelope only, like smtplib's send_message with a Bcc header.
	rcpts := append([]string{e.Sender}, e.recipientList()...)
	if err := smtp.SendMail(addr, nil, e.Sender, rcpts, msg); err != nil {
		return fmt.Errorf("sending email via %s: %w", addr, err)
	}
	fmt.Printf("Email sent to %s\n", e.Recipients)
	return nil
}
