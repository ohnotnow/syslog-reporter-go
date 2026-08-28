package reporter

// Port of agents/emailer.py: the short digest as the message body, the full
// report as a text/markdown attachment, recipients on the envelope only
// (BCC) with the sender in the visible To header. Send failures print a
// message rather than crash, matching the Python behaviour, so a cron run
// still leaves the report files behind.

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

type EmailAgent struct {
	BodyText           string
	AttachmentText     string
	AttachmentFilename string
	Recipients         string // comma-separated
	Subject            string
	SMTPServer         string
	Sender             string
}

func NewEmailAgent(bodyText, attachmentText, recipients string) (*EmailAgent, error) {
	if recipients == "" {
		recipients = os.Getenv("SYSLOG_SMTP_RECIPIENTS")
	}
	if recipients == "" {
		return nil, errors.New("no recipients specified for email agent")
	}
	return &EmailAgent{
		BodyText:           bodyText,
		AttachmentText:     attachmentText,
		AttachmentFilename: "email_attachment.md",
		Recipients:         recipients,
		Subject:            "Syslog Report",
		SMTPServer:         os.Getenv("SYSLOG_SMTP_SERVER"),
		Sender:             os.Getenv("SYSLOG_SMTP_SENDER"),
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

// BuildMessage assembles the email: short digest as the body, full report
// attached. Recipients travel only on the SMTP envelope, so the message
// shows the sender in To and no BCC header.
func (e *EmailAgent) BuildMessage() ([]byte, error) {
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\n", e.Sender)
	fmt.Fprintf(&msg, "To: %s\n", e.Sender)
	fmt.Fprintf(&msg, "Subject: %s\n", e.Subject)
	msg.WriteString("MIME-Version: 1.0\n")

	if e.AttachmentText == "" {
		msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\n\n")
		if err := writeQuotedPrintable(&msg, e.BodyText); err != nil {
			return nil, err
		}
		return []byte(msg.String()), nil
	}

	var parts strings.Builder
	mw := multipart.NewWriter(&parts)
	body, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=\"utf-8\""},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(body)
	if _, err := qp.Write([]byte(e.BodyText)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	attachment, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/markdown; charset=\"utf-8\""},
		"Content-Disposition": {
			fmt.Sprintf("attachment; filename=%q", e.AttachmentFilename)},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	if _, err := attachment.Write(wrapBase64([]byte(e.AttachmentText))); err != nil {
		return nil, err
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

// Run sends the digest (with the full report attached) to recipients as BCC.
func (e *EmailAgent) Run() {
	msg, err := e.BuildMessage()
	if err != nil {
		fmt.Printf("Failed to send email: %v\n", err)
		return
	}
	addr := e.SMTPServer
	if !strings.Contains(addr, ":") {
		addr += ":25"
	}
	// The sender appears in To and gets a copy; the real recipients ride the
	// envelope only, like smtplib's send_message with a Bcc header.
	rcpts := append([]string{e.Sender}, e.recipientList()...)
	if err := smtp.SendMail(addr, nil, e.Sender, rcpts, msg); err != nil {
		fmt.Printf("Failed to send email: %v\n", err)
		return
	}
	fmt.Printf("Email sent to %s\n", e.Recipients)
}
