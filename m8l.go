package m8l

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"time"
)

//------------------------------------------------------------
// Person
//------------------------------------------------------------

type Person struct {
	Identity string
	Email    string
}

func (p *Person) String() string {
	return personFmt(p.Identity, p.Email)
}

func personFmt(identity, email string) string {
	return identity + " <" + email + ">"
}

//------------------------------------------------------------
// Email
//------------------------------------------------------------

type Email struct {
	Date    time.Time
	Sender  map[string]string
	ReplyTo Person
	To      []Person
	Cc      []Person
	Bcc     []Person

	Subject string
	Body    string

	// Not exported fields
	valid                                                                               bool
	isSender                                                                            bool
	msg                                                                                 bytes.Buffer
	senderIdentity, senderEmail, senderUsername, senderPassword, senderHost, senderPort string
}

//------------------------------------------------------------
// Email methods
//------------------------------------------------------------

// Validates parameter: present and not empty.
func getParam(params map[string]string, key string) (val string, err error) {
	var ok bool

	if val, ok = params[key]; !ok {
		err = fmt.Errorf("[m8l] Error: Sender must have '%s' parameter: %v", key, params)
		return
	} else if val == "" {
		err = fmt.Errorf("[m8l] Error: Sender '%s' parameter must not be empty: %v", key, params)
		return
	}
	return
}

// Optional function that validates all parameters.
// Use it to minimize surprises when initializing a larger app.
func PreValidateParams(sender map[string]string) (err error) {

	// Base params
	if _, err = getParam(sender, "email"); err != nil {
		return
	}
	if _, err = getParam(sender, "identity"); err != nil {
		return
	}

	// Check other params only if marked as sender
	if sender["sender"] != "true" {
		return
	}

	// Send related params
	if _, err = getParam(sender, "username"); err != nil {
		return
	}
	if _, err = getParam(sender, "password"); err != nil {
		return
	}
	if _, err = getParam(sender, "host"); err != nil {
		return
	}
	if _, err = getParam(sender, "port"); err != nil {
		return
	}
	return
}

func NewEmail(subject string, body *bytes.Buffer) (email *Email) {
	email = &Email{Date: time.Now(), Subject: subject, Body: body.String()}
	return
}

func NewEmailString(subject, body string) (email *Email) {
	email = &Email{Date: time.Now(), Subject: subject, Body: body}
	return
}

func (m *Email) SetSender(params map[string]string) {
	m.Sender = params
}

func (m *Email) SetReplyTo(identity, email string) {
	m.ReplyTo = Person{identity, email}
}

func (m *Email) AddTo(identity, email string) {
	m.To = append(m.To, Person{identity, email})
}

func (m *Email) AddCC(identity, email string) {
	m.Cc = append(m.Cc, Person{identity, email})
}

func (m *Email) AddBCC(identity, email string) {
	m.Bcc = append(m.Bcc, Person{identity, email})
}

func (m *Email) assembleHeaderToCc() (b *bytes.Buffer) {
	b = &bytes.Buffer{}

	// Date
	b.WriteString("Date: " + m.Date.Format(time.RFC1123Z))
	b.WriteString("\n")

	// From
	b.WriteString("From: " + personFmt(m.Sender["identity"], m.Sender["email"]))
	b.WriteString("\n")

	// Reply To (optional)
	if m.ReplyTo.Email != "" {
		b.WriteString("Reply-To: " + m.ReplyTo.String())
		b.WriteString("\n")
	}

	// To
	var s string
	for i := 0; i < len(m.To); i++ {
		s += m.To[i].String()
		if i < len(m.To)-1 {
			s += ", "
		}
	}
	b.WriteString("To: " + s)
	b.WriteString("\n")

	// CC
	s = ""
	for i := 0; i < len(m.Cc); i++ {
		s += m.Cc[i].String()
		if i < len(m.To)-1 {
			s += ", "
		}
	}
	if s != "" {
		b.WriteString("Cc: " + s)
		b.WriteString("\n")
	}

	// Subject
	b.WriteString("Subject: " + m.Subject)
	b.WriteString("\n")

	return
}

func (m *Email) assembleHeaderBcc(person Person) (b *bytes.Buffer) {
	b = &bytes.Buffer{}

	// Date
	b.WriteString("Date: " + m.Date.Format(time.RFC1123Z))
	b.WriteString("\n")

	// From
	b.WriteString("From: " + personFmt(m.Sender["identity"], m.Sender["email"]))
	b.WriteString("\n")

	// Reply To (optional)
	if m.ReplyTo.Email != "" {
		b.WriteString("Reply-To: " + m.ReplyTo.String())
		b.WriteString("\n")
	}

	// To
	b.WriteString("To: " + person.Email)
	b.WriteString("\n")

	// Subject
	b.WriteString("Subject: " + m.Subject)
	b.WriteString("\n")

	return
}

func (m *Email) assembleHtmlBody() (b *bytes.Buffer) {
	b = &bytes.Buffer{}

	// MIME Version
	b.WriteString("MIME-Version: 1.0")
	b.WriteString("\n")

	// Content Type
	b.WriteString(`Content-Type: text/html; charset="utf-8"`)
	b.WriteString("\n")

	// Message separator
	b.WriteString("\n")

	// Message
	b.WriteString(m.Body)

	return
}

func (m *Email) getToCC() (emails []string) {
	for _, to := range m.To {
		emails = append(emails, to.Email)
	}
	for _, cc := range m.Cc {
		emails = append(emails, cc.Email)
	}
	return
}

func (m *Email) getBCC() (emails []string) {
	for _, bcc := range m.Bcc {
		emails = append(emails, bcc.Email)
	}
	return
}

// Validates all email parameters and prepares email to be sent.
func (m *Email) Validate() (err error) {
	// Check required params supplied
	if m.Sender == nil {
		return fmt.Errorf("[m8l] Error: Sender must be provided")
	}

	// Send email only if 'sender' is present and is 'true'
	m.isSender = m.Sender["sender"] == "true"

	// Validate parameters
	if m.senderEmail, err = getParam(m.Sender, "email"); err != nil {
		return
	}
	if m.senderIdentity, err = getParam(m.Sender, "identity"); err != nil {
		return
	}
	if m.senderUsername, err = getParam(m.Sender, "username"); err != nil {
		return
	}
	if m.senderPassword, err = getParam(m.Sender, "password"); err != nil {
		return
	}
	if m.senderHost, err = getParam(m.Sender, "host"); err != nil {
		return
	}
	if m.senderPort, err = getParam(m.Sender, "port"); err != nil {
		return
	}

	// At least one recipient must be present
	if len(m.To) == 0 {
		return fmt.Errorf("[m8l] Error: At least one TO recipient must be present")
	}

	// Subject must be present
	if len(m.Subject) == 0 {
		return fmt.Errorf("[m8l] Error: Subject must be present")
	}

	// Body must be present
	if len(m.Body) == 0 {
		return fmt.Errorf("[m8l] Error: Body must be present")
	}

	// All is good
	m.valid = true
	return
}

// Sends email asynchrounously.
func (m *Email) SendAsync() error {
	// Passed validation?
	if !m.valid {
		return fmt.Errorf("[m8l] Error: For async send must first call email.Validate()")
	}

	// Don't send if not a sender
	if !m.isSender {
		return nil
	}

	go m.send()
	return nil
}

// Sends email, waits for action completion.
func (m *Email) Send() (err error) {
	// Validate all parameters
	if err = m.Validate(); err != nil {
		return err
	}

	// Passed validation?
	if !m.valid {
		return fmt.Errorf("[m8l] Error: Email parameters did not pass validation. Email send aborted")
	}

	// Don't send if not a sender
	if !m.isSender {
		return
	}

	return m.send()
}

// Sends email.
func (m *Email) send() (err error) {
	// Assemble message
	body := m.assembleHtmlBody()

	// Assemble header for TO/CC
	msg := m.assembleHeaderToCc()

	// Add body
	// NOTE that reading body will drain the buffer
	// To prevent store body in a variable
	bdy := body.Bytes()
	msg.Write(bdy)

	// Send email to TO/CC
	err = m.sendDispatcher(msg.Bytes(), "")
	if err != nil {
		return
	}

	// If no BCC requested return now
	if m.Bcc == nil {
		return
	}

	for _, bcc := range m.Bcc {
		// Assemble header for BCC
		msg = m.assembleHeaderBcc(bcc)
		msg.Write(bdy)

		// Send BCC
		err = m.sendDispatcher(msg.Bytes(), bcc.Email)
		if err != nil {
			return
		}
	}
	return
}

func (m *Email) sendDispatcher(msg []byte, forceTo string) (err error) {
	switch m.senderPort {
	case "465":
		return m.send465_SSLTLS(msg, forceTo)
	case "587":
		return m.send587_STARTTLS(msg, forceTo)
	case "25":
		return m.send25(msg, forceTo)
	default:
		return m.send25(msg, forceTo)
	}
}

func (m *Email) send25(msg []byte, forceTo string) (err error) {
	adr := m.senderHost + ":" + m.senderPort

	// Authenticate
	auth := smtp.PlainAuth(
		"", m.senderUsername, m.senderPassword, m.senderHost)

	// Forced To?
	var to []string
	if forceTo != "" {
		to = []string{forceTo}
	} else {
		to = m.getToCC()
	}

	// Send TO and CC
	err = smtp.SendMail(
		adr,
		auth,
		m.senderEmail,
		to,
		msg)

	return err
}

func (m *Email) send465_SSLTLS(msg []byte, forceTo string) (err error) {
	adr := m.senderHost + ":" + m.senderPort

	// Establish TLS
	config := tls.Config{ServerName: m.senderHost}
	conn, err := tls.Dial("tcp", adr, &config)
	if err != nil {
		return
	}
	defer conn.Close()

	// SMTP Client
	client, err := smtp.NewClient(conn, m.senderHost)
	if err != nil {
		return
	}
	defer client.Quit()

	// Check AUTH extension
	if ok, _ := client.Extension("AUTH"); ok {
		// Authenticate
		auth := smtp.PlainAuth(
			"", m.senderUsername, m.senderPassword, m.senderHost)

		err = client.Auth(auth)
		if err != nil {
			return
		}
	}

	// Mail from
	if err = client.Mail(m.senderEmail); err != nil {
		return
	}

	// Forced To?
	var to []string
	if forceTo != "" {
		to = []string{forceTo}
	} else {
		to = m.getToCC()
	}

	// Recipients
	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			return
		}
	}

	// Data
	w, err := client.Data()
	if err != nil {
		return
	}

	// Write message
	_, err = w.Write(msg)
	if err != nil {
		return
	}

	// Close data
	err = w.Close()
	if err != nil {
		return
	}

	return
}

func (m *Email) send587_STARTTLS(msg []byte, forceTo string) (err error) {
	adr := m.senderHost + ":" + m.senderPort

	// Dial SMTP Submission
	client, err := smtp.Dial(adr)
	if err != nil {
		return
	}
	defer client.Quit()

	// Config
	config := &tls.Config{ServerName: m.senderHost}

	// Start TLS
	err = client.StartTLS(config)
	if err != nil {
		return
	}

	// Check AUTH extension
	if ok, _ := client.Extension("AUTH"); ok {
		// Authenticate
		auth := AuthTLS{
			smtp.PlainAuth(
				"", m.senderUsername, m.senderPassword, m.senderHost)}

		err = client.Auth(auth)
		if err != nil {
			return
		}
	}

	// Mail from
	if err = client.Mail(m.senderEmail); err != nil {
		return
	}

	// Forced To?
	var to []string
	if forceTo != "" {
		to = []string{forceTo}
	} else {
		to = m.getToCC()
	}

	// Recipients
	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			return
		}
	}

	// Data
	w, err := client.Data()
	if err != nil {
		return
	}

	// Write message
	_, err = w.Write(msg)
	if err != nil {
		return
	}

	// Close data
	err = w.Close()
	if err != nil {
		return
	}

	return
}

//------------------------------------------------------------
// Auth fix for TLS
//------------------------------------------------------------

type AuthTLS struct {
	smtp.Auth
}

func (a AuthTLS) Start(server *smtp.ServerInfo) (string, []byte,
	error) {
	server.TLS = true
	return a.Auth.Start(server)
}
