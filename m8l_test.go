package m8l

import (
    "bytes"
    "testing"
)

func OFF_TestEmail(t *testing.T) {
    var body bytes.Buffer
    body.WriteString("Test message\nBye ❤")

    email := NewEmail("Test subject ❤", &body)

    email.SetSender(map[string]string{
        "email": "example.com",
        "identity": "John Smith ❤",
        "username": "john@example.com",
        "password": "s3cret",
        "host": "mail.example.com",
        "port": "465",
    })

    email.AddTo("Mary Stephens ❤", "mary@example.com")

    err := email.Send()
    if err != nil {
        t.Errorf("TestEmail had error: %v", err)
    }

    email.AddTo("Joe Dawkins ❤", "joe@example.com")
    email.AddBCC("Mary Howly ❤", "mh@example.com")

    err = email.Send()
    if err != nil {
        t.Errorf("TestEmail had error: %v", err)
    }
}

