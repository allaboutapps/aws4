package credentials

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestCredentialsDeriveSigningKey(t *testing.T) {
	signTime, err := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	c := Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}

	key := c.DeriveSigningKey(signTime, "us-east-1", "iam")

	expectedKey := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"

	if e, g := expectedKey, hex.EncodeToString(key); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}
