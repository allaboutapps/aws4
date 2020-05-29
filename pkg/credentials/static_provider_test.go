package credentials

import (
	"testing"
)

func TestStaticProviderRetrieve(t *testing.T) {
	expectedID := "AKID"
	expectedSecret := "SECRET"
	expectedToken := "SESSION"

	provider := NewStaticProvider(expectedID, expectedSecret, expectedToken)

	creds, err := provider.Retrieve()
	if err != nil {
		t.Fatalf("expected no error, got %q", err)
	}

	if e, g := expectedID, creds.AccessKeyID; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedSecret, creds.SecretAccessKey; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedToken, creds.SessionToken; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}

	provider = NewStaticProvider(expectedID, expectedSecret, "")

	creds, err = provider.Retrieve()
	if err != nil {
		t.Fatalf("expected no error, got %q", err)
	}

	if e, g := expectedID, creds.AccessKeyID; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedSecret, creds.SecretAccessKey; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := "", creds.SessionToken; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}

	provider = NewStaticProvider("", "", "")

	creds, err = provider.Retrieve()
	if err != ErrStaticCredentialsEmpty {
		t.Fatalf("expected %v, got %q", ErrStaticCredentialsEmpty, err)
	}
}

func TestStaticProviderIsExpired(t *testing.T) {
	provider := NewStaticProvider("AKID", "SECRET", "SESSION")

	expired := provider.IsExpired()
	if e, g := false, expired; e != g {
		t.Errorf("expected %v, got %v", e, g)
	}
}
