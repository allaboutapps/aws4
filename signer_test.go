package aws4_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/allaboutapps/aws4"
	"github.com/allaboutapps/aws4/pkg/util"
)

func TestSignerSign(t *testing.T) {
	req, err := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	signTime, err := time.Parse(util.TimeFormatISO8601DateTime, "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", util.FormatDateTime(signTime))

	signer := aws4.NewSignerWithStaticCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")

	err = signer.Sign(req, nil, "iam", "us-east-1", signTime)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedAuth := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

	if e, g := expectedAuth, req.Header.Get("Authorization"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSignerPresign(t *testing.T) {
	req, err := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	signTime, err := time.Parse(util.TimeFormatISO8601DateTime, "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", util.FormatDateTime(signTime))

	signer := aws4.NewSignerWithStaticCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")

	err = signer.Presign(req, nil, "iam", "us-east-1", 60*time.Second, signTime)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedSig := "63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3"

	q := req.URL.Query()
	if e, g := expectedSig, q.Get("X-Amz-Signature"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSignerValidateSigned(t *testing.T) {
	signedURL := "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
	req, err := http.NewRequest("GET", signedURL, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	signTime, err := time.Parse(util.TimeFormatISO8601DateTime, "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", util.FormatDateTime(signTime))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")

	signer := aws4.NewSignerWithStaticCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")
	signer.TimeNowFunc = func() time.Time { return signTime }

	sc, err := signer.Validate(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if e, g := signedURL, sc.Request.URL.String(); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSignerValidatePresigned(t *testing.T) {
	presignedURL := "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&X-Amz-Signature=63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3"
	req, err := http.NewRequest("GET", presignedURL, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	signTime, err := time.Parse(util.TimeFormatISO8601DateTime, "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", util.FormatDateTime(signTime))

	signer := aws4.NewSignerWithStaticCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")
	signer.TimeNowFunc = func() time.Time { return signTime }

	sc, err := signer.Validate(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if e, g := presignedURL, sc.Request.URL.String(); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}
