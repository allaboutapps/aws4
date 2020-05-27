package aws4_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/allaboutapps/aws4"
	"github.com/allaboutapps/aws4/pkg/util"
)

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
		t.Errorf("expected %s, got %s", e, g)
	}
}
