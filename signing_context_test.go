package aws4

import (
	"net/http"
	"testing"
	"time"

	"github.com/allaboutapps/aws4/pkg/credentials"
	"github.com/allaboutapps/aws4/pkg/util"
)

func buildRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	return req
}

func getSignTime(t *testing.T) time.Time {
	t.Helper()

	signTime, err := time.Parse(util.TimeFormatISO8601DateTime, "20150830T123600Z")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	return signTime
}

func buildSigningContext(t *testing.T) *SigningContext {
	t.Helper()

	req := buildRequest(t)
	signTime := getSignTime(t)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", util.FormatDateTime(signTime))

	sc := &SigningContext{
		Request: req,
		Body:    nil,
		Query:   req.URL.Query(),
		Credentials: credentials.Credentials{
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		},
		Region:    "us-east-1",
		Service:   "iam",
		Time:      getSignTime(t),
		Expiry:    60 * time.Second,
		IsPresign: true,
	}

	sc.cleanupPresign(true)
	sc.sanitizeHost()

	return sc
}

func TestSigningContextBuildBasicQueryValues(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildBasicQueryValues()

	expectedAlg := "AWS4-HMAC-SHA256"
	expectedToken := ""

	if e, g := expectedAlg, sc.Query.Get("X-Amz-Algorithm"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedToken, sc.Query.Get("X-Amz-Security-Token"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}

	sc.Credentials.SessionToken = "TOKEN"

	sc.buildBasicQueryValues()

	expectedToken = "TOKEN"

	if e, g := expectedAlg, sc.Query.Get("X-Amz-Algorithm"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedToken, sc.Query.Get("X-Amz-Security-Token"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildTime(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildTime()

	expectedTime := "20150830T123600Z"
	expectedExpiry := "60"

	if e, g := expectedTime, sc.Query.Get("X-Amz-Date"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedExpiry, sc.Query.Get("X-Amz-Expires"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildCredentialScope(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildCredentialScope()

	expectedCredentialScope := "20150830/us-east-1/iam/aws4_request"

	if e, g := expectedCredentialScope, sc.credentialScope; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildCredential(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildCredential()

	expectedCredentialScope := "20150830/us-east-1/iam/aws4_request"
	expectedCredential := "AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"

	if e, g := expectedCredentialScope, sc.credentialScope; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedCredential, sc.Query.Get("X-Amz-Credential"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildBodyHash(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	err := sc.buildBodyHash()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedBodyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if e, g := expectedBodyHash, sc.bodyHash; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := "", sc.Query.Get("X-Amz-Content-Sha256"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildCanonicalHeaders(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildCanonicalHeaders(ignoredHeaders)

	expectedSignedHeaders := "content-type;host;x-amz-date"
	expectedCanonicalHeaders := `content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z
`

	if e, g := expectedSignedHeaders, sc.signedHeaders; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedCanonicalHeaders, sc.canonicalHeaders; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
	if e, g := expectedSignedHeaders, sc.Query.Get("X-Amz-SignedHeaders"); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildCanonicalRequest(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildBasicQueryValues()
	sc.buildTime()
	sc.buildCredential()
	err := sc.buildBodyHash()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	sc.buildCanonicalHeaders(ignoredHeaders)
	sc.buildCanonicalRequest()

	expectedCanonicalRequest := `GET
/
Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	if e, g := expectedCanonicalRequest, sc.canonicalRequest; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildStringToSign(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildBasicQueryValues()
	sc.buildTime()
	sc.buildCredential()
	err := sc.buildBodyHash()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	sc.buildCanonicalHeaders(ignoredHeaders)
	sc.buildCanonicalRequest()
	sc.buildStringToSign()

	expectedStringToSign := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
829d0ec8859c4877fb1709979fe8ef44a082303f2517ff2a1f335b6b0b1392fa`

	if e, g := expectedStringToSign, sc.stringToSign; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}

	// Manually set values of signing example (without presign) from AWS docs, taken from
	// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html (2020-05-27T15:28:30Z)
	sc = &SigningContext{
		Time:            getSignTime(t),
		credentialScope: "20150830/us-east-1/iam/aws4_request",
		canonicalRequest: `GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
	}

	sc.buildStringToSign()

	expectedStringToSign = `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`

	if e, g := expectedStringToSign, sc.stringToSign; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildSignature(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	sc.buildBasicQueryValues()
	sc.buildTime()
	sc.buildCredential()
	err := sc.buildBodyHash()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	sc.buildCanonicalHeaders(ignoredHeaders)
	sc.buildCanonicalRequest()
	sc.buildStringToSign()
	sc.buildSignature()

	expectedSignature := "63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3"

	if e, g := expectedSignature, sc.signature; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}

	// Manually set values of signing example (without presign) from AWS docs, taken from
	// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html (2020-05-27T15:28:30Z)
	sc = &SigningContext{
		Credentials: credentials.Credentials{
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		},
		Region:  "us-east-1",
		Service: "iam",
		Time:    getSignTime(t),
		stringToSign: `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`,
	}

	sc.buildSignature()

	expectedSignature = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

	if e, g := expectedSignature, sc.signature; e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuild(t *testing.T) {
	t.Parallel()

	sc := buildSigningContext(t)

	err := sc.Build()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	sc.AddSigToRequest()

	expectedURL := "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&X-Amz-Signature=63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3"

	if e, g := expectedURL, sc.Request.URL.String(); e != g {
		t.Errorf("expected %q, got %q", e, g)
	}
}

func TestSigningContextBuildWithPort(t *testing.T) {
	t.Parallel()

	// Testcases from AWS SDK repository, taken from:
	// https://github.com/aws/aws-sdk-go/blob/bcb2cf3fc2263c8c28b3119b07d2dbb44d7c93a0/aws/signer/v4/functional_test.go#L229 (2020-05-27T15:28:30Z)
	tests := []struct {
		name        string
		url         string
		expectedSig string
	}{
		{
			name:        "HTTPS",
			url:         "https://estest.us-east-1.es.amazonaws.com:443/_search",
			expectedSig: "0abcf61a351063441296febf4b485734d780634fba8cf1e7d9769315c35255d6",
		},
		{
			name:        "HTTP",
			url:         "http://example.com:80/_search",
			expectedSig: "fce9976dd6c849c21adfa6d3f3e9eefc651d0e4a2ccd740d43efddcccfdc8179",
		},
		{
			name:        "HTTPS_custom",
			url:         "https://example.com:9200/_search",
			expectedSig: "f33c25a81c735e42bef35ed5e9f720c43940562e3e616ff0777bf6dde75249b0",
		},
		{
			name:        "HTTP_custom",
			url:         "http://example.com:9200/_search",
			expectedSig: "f33c25a81c735e42bef35ed5e9f720c43940562e3e616ff0777bf6dde75249b0",
		},
	}

	creds := credentials.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		SessionToken:    "SESSION",
	}

	signTime := time.Unix(0, 0)

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			sc := &SigningContext{
				Request:     req,
				Body:        nil,
				Query:       req.URL.Query(),
				Credentials: creds,
				Region:      "us-east-1",
				Service:     "es",
				Time:        signTime,
				Expiry:      5 * time.Minute,
				IsPresign:   true,
			}

			err = sc.Build()
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			sc.AddSigToRequest()

			if e, g := tt.expectedSig, sc.Request.URL.Query().Get("X-Amz-Signature"); e != g {
				t.Errorf("%s: expected %q, got %q", tt.name, e, g)
			}
		})
	}
}
