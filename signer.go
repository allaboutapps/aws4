package aws4

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/allaboutapps/aws4/pkg/credentials"
)

type Signer struct {
	TimeNowFunc func() time.Time
	provider    credentials.Provider
}

func NewSigner(provider credentials.Provider) *Signer {
	return &Signer{
		provider: provider,
	}
}

func NewSignerWithStaticCredentials(id string, secret string, token string) *Signer {
	return &Signer{
		provider: credentials.NewStaticProvider(id, secret, token),
	}
}

func (s *Signer) Sign(req *http.Request, body io.ReadSeeker, service string, region string, signTime time.Time) error {
	return s.signRequest(req, body, service, region, 0, signTime, false)
}

func (s *Signer) Presign(req *http.Request, body io.ReadSeeker, service string, region string, expiry time.Duration, signTime time.Time) error {
	return s.signRequest(req, body, service, region, expiry, signTime, true)
}

func (s *Signer) Validate(req *http.Request) (*SigningContext, error) {
	if len(req.URL.Query().Get("X-Amz-Signature")) > 0 {
		return s.validateRequest(req, true)
	} else if len(req.Header.Get("Authorization")) > 0 {
		return s.validateRequest(req, false)
	}

	return nil, ErrMalformedSignature
}

func (s *Signer) signRequest(req *http.Request, body io.ReadSeeker, service string, region string, expiry time.Duration, signTime time.Time, isPresign bool) error {
	credentials, err := s.provider.Retrieve()
	if err != nil {
		return err
	}

	sc := &SigningContext{
		Request:     req,
		Body:        body,
		Query:       req.URL.Query(),
		Credentials: credentials,
		Region:      region,
		Service:     service,
		Time:        signTime,
		Expiry:      expiry,
		IsPresign:   isPresign,
		timeNowFunc: s.TimeNowFunc,
	}

	if err = sc.Build(); err != nil {
		return err
	}

	sc.AddSigToRequest()

	return nil
}

func (s *Signer) validateRequest(req *http.Request, isPresign bool) (*SigningContext, error) {
	credentials, err := s.provider.Retrieve()
	if err != nil {
		return nil, err
	}

	var body io.ReadSeeker
	if req.Body != nil {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		body = bytes.NewReader(buf)
	}

	sc := &SigningContext{
		Request:     req,
		Body:        body,
		Query:       req.URL.Query(),
		Credentials: credentials,
		IsPresign:   isPresign,
		timeNowFunc: s.TimeNowFunc,
		origQuery:   req.URL.Query(),
	}

	if err = sc.Parse(); err != nil {
		return nil, err
	}

	sc.AddSigToRequest()

	return sc, nil
}
