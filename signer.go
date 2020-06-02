package aws4

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/allaboutapps/aws4/pkg/credentials"
)

// Signer allows for signing and presigning HTTP requests as well as verifying request signatures
type Signer struct {
	// The provider to use for retrieving credentials to sign the request against. Must be
	// provided in order to sign requests.
	Provider credentials.Provider
	// Returns a time value representing the current time. This should only be used
	// for unit testing and omitted otherwise, defaulting to time.Now if not provided or nil.
	timeNowFunc func() time.Time
}

// NewSigner returns a new Signer with the given provider set.
func NewSigner(provider credentials.Provider) *Signer {
	return &Signer{
		Provider: provider,
	}
}

// NewSignerWithTimeNowFunc returns a new Signer with the given provider and a custom function
// for returning the current time set. This should only be used for unit testing, Signer will
// default to the current time if no custom function has been defined.
func NewSignerWithTimeNowFunc(provider credentials.Provider, timeNowFunc func() time.Time) *Signer {
	s := NewSigner(provider)
	s.timeNowFunc = timeNowFunc

	return s
}

// NewSignerWithStaticCredentials returns a new Signer with a static credentials provider set,
// using the given access key ID, secret and optional session token as signing credentials.
func NewSignerWithStaticCredentials(id string, secret string, token string) *Signer {
	return NewSigner(credentials.NewStaticProvider(id, secret, token))
}

// Sign signs the provided request using its body, the requested service and region at the specified signing time.
//
// Sign will modify the request, escaping the host and URL as required and adding headers containing signature values.
// This type of signing is intended for requests that will not be shared and can be performed while maintaining the
// defined header values.
//
// If no error is returned, the request originally provided will contain all information necessary and can be executed
// using standard Go HTTP clients to perform the signed request. Should an error be returned instead, discarding
// the original request is advised before attempting to sign it again since it may contain a half-completed signature.
func (s *Signer) Sign(req *http.Request, body io.ReadSeeker, service string, region string, signTime time.Time) error {
	return s.signRequest(req, body, service, region, 0, signTime, false)
}

// Presign signs the provided request using its body, the requested service and region at the specified signing time.
// It also allows for an expiry to be defined after which the request's signature becomes invalid. Passing an expiry of
// 0 disables this additional check, creating a signature with unlimited validity.
//
// Presign will modify the request, escaping the host and URL as required and adding query parameters containing signature values.
// This type of signing is intended for requests that are shared with third parties or performed in a way that cannot preserve
// the defined header values. Note that all header values provided with the original request must be provided when performing
// the request after signing since they are included in the signature.
//
// If no error is returned, the request originally provided will contain all information necessary and can be executed
// using standard Go HTTP clients to perform the signed request. Should an error be returned instead, discarding
// the original request is advised before attempting to sign it again since it may contain a half-completed signature.
func (s *Signer) Presign(req *http.Request, body io.ReadSeeker, service string, region string, expiry time.Duration, signTime time.Time) error {
	return s.signRequest(req, body, service, region, expiry, signTime, true)
}

// Validate validates the provided request, returning a parsed SigningContext containing information about the signature.
// If the signature is malformed or invalid, an error is returned instead.
//
// Validate can be used to validate signed as well as presigned requests using the credentials associated with the Signer.
// During validation, the request is modified (as the signature will be re-generated using the Signer's credentials to verify it),
// however after successful validation, it will be restored to its original state.
//
// If no error is returned, the request can be assumed to contain a valid signature and can be continued to be processed. Should
// an error be returned instead, the original request should not be processed any further as the signature might be invalid and the
// request might be in a modified, invalid state.
func (s *Signer) Validate(req *http.Request) (*SigningContext, error) {
	if len(req.URL.Query().Get("X-Amz-Signature")) > 0 {
		return s.validateRequest(req, true)
	} else if len(req.Header.Get("Authorization")) > 0 {
		return s.validateRequest(req, false)
	}

	return nil, ErrMalformedSignature
}

// signRequest performs request signing, retrieving the Signer's credentials and creating a signing context.
func (s *Signer) signRequest(req *http.Request, body io.ReadSeeker, service string, region string, expiry time.Duration, signTime time.Time, isPresign bool) error {
	credentials, err := s.Provider.Retrieve()
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
		SignTime:    signTime,
		Expiry:      expiry,
		IsPresign:   isPresign,
		timeNowFunc: s.timeNowFunc,
	}

	if err = sc.Build(); err != nil {
		return err
	}

	sc.AddSigToRequest()

	return nil
}

// validateRequests performs request validation, retrieving the Signer's credentials and creating a signing context. If the
// request has a body, it will be read and restored as a ioutil.NopCloser so hash can be calculated and the request can still
// be processed normally afterwards.
func (s *Signer) validateRequest(req *http.Request, isPresign bool) (*SigningContext, error) {
	credentials, err := s.Provider.Retrieve()
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
		timeNowFunc: s.timeNowFunc,
		origQuery:   req.URL.Query(),
	}

	if err = sc.Parse(); err != nil {
		return nil, err
	}

	sc.AddSigToRequest()

	return sc, nil
}
