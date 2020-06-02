package aws4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/allaboutapps/aws4/pkg/credentials"
	"github.com/allaboutapps/aws4/pkg/util"
)

var (
	ErrMalformedSignature        = errors.New("malformed signature")
	ErrExpiredSignature          = errors.New("expired signature")
	ErrInvalidSignature          = errors.New("invalid signature")
	ErrInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")

	ignoredHeaders = map[string]struct{}{
		"Authorization":   {},
		"User-Agent":      {},
		"X-Amzn-Trace-Id": {},
	}
)

const (
	authHeaderPartsLen = 3
	credentialPartsLen = 5
)

// SigningContext stores information relevant to signing a request
type SigningContext struct {
	// Original HTTP request to sign, will be modified during signing and signature validation
	Request *http.Request
	// Body of the request
	Body io.ReadSeeker
	// Query of the original HTTP request, used for preparing a presigned signature while processing
	Query url.Values
	// Credentials to sign request with or validate against
	Credentials credentials.Credentials
	// Region of service request is sent for
	Region string
	// Service request is sent for
	Service string
	// Signing time for request
	SignTime time.Time
	// Expiry of request signature, 0 indicating a signature with no expiry
	Expiry time.Duration
	// Indicates whether the request is unsigned
	IsPresign bool
	// Toggles whether payload signing should be skipped
	UnsignedPayload bool

	credentialScope  string
	bodyHash         string
	signedHeaders    string
	canonicalHeaders string
	canonicalRequest string
	stringToSign     string
	signature        string

	origQuery   url.Values
	timeNowFunc func() time.Time
}

// Build builds a signature for the request using the given signing context.
//
// If no error is returned, the signing context's request will have all required values set and can
// be used to perform a signed request. Should an error be returned instead, discarding the signing
// context is advised before attempting to build it again since it may contain a half-completed signature.
func (s *SigningContext) Build() error {
	for k := range s.Query {
		sort.Strings(s.Query[k])
	}

	s.cleanupPresign(true)
	s.sanitizeHost()

	s.buildBasicQueryValues()
	s.buildTime()
	s.buildCredential()

	if err := s.buildBodyHash(); err != nil {
		return err
	}

	s.buildCanonicalHeaders(ignoredHeaders)
	s.buildCanonicalRequest()
	s.buildStringToSign()
	s.buildSignature()

	return nil
}

// Parse parses the signed requests into the given signing context, verifying its signature in the process.
//
// If no error is returned, the signing context will have its values filled out and the original request restored,
// ready to be processed by the consuming party. Should an error be returned instead, discarding the signing
// context is advised before attempting to build it again since it may contain a half-completed signature.
func (s *SigningContext) Parse() error {
	for k := range s.Query {
		sort.Strings(s.Query[k])
	}

	s.cleanupPresign(true)
	s.sanitizeHost()

	var err error

	if err = s.parseBasicQueryValues(); err != nil {
		return err
	}
	if err = s.parseTime(); err != nil {
		return err
	}
	if err = s.parseCredential(); err != nil {
		return err
	}
	if err = s.buildBodyHash(); err != nil {
		return err
	}
	if err = s.parseCanonicalRequest(); err != nil {
		return err
	}
	if err = s.parseSignature(); err != nil {
		return err
	}

	return nil
}

// AddSigToRequest adds the calculated request signature to the request's header or query, depending on whether
// the request should be signed or presigned.
func (s *SigningContext) AddSigToRequest() {
	if s.IsPresign {
		s.Request.URL.RawQuery = fmt.Sprintf("%s&X-Amz-Signature=%s", s.Request.URL.RawQuery, s.signature)

		return
	}

	s.Request.Header.Set("Authorization", strings.Join([]string{
		fmt.Sprintf("%s Credential=%s/%s", util.Algorithm, s.Credentials.AccessKeyID, s.credentialScope),
		fmt.Sprintf("SignedHeaders=%s", s.signedHeaders),
		fmt.Sprintf("Signature=%s", s.signature),
	}, ", "))
}

// cleanupPresign removes any signature headers for a presigned request so they will not be included in a new signature.
func (s *SigningContext) cleanupPresign(updateRequestURL bool) {
	if !s.IsPresign {
		return
	}

	s.Query.Del("X-Amz-Algorithm")
	s.Query.Del("X-Amz-Signature")
	s.Query.Del("X-Amz-Security-Token")
	s.Query.Del("X-Amz-Date")
	s.Query.Del("X-Amz-Expires")
	s.Query.Del("X-Amz-Credential")
	s.Query.Del("X-Amz-SignedHeaders")

	if updateRequestURL {
		s.Request.URL.RawQuery = s.Query.Encode()
	}
}

// sanitizeHost sanitizes the request's host before signing it.
func (s *SigningContext) sanitizeHost() {
	util.SanitizeHost(s.Request)
}

// buildBasicQueryValues sets the algorithm and security token query values required for presigned requests and
// adds the security token to the request headers for regular signed requests if defined.
func (s *SigningContext) buildBasicQueryValues() {
	if s.IsPresign {
		s.Query.Set("X-Amz-Algorithm", util.Algorithm)

		if len(s.Credentials.SessionToken) == 0 {
			s.Query.Del("X-Amz-Security-Token")
		} else {
			s.Query.Set("X-Amz-Security-Token", s.Credentials.SessionToken)
		}

		return
	}

	if len(s.Credentials.SessionToken) > 0 {
		s.Request.Header.Set("X-Amz-Security-Token", s.Credentials.SessionToken)
	}
}

// buildTime adds the signing time and optional expiry to the request.
func (s *SigningContext) buildTime() {
	if s.IsPresign {
		s.Query.Set("X-Amz-Date", util.FormatDateTime(s.SignTime))
		s.Query.Set("X-Amz-Expires", strconv.FormatInt(int64(s.Expiry/time.Second), 10))
	} else {
		s.Request.Header.Set("X-Amz-Date", util.FormatDateTime(s.SignTime))
	}
}

// buildCredentialScope builds the credential scope for the signing context.
func (s *SigningContext) buildCredentialScope() {
	s.credentialScope = strings.Join([]string{
		util.FormatDate(s.SignTime),
		s.Region,
		s.Service,
		util.RequestTypeAWS4,
	}, "/")
}

// buildCredential builds the credential scope and adds the credential query param to presigned requests.
func (s *SigningContext) buildCredential() {
	s.buildCredentialScope()

	if s.IsPresign {
		s.Query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s", s.Credentials.AccessKeyID, s.credentialScope))
	}
}

// buildBodyHash sets the body hash for the signing context, using the X-Amz-Context-Sha256 header if available.
// Should no predefined hash be set, buildBodyHash determines whether a signature should be generated from the
// request's body and calculates the SHA256 sum if required.
func (s *SigningContext) buildBodyHash() (err error) {
	hash := s.Request.Header.Get("X-Amz-Content-Sha256")
	if len(hash) == 0 {
		includeHeader := s.UnsignedPayload ||
			s.Service == "s3" ||
			s.Service == "glacier"

		s3Presign := s.IsPresign && s.Service == "s3"

		if s.UnsignedPayload || s3Presign {
			hash = util.HashUnsignedPayload
			includeHeader = !s3Presign
		} else if s.Body == nil {
			hash = util.HashEmptyPayload
		} else {
			h := sha256.New()

			start, err := s.Body.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}

			defer func() {
				_, err = s.Body.Seek(start, io.SeekStart)
			}()

			_, err = io.Copy(h, s.Body)
			if err != nil {
				return err
			}

			hash = hex.EncodeToString(h.Sum(nil))
		}

		if includeHeader {
			s.Request.Header.Set("X-Amz-Content-Sha256", hash)
		}
	}

	s.bodyHash = hash

	return nil
}

// buildCanonicalHeaders creates a canonical form of headers to be signed with the request.
// All header values will be escaped before serialization.
func (s *SigningContext) buildCanonicalHeaders(ignoredHeaders map[string]struct{}) {
	headers := make([]string, 0)
	headerVals := make(http.Header)
	for k, vv := range s.Request.Header {
		if _, ok := ignoredHeaders[http.CanonicalHeaderKey(k)]; ok {
			continue
		}

		lowerKey := strings.ToLower(k)
		headers = append(headers, lowerKey)
		headerVals[lowerKey] = vv
	}
	headers = append(headers, "host")

	sort.Strings(headers)

	s.signedHeaders = strings.Join(headers, ";")

	if s.IsPresign {
		s.Query.Set("X-Amz-SignedHeaders", s.signedHeaders)
	}

	var sb strings.Builder
	for _, k := range headers {
		sb.WriteString(k)
		sb.WriteRune(':')
		switch {
		case k == "host":
			sb.WriteString(util.GetHost(s.Request))
			fallthrough
		default:
			for idx, v := range headerVals[k] {
				if idx > 0 {
					sb.WriteRune(',')
				}
				sb.WriteString(util.TrimAll(v))
			}
			sb.WriteRune('\n')
		}
	}

	s.canonicalHeaders = sb.String()
}

// buildCanonicalRequest creates a canonical form of the request, including all information required to
// verify a request, updating the request's URL with the new encoded query.
func (s *SigningContext) buildCanonicalRequest() {
	s.Request.URL.RawQuery = strings.Replace(s.Query.Encode(), "+", "%20", -1)

	url := util.GetURLPath(s.Request.URL)

	s.canonicalRequest = strings.Join([]string{
		s.Request.Method,
		url,
		s.Request.URL.RawQuery,
		s.canonicalHeaders,
		s.signedHeaders,
		s.bodyHash,
	}, "\n")
}

// buildStringToSign creates a hash of the canonical request, combining it with information about the algorithm.
// and credential scope for verification.
func (s *SigningContext) buildStringToSign() {
	h := sha256.New()
	_, _ = h.Write([]byte(s.canonicalRequest))

	s.stringToSign = strings.Join([]string{
		util.Algorithm,
		util.FormatDateTime(s.SignTime),
		s.credentialScope,
		hex.EncodeToString(h.Sum(nil)),
	}, "\n")
}

// buildSignature derives a signing key from the Signer's credentials and creates a HMAC-SHA256 signature
// of the stringToSign.
func (s *SigningContext) buildSignature() {
	key := s.Credentials.DeriveSigningKey(s.SignTime, s.Region, s.Service)
	skey := hex.EncodeToString(key)
	if len(skey) == 0 {
		return
	}

	sig := util.HMACSHA256(key, []byte(s.stringToSign))

	s.signature = hex.EncodeToString(sig)
}

// parseBasicQueryValues parses the algorithm and security token values from a request and stores it in
// the signing context, returning an error if they are missing, malformed or do not match the credentials
// stored by the Signer.
func (s *SigningContext) parseBasicQueryValues() error {
	if s.IsPresign {
		if s.origQuery.Get("X-Amz-Algorithm") != util.Algorithm {
			return ErrInvalidSignatureAlgorithm
		}

		if s.origQuery.Get("X-Amz-Security-Token") != s.Credentials.SessionToken {
			return ErrInvalidSignature
		}
	} else {
		auth := strings.Split(s.Request.Header.Get("Authorization"), ", ")
		if len(auth) != authHeaderPartsLen {
			return ErrMalformedSignature
		}

		if !strings.HasPrefix(auth[0], util.Algorithm) {
			return ErrInvalidSignatureAlgorithm
		}

		if s.Request.Header.Get("X-Amz-Security-Token") != s.Credentials.SessionToken {
			return ErrInvalidSignature
		}
	}

	s.buildBasicQueryValues()

	return nil
}

// parseTime parses the signing time and optionally expiry from the request, storing them in
// the signing context. If an expiry has been set, it will be checked against the current time
// retrieved via the timeNowFunc.
func (s *SigningContext) parseTime() error {
	var err error
	if s.IsPresign {
		s.SignTime, err = util.ParseDateTime(s.origQuery.Get("X-Amz-Date"))
		if err != nil {
			return err
		}

		exp, err := strconv.ParseInt(s.origQuery.Get("X-Amz-Expires"), 10, 64)
		if err != nil {
			return err
		}

		s.Expiry = time.Duration(exp) * time.Second
	} else {
		s.SignTime, err = util.ParseDateTime(s.Request.Header.Get("X-Amz-Date"))
		if err != nil {
			return err
		}
	}

	if s.timeNowFunc == nil {
		s.timeNowFunc = time.Now
	}

	if s.Expiry > 0 && s.timeNowFunc().After(s.SignTime.Add(s.Expiry)) {
		return ErrExpiredSignature
	}

	s.buildTime()

	return nil
}

// parseCredential parses the credential value of the requests, storing it in the signing
// context. This sets the context's region and service as well.
func (s *SigningContext) parseCredential() error {
	var cred string
	if s.IsPresign {
		cred = s.origQuery.Get("X-Amz-Credential")
		if len(cred) == 0 {
			return ErrMalformedSignature
		}
	} else {
		auth := strings.Split(s.Request.Header.Get("Authorization"), ", ")
		if len(auth) != authHeaderPartsLen {
			return ErrMalformedSignature
		}

		if len(auth[0]) <= len(util.Algorithm)+1 {
			return ErrMalformedSignature
		}

		c := auth[0][len(util.Algorithm)+1:]
		if !strings.HasPrefix(c, "Credential=") {
			return ErrMalformedSignature
		}

		cred = strings.TrimPrefix(c, "Credential=")
	}

	credParts := strings.Split(cred, "/")
	if len(credParts) != credentialPartsLen {
		return ErrMalformedSignature
	}

	if credParts[4] != util.RequestTypeAWS4 {
		return ErrMalformedSignature
	}

	if s.Credentials.AccessKeyID != credParts[0] {
		return ErrInvalidSignature
	}

	s.Region = credParts[2]
	s.Service = credParts[3]
	s.credentialScope = strings.Join(credParts[1:], "/")

	if s.IsPresign {
		s.Query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s", s.Credentials.AccessKeyID, s.credentialScope))
	}

	return nil
}

// parseCanonicalRequest parses the request's canonical request, verifying the signed
// headers and building a new canonical request to sign.
func (s *SigningContext) parseCanonicalRequest() error {
	var reqSignedHeaders string
	if s.IsPresign {
		reqSignedHeaders = s.origQuery.Get("X-Amz-SignedHeaders")
		if len(reqSignedHeaders) == 0 {
			return ErrMalformedSignature
		}
	} else {
		auth := strings.Split(s.Request.Header.Get("Authorization"), ", ")
		if len(auth) != authHeaderPartsLen {
			return ErrMalformedSignature
		}

		if !strings.HasPrefix(auth[1], "SignedHeaders=") {
			return ErrMalformedSignature
		}

		reqSignedHeaders = strings.TrimPrefix(auth[1], "SignedHeaders=")
	}

	if len(reqSignedHeaders) == 0 {
		return ErrMalformedSignature
	}

	s.buildCanonicalHeaders(ignoredHeaders)

	if reqSignedHeaders != s.signedHeaders {
		return ErrInvalidSignature
	}

	s.buildCanonicalRequest()

	return nil
}

// parseSignature parses the request's signature and verifies it against the actual
// signature calculated for the current signing context.
func (s *SigningContext) parseSignature() error {
	var reqSignature string
	if s.IsPresign {
		reqSignature = s.origQuery.Get("X-Amz-Signature")
		if len(reqSignature) == 0 {
			return ErrMalformedSignature
		}
	} else {
		auth := strings.Split(s.Request.Header.Get("Authorization"), ", ")
		if len(auth) != authHeaderPartsLen {
			return ErrMalformedSignature
		}

		if !strings.HasPrefix(auth[2], "Signature=") {
			return ErrMalformedSignature
		}

		reqSignature = strings.TrimPrefix(auth[2], "Signature=")
	}

	if len(reqSignature) == 0 {
		return ErrMalformedSignature
	}

	s.buildStringToSign()
	s.buildSignature()

	if reqSignature != s.signature {
		return ErrInvalidSignature
	}

	return nil
}
