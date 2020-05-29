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

type SigningContext struct {
	Request         *http.Request
	Body            io.ReadSeeker
	Query           url.Values
	Credentials     credentials.Credentials
	Region          string
	Service         string
	Time            time.Time
	Expiry          time.Duration
	IsPresign       bool
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

func (s *SigningContext) sanitizeHost() {
	util.SanitizeHost(s.Request)
}

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

func (s *SigningContext) buildTime() {
	if s.IsPresign {
		s.Query.Set("X-Amz-Date", util.FormatDateTime(s.Time))
		s.Query.Set("X-Amz-Expires", strconv.FormatInt(int64(s.Expiry/time.Second), 10))
	} else {
		s.Request.Header.Set("X-Amz-Date", util.FormatDateTime(s.Time))
	}
}

func (s *SigningContext) buildCredentialScope() {
	s.credentialScope = strings.Join([]string{
		util.FormatDate(s.Time),
		s.Region,
		s.Service,
		util.RequestTypeAWS4,
	}, "/")
}

func (s *SigningContext) buildCredential() {
	s.buildCredentialScope()

	if s.IsPresign {
		s.Query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s", s.Credentials.AccessKeyID, s.credentialScope))
	}
}

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

func (s *SigningContext) buildStringToSign() {
	h := sha256.New()
	_, _ = h.Write([]byte(s.canonicalRequest))

	s.stringToSign = strings.Join([]string{
		util.Algorithm,
		util.FormatDateTime(s.Time),
		s.credentialScope,
		hex.EncodeToString(h.Sum(nil)),
	}, "\n")
}

func (s *SigningContext) buildSignature() {
	key := s.Credentials.DeriveSigningKey(s.Time, s.Region, s.Service)
	skey := hex.EncodeToString(key)
	if len(skey) == 0 {
		return
	}

	sig := util.HMACSHA256(key, []byte(s.stringToSign))

	s.signature = hex.EncodeToString(sig)
}

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

func (s *SigningContext) parseTime() error {
	var err error
	if s.IsPresign {
		s.Time, err = util.ParseDateTime(s.origQuery.Get("X-Amz-Date"))
		if err != nil {
			return err
		}

		exp, err := strconv.ParseInt(s.origQuery.Get("X-Amz-Expires"), 10, 64)
		if err != nil {
			return err
		}

		s.Expiry = time.Duration(exp) * time.Second
	} else {
		s.Time, err = util.ParseDateTime(s.Request.Header.Get("X-Amz-Date"))
		if err != nil {
			return err
		}
	}

	if s.timeNowFunc == nil {
		s.timeNowFunc = time.Now
	}

	if s.Expiry > 0 && s.timeNowFunc().After(s.Time.Add(s.Expiry)) {
		return ErrExpiredSignature
	}

	s.buildTime()

	return nil
}

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
