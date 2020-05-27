package aws4

import (
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/allaboutapps/aws4/pkg/credentials"
)

type Signer struct {
	provider credentials.Provider
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

func (s *Signer) Presign(req *http.Request, body io.ReadSeeker, service string, region string, expiry time.Duration, signTime time.Time) error {
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
		IsPresign:   true,
	}

	for k := range sc.Query {
		sort.Strings(sc.Query[k])
	}

	sc.cleanupPresign()

	sc.sanitizeHost()

	if err := sc.build(); err != nil {
		return err
	}

	return nil
}
