package credentials

import "errors"

// StaticProviderName represents the name of the static credentials provider
const StaticProviderName = "StaticProvider"

var (
	// ErrStaticCredentialsEmpty indicates missing credentials required for a static provider
	ErrStaticCredentialsEmpty = errors.New("static credentials are empty")
)

// StaticProvider implements a provider using a static set of credentials, returning the
// defined access key and optional session token. No expiry or renewal will be managed
// by the provider.
type StaticProvider struct {
	Credentials
}

// NewStaticProvider returns a new static credentials provider using the given set of credentials.
func NewStaticProvider(id string, secret string, token string) *StaticProvider {
	return &StaticProvider{
		Credentials{
			AccessKeyID:     id,
			SecretAccessKey: secret,
			SessionToken:    token,
			ProviderName:    StaticProviderName,
		},
	}
}

// Retrieve verifies the required static credentials are available and returns them.
func (s *StaticProvider) Retrieve() (Credentials, error) {
	if len(s.AccessKeyID) == 0 && len(s.SecretAccessKey) == 0 {
		return Credentials{ProviderName: StaticProviderName}, ErrStaticCredentialsEmpty
	}

	if len(s.Credentials.ProviderName) == 0 {
		s.Credentials.ProviderName = StaticProviderName
	}

	return s.Credentials, nil
}

// IsExpired returns whether the stored credentials are expired. In the case of a static provider,
// this will always return false since expiry is not managed by the provider.
func (s *StaticProvider) IsExpired() bool {
	return false
}
