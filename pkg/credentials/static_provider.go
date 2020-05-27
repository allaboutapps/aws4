package credentials

import "errors"

const StaticProviderName = "StaticProvider"

var (
	ErrStaticCredentialsEmpty = errors.New("static credentials are empty")
)

type StaticProvider struct {
	Credentials
}

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

func (s *StaticProvider) Retrieve() (Credentials, error) {
	if len(s.AccessKeyID) == 0 && len(s.SecretAccessKey) == 0 {
		return Credentials{ProviderName: StaticProviderName}, ErrStaticCredentialsEmpty
	}

	if len(s.Credentials.ProviderName) == 0 {
		s.Credentials.ProviderName = StaticProviderName
	}

	return s.Credentials, nil
}

func (s *StaticProvider) IsExpired() bool {
	return false
}
