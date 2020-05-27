package credentials

type Provider interface {
	Retrieve() (Credentials, error)
	IsExpired() bool
}
