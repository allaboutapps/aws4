package credentials

// Provider presents an interface for retrieving credentials.
type Provider interface {
	// Retrieve returns a set of credentials or an error if retrieval failed.
	Retrieve() (Credentials, error)
	// IsExpired indicates whether the credentials managed by the provider have expired.
	IsExpired() bool
}
