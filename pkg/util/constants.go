package util

const (
	// Algorithm represents the algorithm and version used for signatures.
	Algorithm = "AWS4-HMAC-SHA256"
	// TimeFormatISO8601DateTime represents the Go time format for an ISO 8601 date time string.
	TimeFormatISO8601DateTime = "20060102T150405Z"
	// TimeFormatISO8601DateTime represents the Go time format for an ISO 8601 date string.
	TimeFormatISO8601Date = "20060102"
	// RequestTypeAWS4 represents the type of requests signed by the Signer.
	RequestTypeAWS4 = "aws4_request"
	// HashUnsignedPayload represents a predefined hash for an unsigned payload.
	HashUnsignedPayload = "UNSIGNED-PAYLOAD"
	// HashEmptyPayload represents the SHA256 hash of an empty payload (an empty string).
	HashEmptyPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
