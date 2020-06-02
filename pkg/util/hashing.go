package util

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 creates a HMAC-SHA256 signature of the given data using the provided key, ignoring any errors
// returned for caller's convenience and easier chaining.
func HMACSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}
