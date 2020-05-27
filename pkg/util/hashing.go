package util

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HMACSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}