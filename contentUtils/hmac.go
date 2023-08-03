package contentUtils

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ComputeMAC creates a message authentication code (MAC), sometimes known as a "tag",
// which is a short piece of information used for authenticating a message,
// by using some deterministic data (the traditional "key" concept) which authenticates the origin of the message,
// where the deterministic data (key) serves to regenerate the expected MAC (tag) for the original message.
// In other words, to confirm a tag matches with the expected data and key (its authenticity).
func ComputeMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// ValidMAC reports whether messageMAC is a valid HMAC tag for message.
// Receivers should be careful to use Equal to compare MACs in order to avoid timing side-channels:
func ValidMAC(message, messageMAC, key []byte) bool {
	expectedMAC := ComputeMAC(message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}
