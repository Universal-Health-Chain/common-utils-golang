package contentUtils

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/sha3"
)

// CalculateShake256 is used to generate "xs" & "ds" in Crystals-Dilithium
func CalculateShake256(dataBytes *[]byte) string {
	digestBytes := make([]byte, 32)
	hashFunc := sha3.NewShake256()
	hashFunc.Write(*dataBytes)
	hashFunc.Read(digestBytes)
	digestBase64Url := base64.RawURLEncoding.EncodeToString(digestBytes)
	return digestBase64Url
}

// CalculateSHA256 is used to generate the Thumbprint of a public JSON Web Key (JWK).
func CalculateSHA256(dataBytes *[]byte) string {
	hash := sha256.Sum256(*dataBytes)
	digestBase64Url := base64.RawURLEncoding.EncodeToString(hash[:])
	return digestBase64Url
}

// CalculateSHA3_256 is used to generate the H(pk) in Crystals-Kyber
func CalculateSHA3_256(dataBytes *[]byte) string {
	hash := sha3.Sum256(*dataBytes)
	digestBase64Url := base64.RawURLEncoding.EncodeToString(hash[:])
	return digestBase64Url
}
