package storageUtils

import (
	"crypto/rand"

	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
	"github.com/mr-tron/base58"
	// "github.com/btcsuite/btcutil/base58"
)

const EdvIDSize = 16

// Generates a secure ID but deterministically,
// where the size in bytes for the ID is 16 bytes
// and the result is encoded in Base58.
func GenerateIdentifierDeterministicallyForEDV(inputIdentifier string, hmacKeyBytes []byte) string {
	if inputIdentifier == "" {
		return ""
	}

	keyHash := contentUtils.ComputeMAC([]byte(inputIdentifier), hmacKeyBytes)
	return base58.Encode(keyHash[0:EdvIDSize])
}

type generateRandomBytesFunc func([]byte) (int, error)

// Generates a secure ID
// but using a cryptographically secure random number generator.
func GenerateEDVCompatibleID() (string, error) {
	return generateEDVCompatibleID(rand.Read)
}

func generateEDVCompatibleID(generateRandomBytes generateRandomBytesFunc) (string, error) {
	randomBytes := make([]byte, 16)

	_, err := generateRandomBytes(randomBytes)
	if err != nil {
		return "", err
	}

	base58EncodedUUID := base58.Encode(randomBytes)

	return base58EncodedUUID, nil
}
