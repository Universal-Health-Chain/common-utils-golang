package contentUtils

import (
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
)

var NewUUIDv4Base58 = func() string {
	randomUuid, _ := uuid.NewRandom()
	uuidBytes, _ := randomUuid.MarshalBinary()
	return base58.Encode(uuidBytes)
}

// NewMultibase58UUIDv4 returns an UUID v4 encoded as multi base58 BTC ("z" prefix).
// See https://tools.ietf.org/id/draft-multiformats-multibase-00.html#rfc.appendix.D.1
func NewMultibase58UUIDv4() string {
	return "z" + NewUUIDv4Base58()
}
