package didCommunicationUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/stretchr/testify/assert"
)

func Test_NonSignedJWT(t *testing.T) {
	unsignedMockedJWT := "A.B." // 3 parts (as mandatory for a JWT) but without signature
	partsJWT := joseUtils.GetPartsJWT(&unsignedMockedJWT)
	assert.Equal(t, 0, len(*partsJWT.Signature))
	// fmt.Printf("signature len = %v\n", len(*partsJWT.Signature))
}
