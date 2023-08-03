package joseUtils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CreateParts(t *testing.T) {
	headers := Headers{}
	headers[HeaderAlgorithm] = "some algorithm"
	headers[HeaderKeyID] = "some kid"

	payload := map[string]interface{}{
		"sub": "subjectID",
		// "iat":
	}
	jwtParts, err := CreatePartsUnsignedJWT(headers, payload)
	assert.Nil(t, err)
	// fmt.Printf("jwtParts = %v", jwtParts)
	assert.NotNil(t, jwtParts.Header)
	assert.NotNil(t, jwtParts.Payload)
	// TODO: compare the header and payload with original ones
}

func TestGetDataJWT(t *testing.T) {
	headers := Headers{}
	headers[HeaderAlgorithm] = "some algorithm"
	headers[HeaderKeyID] = "some kid"

	payload := map[string]interface{}{
		"sub": "subjectID",
		// "iat":
	}
	partsJWS, _ := CreatePartsUnsignedJWT(headers, payload)
	compactJWS := partsJWS.Header + "." + partsJWS.Payload + "." + ""
	parts := GetDataJWT(&compactJWS)
	assert.NotNil(t, parts)
	assert.Equal(t, "some algorithm", parts.Header[HeaderAlgorithm])

}

func TestGetPartsJWT(t *testing.T) {
	compactJWS := "header.payload.signature"
	parts := GetPartsJWT(&compactJWS)
	assert.NotNil(t, parts)
	assert.Equal(t, "header", parts.Header)
	assert.Equal(t, "payload", parts.Payload)
	assert.Equal(t, "signature", *(parts.Signature))
}
 // TODO: func TestGetDataByPartsJWT(t *testing.T) {}
