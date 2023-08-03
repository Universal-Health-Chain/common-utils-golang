package didCommunicationUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequestHeaderJWE(t *testing.T) {
	alg := "someValidSignatureAlgorithm"
	kid := "kidTest"
	didServiceEndpoint := "didServiceEndpointTest"

	headerRequestJWS := CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	jsonResp, errStr := CheckRequestHeaderJWE(*headerRequestJWS, "")
	assert.Equal(t, "", errStr, "error must be an empty string when calling CheckRequestHeaderJWE")
	assert.NotNil(t, jsonResp, "json response must not be nil")

}

func TestCreateHeaderRequestJWE(t *testing.T) {
	alg := "someValidEncryptionAlgorithm"
	kid := "kidTest"
	jwk := jwkUtils.JWK{
		Alg:  alg,
		Crv:  nil,
		H:    nil,
		Kid:  kid,
		Kty:  "",
		Pset: nil,
		X:    "",
		Xs:   nil,
		Y:    nil,
		Use:  nil,
		D:    nil,
		Ds:   nil,
		K:    nil,
	}

	jku := "JWKSetURL"

	headerJWE := CreateHeaderRequestJWE(alg, "enc", "skid", &jwk, &kid, &jku)
	assert.NotNil(t, headerJWE, "json response must not be nil for CheckRequestHeaderJWEFromCompactJWS")
	header := *headerJWE
	assert.Equal(t, alg, header.Algorithm, "algorithms must coincide")
	assert.Equal(t, &kid, header.KeyID, "KID must coincide")

}

/*
func TestCheckRequestHeaderJWEFromCompactJWS(t *testing.T) {
	alg := "someValidSignatureAlgorithm"
	kid := "kidTest"
	didServiceEndpoint := "didServiceEndpointTest"

	headerRequestJWS := CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	headerBytes, _ := json.Marshal(headerRequestJWS)
	headerJSON := map[string]interface{}{}
	err := json.Unmarshal(headerBytes, &headerJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	assert.Nil(t, err, "error must be nil when unmarshalling header")

	payload, _ := CreatePayloadForCodeRequestJWT(1000, "issuerDidKid", "subjectDidKid", ResponseModeJWT, "audience", "", "payloadType")
	payloadBytes, _ := json.Marshal(payload)
	payloadJSON := map[string]interface{}{}
	err = json.Unmarshal(payloadBytes, &payloadJSON)
	assert.Nil(t, err, "error must be nil when unmarshalling payload")

	dataJWT := joseUtils.DataJWT{
		Header:    headerJSON, //JSON
		Payload:   payloadJSON,
		Signature: nil,
	}
	unsignedJWT := dataJWT.CompactUnsignedJWT()

	compactJWS := unsignedJWT
	respJson, errStr := CheckRequestHeaderJWEFromCompactJWS(compactJWS)
	assert.Equal(t, "invalid code request", errStr, "JWE must be encrypted and signed")
	assert.Nil(t, respJson, "json response must be nil due to error")

	////
	jwk := kyberUtils.TestAliceKyber768PublicJWK
	senderEncKID := kyberUtils.TestBobKyber768PublicJWK.Kid
	compactJWE, err := kyberUtils.EncryptPlaintextAndCompactJWE(&compactJWS, &jwk, &senderEncKID)

	respJson, errStr = CheckRequestHeaderJWEFromCompactJWS(compactJWE)
	assert.Equal(t, "", errStr, "no error must exist")
	assert.NotNil(t, respJson, "json response must not be nil")

}
*/
