package didCommunicationUtils

import (
	"encoding/json"
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/stretchr/testify/assert"
)

func TestCreateHeaderRequestJWS(t *testing.T) {
	alg := "algTest"
	kid := "kidTest"
	didServiceEndpoint := "didServiceEndpointTest"
	headerRequestJWS := CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	assert.Nil(t, headerRequestJWS, "must be nil because algorithm is not valid")

	alg = "someValidSignatureAlgorithm"
	headerRequestJWS = CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	assert.Equal(t, HeaderTypeJWT, headerRequestJWS.Type, "")
	assert.Equal(t, didServiceEndpoint, headerRequestJWS.To, "")
	assert.Equal(t, alg, headerRequestJWS.Algorithm, "")
	assert.Equal(t, kid, headerRequestJWS.KeyID, "")
	assert.Equal(t, ContentTypeDIDCommSignedJSON, headerRequestJWS.ContentType, "")
}
func TestCheckRequestHeaderJWS(t *testing.T) {
	alg := "someValidSignatureAlgorithm"
	kid := "kidTest"
	didServiceEndpoint := "didServiceEndpointTest"

	headerRequestJWS := CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	jsonResp, errStr := CheckRequestHeaderJWS(*headerRequestJWS)
	assert.Equal(t, "", errStr, "error must be an empty string when checking the JSON response")
	assert.NotNil(t, jsonResp, "json response must not be nil")

	assert.Equal(t, HeaderTypeJWT, headerRequestJWS.Type, "")
	assert.Equal(t, didServiceEndpoint, headerRequestJWS.To, "")
	assert.Equal(t, alg, headerRequestJWS.Algorithm, "")
	assert.Equal(t, kid, headerRequestJWS.KeyID, "")
	assert.Equal(t, ContentTypeDIDCommSignedJSON, headerRequestJWS.ContentType, "")

}
func TestCheckRequestHeaderJsonJWS(t *testing.T) {
	alg := "someValidSignatureAlgorithm"
	kid := "kidTest"
	didServiceEndpoint := "didServiceEndpointTest"

	headerRequestJWS := CreateHeaderRequestJWS(alg, kid, didServiceEndpoint)
	headerBytes, _ := json.Marshal(headerRequestJWS)
	headerJSON := map[string]interface{}{ /* empty but not nil*/ }
	err := json.Unmarshal(headerBytes, &headerJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	assert.Nil(t, err, "error must be nil when unmarshalling")

	jsonResp, errStr := CheckRequestHeaderJsonJWS(headerJSON)
	assert.Equal(t, "", errStr, "error must be an empty string when checking the request header JWS")
	assert.NotNil(t, jsonResp, "json response must not be nil")

}
func TestCheckRequestHeaderJWSFromCompactJWS(t *testing.T) {
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

	respJSON, errStr := CheckRequestHeaderJWSFromCompactJWS(compactJWS, didServiceEndpoint)
	assert.Equal(t, "", errStr, "error must be an empty string when calling CheckRequestHeaderJWSFromCompactJWS")
	assert.NotNil(t, respJSON, "json response must not be nil")

}
