package didCommunicationUtils

import (
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
)

// todo: CreateHeaderRequestJWE returns HeaderRequestJWE or nil
func CreateHeaderRequestJWE(alg, enc, skid string, jwk *jwkUtils.JWK, kid, jku *string) *joseUtils.HeaderRequestJWE {

	// jwk or (kid and jku) are required
	if jwk == nil {
		if kid == nil || jku == nil {
			return nil
		}
	}

	header := joseUtils.HeaderRequestJWE{
		Algorithm:   alg,
		ContentType: ContentTypeDIDCommSignedJSON,
		Encryption:  enc,
		JSONWebKey:  jwk,
		JWKSetURL:   jku,
		KeyID:       kid,
		SenderKeyID: skid,
		Type:        HeaderTypeJWT,
	}
	return &header
}

func CheckRequestHeaderJWE(header joseUtils.HeaderRequestJWS, didServiceEndpoint string) (map[string]interface{}, string) {
	// TODO: check fields

	// then return the JSON
	headerBytes, _ := json.Marshal(header)
	headerJSON := map[string]interface{}{ /* empty but not nil*/ }
	err := json.Unmarshal(headerBytes, &headerJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, ErrCodeRequestInvalid
	}
	return CheckRequestHeaderJsonJWS(headerJSON)
}

func CheckRequestHeaderJWEFromCompactJWS(compactJWS string) (map[string]interface{}, string) {

	resp, err := joseUtils.DeserializeCompactJWE(compactJWS)
	if err != nil {
		return nil, ErrCodeRequestInvalid
	}
	protectedHeaders := resp.ProtectedHeaders

	return CheckRequestHeaderJsonJWS(protectedHeaders)
}
