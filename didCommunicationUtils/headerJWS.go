package didCommunicationUtils

import (
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
)

// CreateHeaderRequestJWS returns joseUtils.HeaderRequestJWS or nil
func CreateHeaderRequestJWS(alg, kid, didServiceEndpoint string) *joseUtils.HeaderRequestJWS {

	header := joseUtils.HeaderRequestJWS{
		Algorithm:   alg,
		ContentType: ContentTypeDIDCommSignedJSON,
		KeyID:       kid,
		To:          didServiceEndpoint,
		Type:        HeaderTypeJWT,
	}
	return &header
}

func CheckRequestHeaderJWS(header joseUtils.HeaderRequestJWS) (map[string]interface{}, string) {
	headerBytes, _ := json.Marshal(header)
	headerJSON := map[string]interface{}{ /* empty but not nil*/ }
	err := json.Unmarshal(headerBytes, &headerJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, ErrCodeRequestInvalid
	}

	return CheckRequestHeaderJsonJWS(headerJSON)
}

func CheckRequestHeaderJsonJWS(headerJSON map[string]interface{}) (map[string]interface{}, string) {
	if headerJSON[joseUtils.HeaderAlgorithm] == "" &&
		headerJSON[joseUtils.HeaderContentType] == "" &&
		headerJSON[joseUtils.HeaderKeyID] == "" &&
		// headerJSON["to"] == "" &&
		headerJSON[joseUtils.HeaderType] == "" {
		return nil, ErrCodeRequestInvalid //ErrCodeRequestInvalidHeader
	}

	return headerJSON, ""
}

func CheckRequestHeaderJWSFromCompactJWS(compactJWS, didServiceEndpoint string) (map[string]interface{}, string) {

	parts := joseUtils.GetDataJWT(&compactJWS)
	headerJWS := parts.Header
	headerJWSBytes, err := json.Marshal(headerJWS)
	if err != nil {
		return nil, ErrCodeRequestInvalid
	}
	headerJSON := map[string]interface{}{ /* empty but not nil*/ }
	err = json.Unmarshal(headerJWSBytes, &headerJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, ErrCodeRequestInvalid
	}
	return CheckRequestHeaderJsonJWS(headerJSON)
}
