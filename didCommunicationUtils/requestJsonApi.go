package didCommunicationUtils

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
)

// DecodeAndCheckRequestJsonApiPayloadJAR receives a decrypted compactJWT (JWS)
// and returns openidUtils.DecodedRequestPayloadJAR (or nil) and error message (or nil) after being checked.
// It checks header fields (valid "alg", "kid" is not empty, "to" match with didServiceEndpoint),
// It checks payload fields "iss" and "sub" match with issuerDidKid and subjectDidKid, also "exp" and "nbf" fields.
// Then the "response_mode", "aud" and "redirect_uri" fields can be checked by the parent function to see if they are allowed.
func DecodeAndCheckRequestJsonApiPayloadJAR(compactJWT *string, recipientDidDoc *didDocumentUtils.DidDoc, expectedAudience string, requiredScopes []string) (*DecodedRequestPayloadJAR, *string) {

	dataJWT, errMsg := DecodeAndCheckRequestJsonApiDataJWT(compactJWT, recipientDidDoc, expectedAudience, requiredScopes)
	if errMsg != nil {
		return nil, errMsg
	}

	payloadBytes, err := json.Marshal(dataJWT.Payload)
	if err != nil {
		return nil, &ErrCodeRequestInvalid
	}

	decodedPayloadJAR := DecodedRequestPayloadJAR{}        // empty object, but not nil
	err = json.Unmarshal(payloadBytes, &decodedPayloadJAR) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, &ErrCodeRequestInvalid
	}

	// todo: set the dataJWT.Headers in the pointerDecodedPayloadJAR.body.meta

	return &decodedPayloadJAR, nil
}

// DecodeAndCheckRequestJsonApiDataJWT returns DataJWT (or nil) and error message (or nil).
// It checks header fields (valid "alg", "kid" are not empty, "to" match with didServiceEndpoint),
// It checks payload fields "iss" and "sub" match with issuerDidKid and subjectDidKid, also "exp" and "nbf" fields.
// Then the "response_mode", "aud" and "redirect_uri" fields can be checked by the parent function to see if they are allowed.
func DecodeAndCheckRequestJsonApiDataJWT(compactJWT *string, recipientDidDoc *didDocumentUtils.DidDoc, expectedAudience string, requiredScopes []string) (*joseUtils.DataJWT, *string) {
	partsJWT := joseUtils.GetPartsJWT(compactJWT)
	headerJSON, payloadBytes := joseUtils.GetInflatedDataByPartsJWT(partsJWT)
	if payloadBytes == nil {
		return nil, &ErrCodeRequestInvalid
	}

	_, errStr := CheckRequestHeaderJsonJWS(headerJSON)
	if errStr != "" {
		return nil, &errStr
	}

	payload := PayloadJsonApiJWT{}
	err := json.Unmarshal(payloadBytes, &payload) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, &ErrCodeRequestInvalid
	}

	payloadJSON, errStr := checkRequestJsonApiPayload(&payload, recipientDidDoc, requiredScopes)
	if errStr != "" {
		return nil, &errStr
	}

	var signatureBytes []byte // empty but not nil
	if partsJWT.Signature != nil {
		signatureBytes, err = base64.RawURLEncoding.DecodeString(*partsJWT.Signature)
	}

	dataJWT := joseUtils.DataJWT{
		Header:    headerJSON,
		Payload:   payloadJSON,
		Signature: &signatureBytes,
	}

	return &dataJWT, nil

}
