package decodeUtils

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Universal-Health-Chain/common-utils-golang/didCommunicationUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/httpUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
)

func decodeRequest(compactJWT *string) (decodedPayloadJAR *didCommunicationUtils.DecodedRequestPayloadJAR, errMsg string) {
	decodedPayloadJAR = &didCommunicationUtils.DecodedRequestPayloadJAR{} // empty object, but not nil

	dataJWT := joseUtils.GetDataJWT(compactJWT)

	// TODO: if header.zip then decompress

	payloadBytes, err := json.Marshal(dataJWT.Payload)
	if err != nil {
		return nil, "ErrCodeRequestInvalid"
	}

	err = json.Unmarshal(payloadBytes, &decodedPayloadJAR) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, "ErrCodeRequestInvalid"
	}

	JWKeySet := jwkUtils.JWKeySet{}
	JWKeySetBytes, err := json.Marshal(dataJWT.Header["jwks"])
	if err != nil {
		return nil, "ErrCodeRequestInvalid"
	}

	err = json.Unmarshal(JWKeySetBytes, &JWKeySet) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
	if err != nil {
		return nil, "ErrCodeRequestInvalid"
	}
	decodedPayloadJAR.Body.Meta.JWS.JSONWebKeySet = &JWKeySet

	return decodedPayloadJAR, ""
}

// it expects a JWT (3 parts), not JWE
var GetDecodedRequestWithTokenData = func(compactJWT string, httpHeaders httpUtils.HttpPrivateHeadersOpenid) (decodedRequestPayloadJAR *didCommunicationUtils.DecodedRequestPayloadJAR, errorMsg string) {

	// 1 - Getting the checked JWE header and the decrypted compact JWS (if encrypted)
	numberOfPartsJWT := len(strings.Split(compactJWT, "."))

	if numberOfPartsJWT != 3 {
		return nil, "ErrMsgMalformedJWT"
	}

	// 2 - Checking the JWS fields

	// 2.a - TODO: call to check the JWS header
	// required headers are: alg, cty, kid, typ
	/*
		checkedHeaderJWS, _ := didCommunicationUtils.CheckRequestHeaderJWSFromCompactJWS(compactJWT, "")
		if checkedHeaderJWS == nil {
			return nil, "ErrMsgRequestInvalidJWS"
		}
	*/

	// 3 - Getting decoded request
	decodedPayload, errMsg := decodeRequest(&compactJWT)
	if errMsg != "" {
		return decodedPayload, errMsg
	}

	// 4 - Getting both Bearer access token and DPoP token when required (no test environment and no standard "code" request).
	if httpHeaders.Authorization != "" {
		accessTokenCompactJWT := strings.Replace(httpHeaders.Authorization, "Bearer ", "", 1)
		if accessTokenCompactJWT != "" {
			accessTokenDataJWT := joseUtils.GetDataJWT(&accessTokenCompactJWT)
			if accessTokenDataJWT != nil {
				decodedPayload.Body.Meta.BearerData = *accessTokenDataJWT
			}
		}
	}

	// 5 - TODO: setting the metadata: JWE and JWS header, Bearer access token and DPoP token
	return decodedPayload, ""
}

func DecodedRequestPayload(r *http.Request) (decodedPayload *didCommunicationUtils.DecodedRequestPayloadJAR, errorMsg string) {
	headers := httpUtils.GetHttpHeaders(r)

	if !strings.Contains(headers.ContentType, "json") {
		return nil, "Content-Type must be `application/json`"
	}

	var payload *didCommunicationUtils.DecodedRequestPayloadJAR
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		return nil, err.Error()
	}
	return payload, ""
}
