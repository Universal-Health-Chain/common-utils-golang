package didCommunicationUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/openidUtils"
	"github.com/stretchr/testify/assert"
)

var testServiceOne = didDocumentUtils.Service{
	ID:              "IdOfService",
	Type:            "TypeOfService",
	Priority:        0,
	RecipientKeys:   nil,
	RoutingKeys:     nil,
	ServiceEndpoint: "SomeEndpointURL",
	Accept:          nil,
	Properties:      nil,
}
var testServiceTwo = didDocumentUtils.Service{
	ID:              "SecondIdOfService",
	Type:            "SecondTypeOfService",
	Priority:        0,
	RecipientKeys:   nil,
	RoutingKeys:     nil,
	ServiceEndpoint: "https://audience-test.example.com",
	Accept:          nil,
	Properties:      nil,
}
var testServices = []didDocumentUtils.Service{testServiceOne, testServiceTwo}
var testRcptOrgDidDoc = didDocumentUtils.DidDoc{
	Context:            nil,
	Controller:         nil,
	ID:                 "did:legal:healthcare:ES::::Organization:uuid:<test-org-uuid-v4>",
	KeyAgreement:       &[]didDocumentUtils.VerificationMethod{}, // Kyber key
	Service:            testServices,                             // endpoints: authorization (code), token, transaction ...
	VerificationMethod: []didDocumentUtils.VerificationMethod{},  // Dilithium key
}

// TODO: remove the issuer in CreatePayloadForCodeRequestJWT
func TestCreatePayloadForCodeRequestJWT(t *testing.T) {
	expirationSeconds := int64(10)
	issuerDidKid := "did:123#ABC"
	subjectDidKid := "subjectDidKidTest"
	respMode := "jwt"
	audience := "https://audience-test.example.com"
	redirectURI := "redirectURITest"
	payloadType := PayloadTypeNewProfileCode

	t.Run("successful creation and valid request", func(t *testing.T) {
		payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, respMode, audience, redirectURI, payloadType)
		assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
		assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

		validationTrue, errMsg := CheckRequestCodePayload(*payloadCodeRequestJWT, &testRcptOrgDidDoc)
		assert.Equal(t, "", errMsg, "no error must be for the true validation test")
		assert.NotNil(t, validationTrue, "the response payloadJSON must not be nil when validation is true")

	})

	//Invalid requests
	//1
	//2
	t.Run("successful creation and invalid request", func(t *testing.T) {
		payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, "respMode", audience, redirectURI, payloadType)
		assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
		assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

		validationFalse, errMsg := CheckRequestCodePayload(*payloadCodeRequestJWT, &testRcptOrgDidDoc)
		assert.NotEqual(t, "", errMsg, "an error is expected when it is not valid respMode")
		assert.Nil(t, validationFalse, "the response payloadJSON is expected to be nil due to the occurrence of an error")

	})

	//3 wrong type
	t.Run("successful creation and invalid request due to wrong type", func(t *testing.T) {
		payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, "respMode", audience, redirectURI, PayloadTypeData)
		assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
		assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

		validationFalse, errMsg := CheckRequestCodePayload(*payloadCodeRequestJWT, &testRcptOrgDidDoc)
		assert.NotEqual(t, "", errMsg, "an error is expected when it is not valid respMode")
		assert.Nil(t, validationFalse, "the response payloadJSON is expected to be nil due to the occurrence of an error")

	})

}

func TestCheckRequestCodePayload(t *testing.T) {

}

func TestCheckFieldsInPayload(t *testing.T) {

}

/*
func TestCheckIssuer(t *testing.T) {
	expirationSeconds := int64(10)
	issuerDidKid := "did:123#ABC"
	subjectDidKid := "subjectDidKidTest"
	respMode := "jwt"
	audience := "audienceTest"
	redirectURI := "redirectURITest"
	payloadType := PayloadTypeNewProfileCode

	payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, respMode, audience, redirectURI, payloadType)
	assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
	assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

	valid := openidUtils.CheckIssuerDidKidURI(payloadCodeRequestJWT.Issuer)
	assert.Equal(t, true, valid, "the answer must be true")

}
*/

func TestCheckCodeChallengeLen(t *testing.T) {
	expirationSeconds := int64(10)
	issuerDidKid := "did:123#ABC"
	subjectDidKid := "subjectDidKidTest"
	respMode := "jwt"
	audience := "audienceTest"
	redirectURI := "redirectURITest"
	payloadType := PayloadTypeNewProfileCode

	payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, respMode, audience, redirectURI, payloadType)
	assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
	assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

	valid := openidUtils.CheckCodeChallengeLength(payloadCodeRequestJWT.CodeChallenge)
	assert.Equal(t, true, valid, "the answer must be true")

}

func TestCheckTimeValidation(t *testing.T) {
	expirationSeconds := int64(10)
	issuerDidKid := "did:123#ABC"
	subjectDidKid := "subjectDidKidTest"
	respMode := "jwt"
	audience := "audienceTest"
	redirectURI := "redirectURITest"
	payloadType := PayloadTypeNewProfileCode

	payloadCodeRequestJWT, codeVerifierBase64Url := CreatePayloadForCodeRequestJWT(expirationSeconds, issuerDidKid, subjectDidKid, respMode, audience, redirectURI, payloadType)
	assert.NotNil(t, payloadCodeRequestJWT, "must not be nil")
	assert.NotEqual(t, "", codeVerifierBase64Url, "must not be empty")

	valid := openidUtils.CheckTimeValidation(payloadCodeRequestJWT.NonValidBefore, payloadCodeRequestJWT.Expiration)
	assert.Equal(t, true, valid, "the answer must be true")
}
