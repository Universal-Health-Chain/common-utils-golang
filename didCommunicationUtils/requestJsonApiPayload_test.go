package didCommunicationUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/stretchr/testify/assert"
)

var TestAudienceUrl = "https://endpoint-test.example.com"
var TestPayload = PayloadJsonApiJWT{
	Audience: TestAudienceUrl,
	Body: PrimaryDocument{
		Data:   []ResourceObject{},
		Meta:   DIDCommBodyMetaJAR{},
	},
	ClientID:       "com.example.organization-name.app-name",
	Expiration:     9999999999,
	Issuer:         "com.example.organization-name.app-name",
	JSONTokenID:    "TestJSONTokenID",
	NonValidBefore: 9999999998,
	RedirectURI:    "redirectURITest",
	ResponseMode:   ResponseModeFormPostJWT,
	ResponseType:   ResponseTypeDATA,
	Scope:          ScopeOpenidGeneric,
	Subject:        "did:method:subjectID", // DID of the OpenID service which contains an endpoint with ID "issuer" equal to the "aud" property (audience).
	ThreadID:       "TestThreadID",
	Type:           PayloadTypeData,
}

func Test_checkRequestJsonApiPayload(t *testing.T) {
	correctExpirationSeconds := int64(10)
	incorrectExpirationSeconds := int64(-10)
	correctClientAppSoftwareId := "com.example.organization-name.app-name"
	correctSubjectDid := "did:method:subjectID"
	incorrectStringAttribute := "_"
	resourceObject := ResourceObject{}
	resourceObjectArray := []ResourceObject{resourceObject}
	emptyResourceObjectArray := []ResourceObject{}

	redirectURI := "redirectURITest"
	serviceEndpoint := didDocumentUtils.Service{
		ID:              "endpoint-test-ID",
		Type:            "endpoint-test-Type",
		ServiceEndpoint: TestAudienceUrl,
	}
	emptyServiceEndpoint := didDocumentUtils.Service{}
	didDoc := didDocumentUtils.DidDoc{
		Service: []didDocumentUtils.Service{serviceEndpoint},
	}
	emptyDidDoc1 := didDocumentUtils.DidDoc{
		Service: []didDocumentUtils.Service{emptyServiceEndpoint},
	}
	emptyDidDoc2 := didDocumentUtils.DidDoc{}

	t.Run("Empty parameters - expected error", func(t *testing.T) {
		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(nil, nil, nil)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, joseUtils.ErrMsgInvalidRequest, errorMsg)
	})
	t.Run("Empty resource object array - expected error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(correctExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, emptyResourceObjectArray, TestAudienceUrl, redirectURI)
		scopeArray := []string{ScopeOpenidGeneric}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &didDoc, scopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, joseUtils.ErrMsgInvalidRequest, errorMsg)
	})
	t.Run("Incorrect audienceURL - expected error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(incorrectExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, resourceObjectArray, TestAudienceUrl, redirectURI)
		scopeArray := []string{ScopeOpenidGeneric}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &didDoc, scopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, ErrCodeRequestInvalid, errorMsg)
	})
	t.Run("Incorrect expiration seconds - expected error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(correctExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, resourceObjectArray, incorrectStringAttribute, redirectURI)
		scopeArray := []string{ScopeOpenidGeneric}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &didDoc, scopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, ErrCodeRequestInvalid, errorMsg)
	})
	t.Run("Empty didCom - expected error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(correctExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, resourceObjectArray, TestAudienceUrl, redirectURI)
		scopeArray := []string{ScopeOpenidGeneric}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &emptyDidDoc1, scopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, ErrCodeRequestInvalid, errorMsg)

		jwtPayloadJSON, errorMsg = checkRequestJsonApiPayload(payload, &emptyDidDoc2, scopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, ErrCodeRequestInvalid, errorMsg)
	})
	t.Run("Required scopes (scopeArray) with more than the payload has - expected error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(correctExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, resourceObjectArray, TestAudienceUrl, redirectURI)
		emptyScopeArray := []string{"testScope"}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &didDoc, emptyScopeArray)
		assert.Nil(t, jwtPayloadJSON)
		assert.Equal(t, ErrCodeRequestInvalid, errorMsg)
	})
	t.Run("Correct parameters - expected no error", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(correctExpirationSeconds, correctClientAppSoftwareId, correctSubjectDid, resourceObjectArray, TestAudienceUrl, redirectURI)
		scopeArray := []string{ScopeOpenidGeneric}

		jwtPayloadJSON, errorMsg := checkRequestJsonApiPayload(payload, &didDoc, scopeArray)
		assert.NotNil(t, jwtPayloadJSON)
		assert.Empty(t, errorMsg)
	})

}

func Test_CreatePayloadForJsonApiJWT(t *testing.T) {
	expirationSeconds := int64(10)
	clientAppSoftwareId := "com.example.organization-name.app-name"
	subjectDid := "did:method:subjectID"
	resourceObject := ResourceObject{}
	resourceObjectArray := []ResourceObject{resourceObject}
	audienceUrl := "https://endpoint-test.example.com"
	redirectURI := "redirectURITest"

	t.Run("Correct values", func(t *testing.T) {
		payload := CreatePayloadForJsonApiJWT(expirationSeconds, clientAppSoftwareId, subjectDid, resourceObjectArray, audienceUrl, redirectURI)

		assert.Equal(t, audienceUrl, payload.Audience)
		assert.Equal(t, resourceObject, payload.Body.Data[0])
		assert.Equal(t, clientAppSoftwareId, payload.ClientID)
		assert.Equal(t, clientAppSoftwareId, payload.Issuer)
		assert.Equal(t, redirectURI, payload.RedirectURI)
		assert.Equal(t, subjectDid, payload.Subject)

		assert.Positive(t, payload.Expiration)
		assert.Positive(t, payload.NonValidBefore)

		assert.NotEmpty(t, payload.JSONTokenID)
		assert.NotEmpty(t, payload.ResponseMode)
		assert.NotEmpty(t, payload.ResponseType)
		assert.NotEmpty(t, payload.Scope)
		assert.NotEmpty(t, payload.ThreadID)
		assert.NotEmpty(t, payload.Type)

	})
}

func Test_checkRequestJsonApiPayloadProperties(t *testing.T) {
	serviceEndpoint := didDocumentUtils.Service{
		ID:              "endpoint-test-ID",
		Type:            "endpoint-test-Type",
		ServiceEndpoint: TestAudienceUrl,
	}
	didDoc := didDocumentUtils.DidDoc{
		Service: []didDocumentUtils.Service{serviceEndpoint},
	}
	scopeArray := []string{ScopeOpenidGeneric}

	t.Run("Empty parameters - expected invalid (false)", func(t *testing.T) {
		isValid := checkRequestJsonApiPayloadProperties(nil, &didDoc, scopeArray)
		assert.False(t, isValid)

		isValid = checkRequestJsonApiPayloadProperties(&TestPayload, nil, scopeArray)
		assert.False(t, isValid)
	})
	t.Run("Required scopes (scopeArray) with more than the payload has - expected invalid (false)", func(t *testing.T) {
		extraScopeArray := []string{"testScope"}
		isValid := checkRequestJsonApiPayloadProperties(&TestPayload, &didDoc, extraScopeArray)
		assert.False(t, isValid)
	})
	t.Run("Correct parameters - expected valid (true)", func(t *testing.T) {
		isValid := checkRequestJsonApiPayloadProperties(&TestPayload, &didDoc, scopeArray)
		assert.True(t, isValid)
	})
}
