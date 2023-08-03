package openidUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
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

func TestCheckCodeChallengeLength(t *testing.T) {
	codeChallenge := "0e52599fdce2739d8d84ac0944df4428ad4d8bb81f3ebb93ada44a5a6036dff4"
	resp := CheckCodeChallengeLength(codeChallenge)
	assert.True(t, resp, "response must be true")
}

//Succeeds
func TestCheckAudience(t *testing.T) {
	payloadAudience := "https://audience-test.example.com"
	resp := CheckAudience(payloadAudience, &testRcptOrgDidDoc)
	assert.True(t, resp, "response must be true")
}

//succeeds
func TestGetAudiences(t *testing.T) {
	payloadAudience := "https://audience-test.example.com"
	audiences := GetAudiences(payloadAudience)
	assert.NotNil(t, audiences, "audiences must not be nil")
}
