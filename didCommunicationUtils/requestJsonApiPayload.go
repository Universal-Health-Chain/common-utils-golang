package didCommunicationUtils

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/openidUtils"

	"github.com/google/uuid"
)

// In JAR the JWT (data container) is named "Request Object" and in JARM it is named "Response Document"

// PayloadJsonApiJWT receives from a client app the code challenge as part of the OAuth 2.0 Authorization Request.
// Note: the "id" property (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID.
// - the "type" (required for DIDComm) property is set in UHC as "code+jar" or "profile-code+jar" to predict the content of the message.
// - the "body" (required for DIDComm) property has a JSON:API Primary Document, which can include with one or more Resource Objects in the "data" property and one or more DIDComm "attachments" within each Resource Object.
// - the "subject" (required in UHC) property refers in UHC to the target practitioner's DID when an admin is creating an install-code for a practitioner's profile (rather than referring to the cryptographic identifier "client_id" of the requester).
// - the "thid" (required in UHC): it is like the optional OpenID "state" property, but mandatory in the DIDComm specification.
// - the "scope" (required) property value is "openid".
// - the "response_type" (required) property value contains "code".
// - the "response_mode" (required) property value is "jwt" (to get the default "query.jwt" redirect URL format) or "form_post.jwt", recommended in UHC.
// - the "nbf" (required) property is no longer than 60 minutes in the past.
// - the "exp" (required) property has a lifetime of no longer than 60 minutes after the "nbf" property.
//	NOTE: Set the expiration period of the authorization code to one minute or a suitable short period of time if not replay is possible. The validity period may act as a cache control indicator of when to clear the authorization code cache if one is used.
// - the "iss" (required) property is the "client_id" of a wallet's DID#kid URI in a client application (*private_key_jwt* authentication method as specified in *section 9 of OIDC*).
// - the "client_id" (required) identifies in UHC the identifier of the cryptographic signature key (DID#kid URI) of the profile sending the request
//	(the key ID of the wallet of an employee who performs a role in a concrete department)
// - the "aud" in UHC identifies at the same time the "software_id" URL and the OP's Issuer Identifier URL as the intended Audience. The Authorization Server MUST verify that it is an intended audience.
// - the "jti" property is a unique identifier for the JWT (JWT ID), which can be used to prevent reuse of the request (replay attacks).
// - the "redirect_uri" (conditional) is required when using pushed authorization request (PAR).
// Note: the Audience "aud" property is in the Bearer access token but not in the payload when the request is not of type "code" or "token".
type PayloadJsonApiJWT struct {
	Audience       string          `json:"aud,omitempty" bson:"aud,omitempty"`
	Body           PrimaryDocument `json:"body,omitempty" bson:"body,omitempty"` // it has "data" with an array of one or more Resource Object(s)
	ClientID       string          `json:"client_id,omitempty" bson:"client_id,omitempty"`
	Expiration     int64           `json:"exp,omitempty" bson:"exp,omitempty"` // end of the valid date (number of seconds from Unix epoch);
	Issuer         string          `json:"iss,omitempty" bson:"iss,omitempty"`
	JSONTokenID    string          `json:"jti,omitempty" bson:"jti,omitempty"`
	NonValidBefore int64           `json:"nbf,omitempty" bson:"nbf,omitempty"` // start of the valid date (number of seconds from Unix epoch);
	RedirectURI    string          `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseMode   string          `json:"response_mode,omitempty" bson:"response_mode,omitempty"` // e.g.: "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"
	ResponseType   string          `json:"response_type,omitempty" bson:"response_type,omitempty"` // shall be "code"
	Scope          string          `json:"scope,omitempty" bson:"scope,omitempty"`
	Subject        string          `json:"sub,omitempty" bson:"sub,omitempty"`
	ThreadID       string          `json:"thid,omitempty" bson:"thid,omitempty"` // thread of the message, used instead of the optional OpenID State.
	To             string          `json:"to,omitempty" bson:"to,omitempty"`     // OPTIONAL. Copy the "kid" property from the JWE header (recipient) of the body.request object before removing the encrypted request object in the body when storing on a DB's collection.
	Type           string          `json:"type,omitempty" bson:"type,omitempty"` // The media type of the envelope MAY be set in the "typ" property
}

// CreatePayloadForJsonApiJWT is used in the tests to call the `/authorization` endpoint. It returns payload (or nil) and codeVerifierBase64Url.
// It creates SHA256 checksum of 32 random bytes (challenge) in hex format (64 characters) to comply with the 43-128 characters long.
func CreatePayloadForJsonApiJWT(expirationSeconds int64, clientAppSoftwareId, subjectDid string, resourceObjects []ResourceObject, audienceUrl, redirectURI string) (payload *PayloadJsonApiJWT) {

	// TODO: check valid did#kid URI structure for clientAppSoftwareId and subjectDid
	// TODO: check valid audience format with predefined rules
	// TODO: check valid respMode or set a default one

	currentSecondsUnix := time.Now().Unix() // seconds
	expiryUnixTime := currentSecondsUnix + expirationSeconds
	randomUUID, _ := uuid.NewRandom()
	threadID, _ := uuid.NewRandom()

	payload = &PayloadJsonApiJWT{
		Audience: audienceUrl,
		Body: PrimaryDocument{
			Data: resourceObjects, // the length of the array of resource objects SHALL be greater than 0
		},
		ClientID:       clientAppSoftwareId,
		Expiration:     expiryUnixTime,
		Issuer:         clientAppSoftwareId,
		JSONTokenID:    randomUUID.String(),
		NonValidBefore: currentSecondsUnix,
		RedirectURI:    redirectURI,
		ResponseMode:   ResponseModeFormPostJWT,
		ResponseType:   ResponseTypeDATA,
		Scope:          ScopeOpenidGeneric,
		Subject:        subjectDid, // DID of the OpenID service which contains an endpoint with ID "issuer" equal to the "aud" property (audience).
		ThreadID:       threadID.String(),
		Type:           PayloadTypeData,
	}

	return payload
}

func checkRequestJsonApiPayload(payload *PayloadJsonApiJWT, recipientDidDocument *didDocumentUtils.DidDoc, requiredScopes []string) (JWTPayloadJSON map[string]interface{}, errorMsg string) {
	if payload == nil || len(payload.Body.Data) < 1 {
		return nil, joseUtils.ErrMsgInvalidRequest
	}
	// TODO: check additional resourceObject fields?

	if checkRequestJsonApiPayloadProperties(payload, recipientDidDocument, requiredScopes) {
		// then return the JSON
		payloadBytes, _ := json.Marshal(payload)
		payloadJSON := map[string]interface{}{ /* empty but not nil*/ }
		err := json.Unmarshal(payloadBytes, &payloadJSON) //  Unmarshal fails if the object is nil and/or the pointer to the object is not provided.
		if err != nil {
			return nil, ErrCodeRequestInvalid
		}
		return payloadJSON, ""
	}
	return nil, ErrCodeRequestInvalid //ErrCodeRequestInvalidPayload
}

// checkRequestJsonApiPayloadProperties :
// - the expected subject "sub" shall be the organization DID for departments and employees operations (CRUDS).
func checkRequestJsonApiPayloadProperties(payload *PayloadJsonApiJWT, recipientDidDocument *didDocumentUtils.DidDoc, requiredScopes []string) bool {
	currentSecondsUnix := time.Now().Unix()
	//redirectUri property is optional, therefore is not required
	/* fmt.Println(openidUtils.CheckAudience(payload.Audience, recipientDidDocument)) */
	if payload != nil &&
		CheckAudience(payload.Audience, recipientDidDocument) &&
		openidUtils.CheckRequiredScopes(payload.Scope, requiredScopes) &&
		// openidUtils.CheckIssuerDidKidURI(payload.Issuer, issuerDidKid) &&
		strings.Contains(payload.Type, PayloadTypeData) &&
		strings.Contains(payload.ResponseType, ResponseTypeDATA) &&
		(payload.ResponseMode == ResponseModeJWT || payload.ResponseMode == ResponseModeFormPostJWT) &&
		payload.ClientID != "" && // It is the Client software application ID
		payload.Issuer != "" &&
		payload.Subject != "" && // shall be the organization DID for departments and employees operations (CRUDS).
		payload.JSONTokenID != "" &&
		payload.ThreadID != "" &&
		payload.Expiration > currentSecondsUnix {
		return true
	} else {
		return false
	}
}
