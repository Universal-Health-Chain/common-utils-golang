package didCommunicationUtils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/uuid"
)

// In JAR the JWT (data container) is named "Request Object" and in JARM it is named "Response Document"

// PayloadCodeRequestJWT receives from a client app the code challenge as part of the OAuth 2.0 Authorization Request.
// Note: the "id" field (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID.
// - the "type" (required in UHC) field is set in UHC as "code+jar" to predict the content of the message.
// - the "body" (required in UHC) field can have protocol and application-level data as per the DIDComm specification, but it is not used in the standard HTTP OpenID Authorization Code request.
// - the "subject" (required in UHC) field refers in UHC to the target practitioner's DID when an admin is creating an install-code for a practitioner's profile (rather than referring to the cryptographic identifier "client_id" of the requester).
// - the "thid" (required in UHC): it is like the optional OpenID "state" field, but mandatory in the DIDComm specification.
// - the "scope" (required) field value is "openid".
// - the "response_type" (required) field value contains "code".
// - the "response_mode" (required) field value is "jwt" (to get the default "query.jwt" redirect URL format) or "form_post.jwt", recommended in UHC.
// - the "code_challenge_method" (required) field value is "S256".
// - the "code_challenge" (required) field is the SHA-256 hash result of a random challenge generated by the client application, base64url encoded.
// - the "nbf" (required) field is no longer than 60 minutes in the past.
// - the "exp" (required) field has a lifetime of no longer than 60 minutes after the "nbf" field.
//	NOTE: Set the expiration period of the authorization code to one minute or a suitable short period of time if not replay is possible. The validity period may act as a cache control indicator of when to clear the authorization code cache if one is used.
// - the "iss" (required) field is the "client_id" of the OAuth Client (private_key_jwt authentication method as specified in section 9 of OIDC). The parameters required to create the professional's client app the "client_id" must be provided offline by the admin.
// - the "client_id" (required) identifies in UHC the identifier of the cryptographic signature key (DID#kid URI) of the profile sending the request
//	(the key ID of the wallet of an employee who performs a role in a concrete department)
// - the "aud" in UHC identifies at the same time the "software_id" URL and the OP's Issuer Identifier URL as the intended Audience. The Authorization Server MUST verify that it is an intended audience.
// - the "jti" field is a unique identifier for the JWT (JWT ID), which can be used to prevent reuse of the request (replay attacks).
// - the "redirect_uri" (conditional) is required when using pushed authorization request (PAR).
type PayloadCodeRequestJWT struct {
	// TODO: define all the fields, sorted alphabetically by the JSON field name.
	Audience            string `json:"aud,omitempty" bson:"aud,omitempty"`
	ClientID            string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`     // when requesting a code
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method,omitempty"` // when requesting a code
	Expiration          int64  `json:"exp,omitempty" bson:"exp,omitempty"`                           // end of the valid date (number of seconds from Unix epoch);
	Issuer              string `json:"iss,omitempty" bson:"iss,omitempty"`
	JSONTokenID         string `json:"jti,omitempty" bson:"jti,omitempty"`
	NonValidBefore      int64  `json:"nbf,omitempty" bson:"nbf,omitempty"` // start of the valid date (number of seconds from Unix epoch);
	RedirectURI         string `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseMode        string `json:"response_mode,omitempty" bson:"response_mode,omitempty"` // e.g.: "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"
	ResponseType        string `json:"response_type,omitempty" bson:"response_type,omitempty"` // shall be "code"
	Scope               string `json:"scope,omitempty" bson:"scope,omitempty"`
	Subject             string `json:"sub,omitempty" bson:"sub,omitempty"`
	ThreadID            string `json:"thid,omitempty" bson:"thid,omitempty"` // thread of the message, used instead of the optional OpenID State.
	To                  string `json:"to,omitempty" bson:"to,omitempty"`     // OPTIONAL. Copy the "kid" field from the JWE header (recipient) of the body.request object before removing the encrypted request object in the body when storing on a DB's collection.
	Type                string `json:"type,omitempty" bson:"type,omitempty"` // The media type of the envelope MAY be set in the "typ" property
}

// CreatePayloadForCodeRequestJWT is used in the tests to call the `/authorization` endpoint. It returns payload (or nil) and codeVerifierBase64Url.
// It creates SHA256 checksum of 32 random bytes (challenge) in hex format (64 characters) to comply with the 43-128 characters long.
func CreatePayloadForCodeRequestJWT(expirationSeconds int64, issuerDidKid, subjectDidKid, respMode, audience, redirectURI, payloadType string) (payload *PayloadCodeRequestJWT, codeVerifierBase64Url string) {

	// TODO: check valid did#kid URI structure for issuerDidKid and subjectDidKid
	// TODO: check valid audience format with predefined rules
	// TODO: check valid response_mode or set a default one

	codeChallengeBytes := random.GetRandomBytes(32)
	codeVerifierBase64Url = base64.RawURLEncoding.EncodeToString(codeChallengeBytes)

	currentSecondsUnix := time.Now().Unix() // seconds
	expiryUnixTime := currentSecondsUnix + expirationSeconds
	randomUUID, _ := uuid.NewRandom()
	threadID, _ := uuid.NewRandom()

	payload = &PayloadCodeRequestJWT{
		Audience:            audience,
		ClientID:            issuerDidKid,
		CodeChallenge:       fmt.Sprintf("%x", sha256.Sum256(codeChallengeBytes)),
		CodeChallengeMethod: CodeChallengeMethod,
		Expiration:          expiryUnixTime,
		Issuer:              issuerDidKid,
		JSONTokenID:         randomUUID.String(),
		NonValidBefore:      currentSecondsUnix,
		RedirectURI:         redirectURI,
		ResponseMode:        respMode,
		ResponseType:        ResponseTypeCODE,
		Scope:               ScopeOpenidGeneric,
		Subject:             subjectDidKid,
		ThreadID:            threadID.String(),
		Type:                payloadType, //PayloadTypeData, //  //TODO: remove use paramater in the function "payloadType"
	}

	return payload, codeVerifierBase64Url
}

func CheckRequestCodePayload(payload PayloadCodeRequestJWT, recipientDidDocument *didDocumentUtils.DidDoc) (map[string]interface{}, string) {
	if recipientDidDocument == nil {
		return nil, "recipient didDocument must not be nil"
	}
	// TODO: check fields
	ans := checkRequestCodePayloadProperties(payload, recipientDidDocument)
	if ans {
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

// checkRequestCodePayloadProperties :
// A native client application is a public client installed and executed on a device, which can be operated by end-user(s).
// - "client_id" uniquely identifies a single Client software application throughout the system. UHC uses reverse-DNS (rDNS) format for the Client ID (software ID), similar to the Apple Bundle ID for iOS apps. For example, `com.example.organization-name.<admin|professional|personal>`
// - the parent function shall check the "from" DID prefix to allow or deny the request.
// - "sub" is the subject's DID (can be different to "from"): the parent function can check the DID in the Subject "sub" starts (has as prefix) the DID of the recipient (organization), else the subject is a professional from other organization
//	(e.g.: in case of an employee wants to obtain an access token from other organization because the organization's service is down).
// - ThreadID "thid" is like the OpenID "state" or "nonce" (created by the client app)
// - client_id is the DID of the requester (same as the DIDComm "from")
func checkRequestCodePayloadProperties(payload PayloadCodeRequestJWT, recipientDidDocument *didDocumentUtils.DidDoc) bool {
	//redirectUri field is optional, therefore is not required
	if (strings.Contains(payload.Type, PayloadTypeNewProfileCode) || strings.Contains(payload.Type, PayloadTypeLoginCode)) &&
		CheckAudience(payload.Audience, recipientDidDocument) &&
		strings.Contains(payload.Scope, ScopeOpenidGeneric) &&
		strings.Contains(payload.ResponseType, ResponseTypeCODE) &&
		(payload.ResponseMode == ResponseModeJWT || payload.ResponseMode == ResponseModeQueryJWT || payload.ResponseMode == ResponseModeFormPostJWT) &&
		payload.CodeChallengeMethod == CodeChallengeMethod &&
		CheckCodeChallengeLength(payload.CodeChallenge) &&
		CheckTimeValidation(payload.NonValidBefore, payload.Expiration) &&
		// openidUtils.CheckIssuerDidKidURI(payload.Issuer, issuerDidKid) &&
		// TODO: check "to" with the did document of the recipient (organization)
		// TODO: check the DID in the "from" starts (has as prefix) the DID of the recipient (organization). Other case is if a practitioner wants to send a message through other organization different to the organization the practitioner works for
		payload.ClientID != "" && // It is the Client software application ID
		payload.Subject != "" && // the subject DID (can be different to "from"): the parent function can check the DID in the Subject "sub" starts (has as prefix) the DID of the recipient (organization), else the subject is a professional from other organization.
		payload.JSONTokenID != "" &&
		payload.ThreadID != "" { // TODO: review if required or optional
		return true
	}
	return false
}
