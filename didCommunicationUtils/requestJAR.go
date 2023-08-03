package didCommunicationUtils

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Universal-Health-Chain/common-utils-golang/httpUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/openidUtils"
)

// In JAR the JWT data container is named "Request Object" and in JARM it is named "Response Document"

// DecodedRequestPayloadJAR is the payload of the JWT Request Document used to secure the communication.
// The request object SHALL contain an "exp" claim [FAPI Part 2, Section 5.2.2, Clause13].
// JAR prohibits referring to request parameters outside the request object (ignore them).
// - Audiences: string with service provider(s) / client_id or other type of valid recipient(s).
// - Expiration: "exp" is required in FAPI (instead of DIDComm "expires_time") as the expiration of the JWT (UTC Epoch seconds)
// - State: the state value as sent by the client in the authorization request (if applicable);
// - ResponseType: space-separated parameter values (case-insensitive and order does not matter): "code", "token" (for access token), "id_token", "json:api"
// - ResponseMode: specifies non-default modes. If it is not present in a request, the default Response Mode mechanism specified by the ResponseType is used.
// - NotValidBefore: "nbf" is used instead of DIDComm "created_time" field.

// DIDComm "created_time" is not used because it is the same as "nbf" (UTC Epoch Seconds)
// Note: the OpenID "id_token" (data) is the Response Document JARM, not the Request Object JAR (it is the response to an authentication request).
type DecodedRequestPayloadJAR struct {
	SoftwareID     *string `json:"software_id,omitempty" bson:"software_id,omitempty"`
	Audiences      *string `json:"aud,omitempty" bson:"aud,omitempty"` // comma separated audiences
	NotValidBefore int64   `json:"nbf,omitempty" bson:"nbf,omitempty"`
	IssuedAt       int64   `json:"iat,omitempty" bson:"iat,omitempty"`

	// FAPI Object Payload fields: The request object SHALL contain an "exp" claim [FAPI Part 2, Section 5.2.2, Clause13].
	Expiration   int64   `json:"exp,omitempty" bson:"exp,omitempty"`                     // the expiration time of the JWT (it is not a string);
	ResponseType *string `json:"response_type,omitempty" bson:"response_type,omitempty"` // e.g.: "code" or "access_token",
	ResponseMode *string `json:"response_mode,omitempty" bson:"response_mode,omitempty"` // e.g.: "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"

	// Claims for OpenID "code" and "access_token" flow requests
	ClientID            *string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	Code                *string `json:"code,omitempty" bson:"code,omitempty"`
	CodeChallenge       *string `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`     // when requesting a code
	CodeChallengeMethod *string `json:"code_challenge_method" bson:"code_challenge_method,omitempty"` // when requesting a code
	CodeVerifier        *string `json:"code_verifier,omitempty" bson:"code_verifier,omitempty"`       // when requesting a token
	GrantType           *string `json:"grant_type,omitempty" bson:"grant_type,omitempty"`             // when requesting a code, it MUST be set to "authorization_code".
	RedirectURI         *string `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	Scope               *string `json:"scope,omitempty" bson:"scope,omitempty"`

	// IssuedAt            *joseUtils.NumericDate `json:"iat,omitempty"`

	// NotBefore           *joseUtils.NumericDate `json:"nbf,omitempty"`

	// Open ID additional request fields
	State     *string `json:"state,omitempty" bson:"state,omitempty"` // the state value as sent by the client in the authorization request (if applicable)
	LocalesUI *string `json:"ui_locales,omitempty" bson:"ui_locales,omitempty"`
	LoginHint *string `json:"login_hint,omitempty" bson:"login_hint,omitempty"`
	Nonce     *string `json:"nonce,omitempty"  bson:"nonce,omitempty"`

	// Subject is required when creating an install-code for a profile which is the employee DID
	Subject     *string `json:"sub,omitempty" bson:"sub,omitempty"`
	JSONTokenID *string `json:"jti,omitempty" bson:"jti,omitempty"`

	// DIDComm fields
	// Bearer data will be in Body.Meta.Bearer and Attachments will be in each ResourceObject within the PrimaryDocument
	Body         PrimaryDocument `json:"body,omitempty" bson:"body,omitempty"`   //
	ThreadID     *string         `json:"thid,omitempty" bson:"thid,omitempty"`   // thread of the message, to be used instead of the OpenID State.
	To           string          `json:"to,omitempty" bson:"to,omitempty"`       // OPTIONAL. Copy the "kid" field from the JWE header (recipient) of the body.request object before removing the encrypted request object in the body when storing on a DB's collection.
	Type         string          `json:"type,omitempty" bson:"type,omitempty"`   // The media type of the envelope MAY be set in the "typ" property
	From         string          `json:"from,omitempty" bson:"from,omitempty"`   // copy of the "skid" field from the JWE header (sender)
	ID           *string         `json:"id,omitempty" bson:"id,omitempty"`       // the ID is unique to the sender. If ThreadID is not specified then the ID is used as ThreadID.
	ParentThread string          `json:"pthid,omitempty" bson:"pthid,omitempty"` // OPTIONAL. In case of an access_token request it links to the ID of the "code" request in the OpenID Authentication Code flow.
}

/*
// SetBearerAccessToken sets a given access token only if a previous one does not exits and if it has:
// - Issuer "iss" JSON field.
// - Subject "sub" JSON field.
// - Non-valid before "nbf" JSON field.
// - Expiration "exp" JSON field.
//ait is has an issuer and  removes the Body.Meta information (the decoded Bearer and DPoP tokens)
func (decodedJAR *DecodedRequestPayloadJAR) SetBearerAccessToken(httpAuthorization *string) bool {
	if decodedJAR == nil {
		return false
	}

	// 1 - check if the given access token is valid
	httpBearerDataJWT := joseUtils.GetDataJWT(httpAuthorization)
	if (httpBearerDataJWT.)

	// 2 - check if an access token already exists
	jarBearerDataJWT := decodedJAR.Body.JARProtocol.Bearer

	// to determine if a valid access token has been included in the request the Issuer is checked
	if jarBearerDataJWT.Payload["iss"] == "" {
		if accessToken != nil {
			compactAccessToken := strings.Replace(httpHeaders.Authorization, "Bearer ", "", 1)
			if compactAccessToken != "" {
				accessTokenDataJWT := joseUtils.GetDataJWT(&compactAccessToken)
				if (accessTokenDataJWT != nil) {
					decodedPayloadJAR.Body.Meta.Bearer = *accessTokenDataJWT
				}
			}
		}
	}

}
*/

// DecodedRequestPayloadJAR method removes the Body.Meta information (the decoded Bearer and DPoP tokens)
func (requestPayloadData *DecodedRequestPayloadJAR) ToJSON() map[string]interface{} {

	// removing the decoded Bearer and DPoP tokens (if any)
	requestPayloadData.Body.Meta = DIDCommBodyMetaJAR{}

	requestPayloadJSON := &map[string]interface{}{} // empty JSON
	requestPayloadBytes, err1 := json.Marshal(*requestPayloadData)
	if err1 != nil {
		return *requestPayloadJSON
	}

	err2 := json.Unmarshal(requestPayloadBytes, requestPayloadJSON)
	if err2 != nil {
		return *requestPayloadJSON
	} else {
		return *requestPayloadJSON
	}
}

func (requestPayloadData *DecodedRequestPayloadJAR) GetBearer() joseUtils.DataJWT {
	return requestPayloadData.Body.Meta.BearerData
}

func (requestPayloadData *DecodedRequestPayloadJAR) GetBearerSubject() string {
	if requestPayloadData == nil || requestPayloadData.Body.Meta.BearerData.Payload["sub"] == nil {
		return ""
	}

	return requestPayloadData.Body.Meta.BearerData.Payload["sub"].(string)
}

func (requestPayloadData *DecodedRequestPayloadJAR) GetBearerScope() string {
	if requestPayloadData == nil || requestPayloadData.Body.Meta.BearerData.Payload["scope"] == nil {
		return ""
	}

	return requestPayloadData.Body.Meta.BearerData.Payload["scope"].(string)
}

// PKCE was originally designed to protect the authorization code flow in mobile apps,
// but its ability to prevent authorization code injection makes it useful for every type of OAuth client.
// With PKCE, the checks that the "code_challenge" is correct is done on the authentication server-side and the check for valid state is done on the client-side.
// There are cases where the client does not check the "state" / "nonce" properly (or not at all)
// and PKCE let the auth-server do the check instead. The auth server can force/require that all clients follow the PKCE concept.

// When using DIDComm envelope over OpenID the IANA type ("typ" header) "application/didCommunicationUtils-encrypted+json" is the default.
// Guarantees confidentiality and integrity. Also proves the identity of the sender – but in a way that only the recipient can verify.
// Aligning with RFC 7515, IANA types for DIDComm messages MAY omit the "application/" prefix;
// the recipient MUST treat media types not containing "/" as having the "application/" prefix present.
// The "from" attribute in the plaintext message MUST match the signer’s kid in a signed message.
// The "from" attribute in the plaintext message MUST match the skid attribute in the encryption layer.
// The "to" attribute in the plaintext message MUST contain the kid attribute of an encrypted message.

// OpenidHttpPrivateData contains HttpHeaders such as blockchainUtils.PrivateDataToSC
type OpenidHttpPrivateData struct {
	HttpHeaders httpUtils.HttpPrivateHeadersOpenid `json:"httpHeaders,omitempty" bson:"httpHeaders,omitempty"`
}

// OpenidRequestFormDataDecoded has client_id, response_type and scope outside the request object as per Oauth2 specifications.
type OpenidRequestFormData struct {
	ClientID     string  `json:"client_id,omitempty" bson:"client_id,omitempty"`         // the client ID is stored on a DB collection (e.g.: practitionerRole DID)
	Request      string  `json:"request,omitempty" bson:"request,omitempty"`             // Request with a JWE and nested JWS/JWT, it is not stored.
	ResponseType string  `json:"response_type,omitempty" bson:"response_type,omitempty"` // the response type is stored (e.g.: code, token)
	Scope        *string `json:"scope,omitempty" bson:"scope,omitempty"`                 // the scope is stored
}

// Bearer.Header.iss should be the DID or the URL of the kid (better the DID to have the JWK Thumbprint in the logs).
type OpenidRequestMeta struct {
	Bearer  *OpenidAccessTokenPayload `json:"bearer,omitempty" bson:"bearer,omitempty"`
	DPoP    *OpenidDpopPayload        `json:"dpop,omitempty" bson:"dpop,omitempty"`
	IDToken *OpenidIDTokenPayload     `json:"idToken,omitempty" bson:"idToken,omitempty"`
}

type OpenidAccessTokenPayload struct {
}

type OpenidIDTokenPayload struct {
}

// The payload of a DPoP proof MUST contain at least the following claims:
// - jti: Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 UUID string according to [RFC4122]. The jti can be used by the server for replay detection and prevention, see Section 11.1.
// - htm: The HttpHeaders method of the request to which the JWT is attached, as defined in [RFC7231].
// - htu: The HttpHeaders request URI (Section 5.5 of [RFC7230]), without query and fragment parts.
// - iat: Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).When the DPoP proof is used in conjunction with the presentation of an access token, see Section 7, the DPoP proof MUST also contain the following claim:
// - ath: hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
type OpenidDpopPayload struct {
}

// The JOSE header of a DPoP JWT MUST contain at least the following parameters:
// - typ: with value dpop+jwt.
// - alg: a digital signature algorithm identifier as per [RFC7518]. MUST NOT be none or an identifier for a symmetric algorithm (MAC).
// - jwk: representing the public key chosen by the client, in JSON Web Key (JWK) [RFC7517] format, as defined in Section 4.1.3 of [RFC7515]. MUST NOT contain a private key.
// see https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-09.html
type OpenidDpopHeader struct {
}

var GetOpenidRequestFormData = func(r *http.Request) *OpenidRequestFormData {
	// use r.ParseForm and r.FormValue instead of Gorilla mux params := mux.Vars(r)
	if err := r.ParseForm(); err != nil {
		return nil
	}
	// use r.Form.Get("param-name") instead of Gorilla mux params["param-name"]
	scope := r.Form.Get("scope")
	openidRequestJAR := &OpenidRequestFormData{
		ClientID:     r.Form.Get("client_id"),
		Request:      r.Form.Get("request"),
		ResponseType: r.Form.Get("response_type"),
		Scope:        &scope,
	}

	return openidRequestJAR
}
var GetPublicEncryptionKeyByOpenidHeaders = func(openidHeaders *openidUtils.OpenidHeaders) *jwkUtils.JWK {
	jwkSet := openidHeaders.HeaderJSONWebKeySet.SearchJWKeyByAlg("kyber")
	if jwkSet != nil || len(*jwkSet) > 1 {
		jwk := *jwkSet
		return &jwk[0]
	} else {
		return nil
	}
}

// CheckResponseTypeAndMode returns true if "response_type" contains "code", "token", or "data"
func CheckResponseTypeAndMode(decodedRequestPayload *DecodedRequestPayloadJAR) bool {
	responseType := decodedRequestPayload.ResponseType
	if responseType != nil {

		// OpenID Connect Authorization and Authentication flow (code, access_token)
		if strings.Contains(*responseType, "code") || strings.Contains(*responseType, "token") {
			return true
		}

		// JSON:API CRUDS operations
		if strings.Contains(*responseType, "data") {
			return true
		}

	}

	return false

}
