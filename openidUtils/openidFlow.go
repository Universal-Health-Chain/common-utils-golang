package openidUtils

import (
	"errors"
	"time"
)

// The OpenID "state" property is unique to the requester (sender) to identify the request,
// it is used as a thread ID by the recipient (issuer of the response) and included in the response.
// As per the DIDComm specification, the message that begins a thread may declare a "thid" property for the new thread
// and if no "thid" property is declared in the first message of an interaction
// the "id" property of the message must be treated as the value of the "thid".
// Instead of using the "id" for that, to envelope a OpenID message (OAuth2 protocol) over DIDComm
// the "state" property shall be copied to the "thid" to be compliant with both specifications.
//
// In the DIDComm specification each type of message has its own schema for body (the application-level data).
// and is predicted by the value of the message’s payload "type" attribute (e.g.: "openid", "json:api");
// the media type of the envelope is set the header "typ" property for typed JWT, JWM and DIDComm messages (e.g.: "JWT", "code+jwt", "fhir+json").
//
// Profiles are named in the accept section of a DIDComm service endpoint, in an out-of-band message and in HTTP Accept header.
// When a client app declares that accepts DIDComm response (e.g.: "didcomm/v2") it is saying that all route to it
// (such as OpenID responses, JSON:API responses) will use the didcomm profile specified.

/*
When parties want to communicate via DIDComm, a number of mechanisms must align.
(https://identity.foundation/didcomm-messaging/spec/)
These include:
    The type of service endpoint used by each party
    The key types used for encryption and/or signing
    The format of the encryption and/or signing envelopes
    The encoding of plaintext messages
    The protocol used to forward and route
    The protocol embodied in the plaintext messages

*/

/*
https://identity.foundation/didcomm-messaging/spec/

*/

// SMART Auth from https://hl7.org/fhir/uv/bulkdata/authorization/index.html

/** Step 1:
 * At launch time, the app constructs a request for authorization by supplying the following parameters to the EHR’s “authorize” endpoint.
 * Note on PKCE Support: the EHR SHALL ensure that the code_verifier is present and valid in Step 3 (“App exchanges authorization code for access token”), at the completion of the OAuth flow.
 * The app SHOULD limit its requested scopes to the minimum necessary (i.e., minimizing the requested data categories and the requested duration of access).
 * If the app needs to authenticate the identify of or retrieve information about the end-user, it should include two OpenID Connect scopes: openid and fhirUser.
 * When these scopes are requested, and the request is granted, the app will receive an id_token along with the access token.
 * For full details, see SMART launch context parameters.
 * The following requirements are adopted from OpenID Connect Core 1.0 Specification section 3.1.2.1:
 * Authorization Servers SHALL support the use of the HttpHeaders GET and POST methods at the Authorization Endpoint.
 * Clients SHALL use either the HttpHeaders GET or the HttpHeaders POST method to send the Authorization Request to the Authorization Server.
 * If using the HttpHeaders GET method, the request parameters are serialized using URI Query String Serialization.
 * If using the HttpHeaders POST method, the request parameters are serialized using Form Serialization and the application/x-www-form-urlencoded content type.
 */
type RequestOauthAuthorizeWithPKCE struct {
	ResponseType        string `bson:"response_type,omitempty" json:"response_type,omitempty"`                 // Required: Fixed value is "code"
	ClientId            string `bson:"client_id,omitempty" json:"client_id,omitempty"`                         // Required: The client's identifier.
	RedirectUri         string `bson:"redirect_uri,omitempty" json:"redirect_uri,omitempty"`                   // Required: Must match one of the client's pre-registered redirect URIs.
	Launch              string `bson:"launch,omitempty" json:"launch,omitempty"`                               // Optional: When using the EHR Launch flow, this must match the Launch value received from the EHR.
	Scope               string `bson:"scope,omitempty" json:"scope,omitempty"`                                 // Required: Must describe the access that the app needs, including scopes like patient/*.read, openid and fhirUser (if app needs authenticated patient identity) and either see SMART on FHIR Access Scopes details.
	State               string `bson:"state,omitempty" json:"state,omitempty"`                                 // Required: An opaque value used by the client to maintain State between the request and callback. The authorization server includes this value when redirecting the user-agent back to the client. The parameter SHALL be used for preventing cross-site request forgery or session fixation attacks. The app SHALL use an unpredictable value for the State parameter with at least 122 bits of entropy (e.g., a properly configured random uuid is suitable).
	Audience            string `bson:"aud,omitempty" json:"aud,omitempty"`                                     // Required: URL of the EHR resource server from which the app wishes to retrieve FHIR data. This parameter prevents leaking a genuine bearer token to a counterfeit resource server. (Note: in the case of an EHR Launch flow, this Audience value is the same as the Launch's iss value.) Note that the Audience parameter is semantically equivalent to the resource parameter defined in RFC8707. SMART's Audience parameter predates RFC8707 for reasons of backwards compatibility.
	CodeChallenge       string `bson:"code_challenge,omitempty" json:"code_challenge,omitempty"`               // Required: This parameter is generated by the app and used for the code challenge, as specified by PKCE. For example, when code_challenge_method is 'S256', this is the S256 hashed version of the code_verifier parameter. See considerations-for-pkce-support.
	CodeChallengeMethod string `bson:"code_challenge_method,omitempty" json:"code_challenge_method,omitempty"` // Required: Method used for the CodeChallenge parameter. Example value: S256. See considerations-for-pkce-support.
}

/* RequestOauthAuthorizeWithPKCE example
   Location: https://ehr/authorize?
               response_type=code&
               client_id=app-client-id&
               redirect_uri=https%3A%2F%2Fapp%2Fafter-auth&
               launch=xyz123&
               scope=launch+patient%2FObservation.read+patient%2FPatient.read+openid+fhirUser&
               state=98wrghuwuogerg97&
               Audience=https://ehr/fhir
*/

/** Step 2:
 * When the EHR decides grant access it is communicated to the app returning an authorization code (or, if denying access, an error response).
 * Authorization codes are short-lived, usually expiring within around one minute.
 * The code is sent when the EHR authorization server causes the browser to navigate to the app’s redirect_uri, with the following URL parameters:
 */
type ResponseOauthAuthorizeWithCode struct {
	Code  string `bson:"code,omitempty" json:"code,omitempty"`   // Required: The authorization Code generated by the authorization server. The authorization Code *must* expire shortly after it is issued to mitigate the risk of leaks.
	State string `bson:"state,omitempty" json:"state,omitempty"` // Required: The exact value received from the client.
}

/* ResponseOauthAuthorizeWithCode example:
   The app SHALL validate the value of the state parameter upon return to the redirect URL and SHALL ensure that the state value is securely tied to the user’s current session (e.g., by relating the state value to a session identifier issued by the app).
   Location: https://app/after-auth?
     code=123abc&
     state=98wrghuwuogerg97
*/

/** Step 3.A:
 * App exchanges authorization code for access token
 * After obtaining an authorization code, the app trades the code for an access token via HttpHeaders POST to the EHR authorization server’s token endpoint URL, using content-type application/x-www-form-urlencoded, as described in section 4.1.3 of RFC6749.
 * For public apps or not registered devices, authentication is not possible (since a client with no secret cannot prove its identity when it issues a call).
 * (The end-to-end system can still be secure because the client comes from a known, https protected endpoint specified and enforced by the redirect uri)
 * For confidential apps, authentication is required.
 * Confidential clients SHOULD use Asymmetric Authentication (see 3.B) if available (when confidential app is running in a registered device), and MAY use Symmetric Authentication.
 */
type RequestOauthAccessTokenByCodeConfidentialAppPKCE struct {
	GrantType    string `bson:"grant_type,omitempty" json:"grant_type,omitempty"`       // Required: Fixed value is "authorization_code"
	Code         string `bson:"code,omitempty" json:"code,omitempty"`                   // Required: Code that the app received from the authorization server
	RedirectUri  string `bson:"redirect_uri,omitempty" json:"redirect_uri,omitempty"`   // Required: The same RedirectUri used in the initial authorization request
	CodeVerifier string `bson:"code_verifier,omitempty" json:"code_verifier,omitempty"` // Conditional: it is for PKCE. This parameter is used to verify against the code_challenge parameter previously provided in the authorize request.
}

type RequestOauthAccessTokenByNonConfidentialApp struct {
	RequestOauthAccessTokenByCodeConfidentialAppPKCE
	ClientId string `bson:"client_id,omitempty" json:"client_id,omitempty"` // Only used in non confidential apps.
}

/** Step 3.B:
 * Confidential app in a registered device uses Asymmetric Authentication
 * and sends a NestedJWT instead of doing the Authorize Code flow (skip steps from 1 to 3.A)
 */
type RequestOauthAccessTokenWithJWS struct {
	ClientAssertion     string `bson:"client_assertion,omitempty" json:"client_assertion,omitempty"`           // Signed authentication JWT (NestedJWT generated by the client application)
	ClientAssertionType string `bson:"client_assertion_type,omitempty" json:"client_assertion_type,omitempty"` // Fixed to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	GrantType           string `bson:"grant_type,omitempty" json:"grant_type,omitempty"`                       // Fixed to "client_credentials"
	Scope               string `bson:"scope,omitempty" json:"scope,omitempty"`                                 // scopes such as "system/(:resourceType|*).(read|write|*)" which are associated with permissions assigned to an authorized software client rather than to a human end-user.
	// "lauch/connection/<id>"
}

/** Step 4:
 * The EHR authorization server SHALL return a JSON object that includes an access token or a message indicating that the authorization request has been denied.
 */
type ResponseOauthAccessToken struct {
	AccessToken   string  `bson:"access_token,omitempty" json:"access_token,omitempty"`   // Required: The access token issued by the authorization server.
	TokenType     string  `bson:"token_type,omitempty" json:"token_type,omitempty"`       // Required: Fixed value is "Bearer", not "bearer": http://www.hl7.org/fhir/smart-app-launch/
	ExpiresIn     int     `bson:"expires_in,omitempty" json:"expires_in,omitempty"`       // Recommended: Lifetime in seconds of the access token, after which the token SHALL NOT be accepted by the resource server. The recommended value is 300, for a five-minute token lifetime.
	Scope         string  `bson:"scope,omitempty" json:"scope,omitempty"`                 // Required: Scope of access authorized. Note that this can be different from the scopes requested by the app.
	IdentityToken *string `bson:"id_token,omitempty" json:"id_token,omitempty"`           // Optional: Authenticated user identity and user details, if requested.
	RefreshToken  *string `bson:"refresh_token,omitempty" json:"refresh_token,omitempty"` // Optional: Token that can be used to obtain a new access token, using the same or a subset of the original authorization grants.
}

// It returns the standardized OAuth2 properties.
// expiration (exp) are seconds, not miliseconds.
var CreateResponseOAuthToken = func(accessToken, idToken, scope *string, expiration int) (*ResponseOauthAccessToken, error) {
	if accessToken == nil || scope == nil || expiration < time.Now().Second() {
		return nil, errors.New("bad format to create the response")
	}

	responseOAuthAccessToken := &ResponseOauthAccessToken{
		AccessToken:   *accessToken, // The access token issued by the authorization server.
		ExpiresIn:     expiration,   // The lifetime in seconds of the access token. The recommended value is 300, for a five-minute token lifetime.
		TokenType:     "bearer",
		Scope:         *scope, // Scope of access authorized. Note that this can be different from the scopes requested by the app.
		IdentityToken: idToken,
	}

	return responseOAuthAccessToken, nil
}

/* convert token's claims to standard claims
   var tm time.Time
   switch iat := claims["iat"].(type) {
   case float64:
       tm = time.Unix(int64(iat), 0)
   case json.Number:
       v, _ := iat.Int64()
       tm = time.Unix(v, 0)
   }
*/
