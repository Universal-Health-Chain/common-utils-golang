package openidUtils

import (
	"strings"

)

/* The manager creates this object:
const responseAccessTokenData := OpenidAccessTokenResponseData{
	AccessToken: compactJWS, // The access token issued by the authorization server.
	TokenType:   "bearer",
	ExpiresIn:   expiration,     // The lifetime in seconds of the access token. The recommended value is 300, for a five-minute token lifetime.
	Scope:       requestedScope, // Scope of access authorized. Note that this can be different from the scopes requested by the app.
}
*/

const AuthorizationBearerType = "Bearer"

// using snake_case because of JWT standard claims: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
type OpenidAccessTokenResponseData struct {
	AccessToken  string  `json:"access_token,omitempty" bson:"access_token,omitempty"` // compactJWS: the access token issued by the authorization server.
	TokenType    string  `json:"type,omitempty" bson:"type,omitempty"`                 // fixed to "bearer"
	ExpiresIn    int64   `json:"expires_in,omitempty" bson:"expires_in,omitempty"`     // The lifetime in seconds of the access token. The recommended value is 300, for a five-minute token lifetime.
	Scope        string  `json:"scope,omitempty" bson:"scope,omitempty"`               // Scope of access authorized. Note that this can be different from the scopes requested by the app.
	RefreshToken *string `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
	IDToken      *string `json:"id_token,omitempty" bson:"id_token,omitempty"`
}

// using snake_case because of JWT standard claims: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
type StandardClaimsJWT struct {
	// StandardClaims	jwt.Claims 	`bson:",inline" json:",inline"`		// inline, 'AudienceSlice' is the appAliasUrl and 'iss' is UNID
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Expiry    int64  `json:"exp,omitempty"` // it is int64
	NotBefore int64  `json:"nbf,omitempty"` // it is int64
	IssuedAt  int64  `json:"iat,omitempty"` // it is int64
	ID        string `json:"jti,omitempty"`
}

// TODO: review audience
var GetAppAliasByAudience = func(jwtAudience []string) string {
	parts := strings.Split(jwtAudience[0], "/")
	partsLength := len(parts)

	if partsLength == 1 {
		return parts[0] // it not an url but a single appAliasUrl
	}
	if partsLength >= 3 { // url ends with <some>/appAliasUrl/token, so getting the len-2 (not the last but the previous part)
		return parts[partsLength-2] // it will return appAliasUrl from http://<some>/appAliasUrl/token
	}
	return "" // empty string, appAliasUrl not found
}

/*
OLD SIOPv1: Request Object
https://identity.foundation/did-siop/#generate-siop-request
The Request Object follows the OIDC specification, e.g., adding "nonce", "state", "response_type", and "client_id" parameters.
The request contains "scope", "response_type" and "client_id" as query string parameters for backward compatibility with the OAuth2 specification [RFC6749].
"response_type" MUST be "id_token" and "client_id" MUST specify the redirect URI of the RP (as per [OIDC.Core])

REQUIRED. iss MUST contain the DID of the RP that can be resolved to a DID Document.
The DID Document MUST contain a verification method in the authentication section, e.g., public key, that allows the SIOP to verify the Request Object.
Note: By default, the iss claim refers to the client_id but SIOP assumes that client_id is the redirect URI of the RP.
That is the reason why the DID is not encoded in the client_id. It is compliant with the OIDC specification to use different values for iss and client_id.
REQUIRED. kid MUST be a DID URL referring to a verification method in the authentication section in the RP's DID Document, e.g., did:example:0xab#key1.
The SIOP MUST be able to use that verification method to verify the Request Object directly or indirectly.
Additionally, the referred JWKS in the registration parameter MUST contain an entry with the same kid.

 - Resolve the DID Document from the RP's DID specified in the iss request parameter.
 - If jwks_uri is present, ensure that the DID in the jwks_uri matches the DID in the iss claim.
 - Determine the verification method from the RP's DID Document that matches the kid of the SIOP Request.
 - Verify the SIOP Request according to the verification method above. This step depends on the verification method in the authentication section in the DID Document and is out-of-scope of this specification.

OLD Generate SIOP Response
https://identity.foundation/did-siop/#generate-siop-response
The SIOP MUST generate and send the <SIOP Response> to the RP as described in the Self-Issued OpenID Provider Response section in [OIDC.Core].
The id_token represents the <SIOP Response> encoded as a JWS, or nested JWS/JWE.

// from https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
7.3.  Self-Issued OpenID Provider Request
The Client sends the Authentication Request to the Authorization Endpoint with the following parameters:
    scope REQUIRED. scope parameter value, as specified in Section 3.1.2.
    response_type REQUIRED. Constant string value id_token.
    client_id REQUIRED. Client ID value for the Client, which in this case contains the redirect_uri value of the Client. Since the Client's redirect_uri URI value is communicated as the Client ID, a redirect_uri parameter is NOT REQUIRED to also be included in the request.
    id_token_hint OPTIONAL. id_token_hint parameter value, as specified in Section 3.1.2. If the ID Token is encrypted to the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE. Encrypting content to Self-Issued OPs is currently only supported when the OP's JWK key type is RSA and the encryption algorithm used is RSA1_5.
    claims OPTIONAL. claims parameter value, as specified in Section 5.5.
    registration OPTIONAL. This parameter is used by the Client to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic Client Registration, as specified in Section 7.2.1.
    request OPTIONAL. Request Object value, as specified in Section 6.1. The Request Object MAY be encrypted to the Self-Issued OP by the Client. In this case, the sub (subject) of a previously issued ID Token for this Client MUST be sent as the kid (Key ID) of the JWE. Encrypting content to Self-Issued OPs is currently only supported when the OP's JWK key type is RSA and the encryption algorithm used is RSA1_5.

Other parameters MAY be sent. Note that all Claims are returned in the ID Token.
The entire URL MUST NOT exceed 2048 ASCII characters.
The following is a non-normative example HTTP 302 redirect response by the Client, which triggers the User Agent to make an Authentication Request to the Self-Issued OpenID Provider (with line wraps within values for display purposes only):
*/

/* Standard JWE (encrypted JWT):
Header
REQUIRED:
- "cty", type of the content, e.g.: "JWT".
- "enc", encryption algorithm, e.g.: AES 256.
- "alg", algorithm used to encrypt the CEK (it is for each recipient's header).
OPTIONAL:
- "zip", if it has "DEF" then the payload data (bytes) are compressed (deflated).

*/

// JOSE Header describe the cryptographic operations applied to the JWT and optionally, additional properties of the JWT
// Payload: Base64url encoding the octets of the UTF-8 representation of the JWT Claims Set yields
// https://datatracker.ietf.org/doc/html/rfc7519

// An specific endpoint takes the previous auth token (which is still valid), and returns a new token with a renewed expiry time.
// To minimize misuse of a JWT, the expiry time is usually kept in the order of a few minutes.
// Typically the client application would refresh the token in the background.

/* ID Token: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
endpoint /userinfo Request: It is RECOMMENDED that the request use the HttpHeaders GET method and the Access Token be sent using the Authorization header field.

Do not use ID tokens to gain access to an API.
Each token contains information for the intended audience (which is usually the recipient).
According to the OpenID Connect specification, the audience of the ID token (indicated by the AudienceSlice claim)
must be the client ID of the application making the authentication request.
If this is not the case, you should not trust the token.

The decoded contents of an ID token looks like the following:
{
  "iss": "http://YOUR_DOMAIN/",
  "sub": "auth0|123456",
  "AudienceSlice": "YOUR_CLIENT_ID",
  "exp": 1311281970,
  "iat": 1311280970,
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "gender": "female",
  "birthdate": "0000-10-31",
  "email": "janedoe@example.com",
  "picture": "http://example.com/janedoe/me.jpg"
}

This token authenticates the user to the application.
The audience (the AudienceSlice claim) of the token is set to the application's identifier, which means that only this specific application should consume this token.

5.1.  Standard Claims
This specification defines a set of standard Claims. They can be requested to be returned either in the UserInfo Response, per Section 5.3.2, or in the ID Token, per Section 2.
Table 1: Registered Member Definitions

Member	Type	Description
sub	string	Subject - Identifier for the End-User at the Issuer.
name	string	End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
given_name	string	Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
family_name	string	Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
middle_name	string	Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
nickname	string	Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
preferred_username	string	Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
profile	string	URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
picture	string	URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
website	string	URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
email	string	End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
email_verified	boolean	True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
gender	string	End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
birthdate	string	End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just year can result in varying month and day, so the implementers need to take this factor into account to correctly process the dates.
zoneinfo	string	String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
locale	string	End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
phone_number	string	End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
phone_number_verified	boolean	True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
address	JSON object	End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 5.1.1.
updated_at	number	Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
*/
