package didCommunicationUtils

// In JAR the JWT (data container) is named "Request Object" and in JARM it is named "Response Document"

// PayloadTokenRequestJWT receives from a client app the code challenge as part of the OAuth 2.0 Authorization Request.
// Note: the "id" field (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID.
// - the "type" (required in UHC) field is set in UHC as "code+jar" to predict the content of the message.
// - the "body" (required in UHC) field can have protocol and application-level data as per the DIDComm specification, but it is not used in the standard HTTP OpenID Authorization Code request.
// - the "subject" (required in UHC) field refers in UHC to the target practitioner's DID when an admin is creating an install-code for a practitioner's profile (rather than referring to the cryptographic identifier "client_id" of the requester).
// - the "thid" (required in UHC): it is like the optional OpenID "state" field, but mandatory in the DIDComm specification.
// - the "scope" (required) field value is "openid".
// - the "response_type" (required) field value contains "code".
// - the "response_mode" (required) field value is "jwt" (to get the default "query.jwt" redirect URL format) or "form_post.jwt", recommended in UHC.
// - the "code" (required) field is the code previously generated by the /authorize endpoint.
// - the "nbf" (required) field is no longer than 60 minutes in the past.
// - the "exp" (required) field has a lifetime of no longer than 60 minutes after the "nbf" field.
//	NOTE: Set the expiration period of the authorization code to one minute or a suitable short period of time if not replay is possible. The validity period may act as a cache control indicator of when to clear the authorization code cache if one is used.
// - the "iss" (required) field is the "client_id" of the OAuth Client (private_key_jwt authentication method as specified in section 9 of OIDC). The parameters required to create the professional's client app the "client_id" must be provided offline by the admin.
// - the "client_id" (required) identifies in UHC the identifier of the cryptographic signature key (DID#kid URI) of the profile sending the request
//	(the key ID of the wallet of an employee who performs a role in a concrete department)
// - the "aud" in UHC identifies at the same time the "software_id" URL and the OP's Issuer Identifier URL as the intended Audience. The Authorization Server MUST verify that it is an intended audience.
// - the "jti" field is a unique identifier for the JWT (JWT ID), which can be used to prevent reuse of the request (replay attacks).
// - the "redirect_uri" (conditional) is required when using pushed authorization request (PAR).
type PayloadTokenRequestJWT struct {
	// TODO: define all the fields, sorted alphabetically by the JSON field name.
	Audience       string `json:"aud,omitempty" bson:"aud,omitempty"`
	ClientID       string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	Code           string `json:"code,omitempty" bson:"code,omitempty"` // when requesting a token
	Expiration     int64  `json:"exp,omitempty" bson:"exp,omitempty"`   // end of the valid date (number of seconds from Unix epoch);
	Issuer         string `json:"iss,omitempty" bson:"iss,omitempty"`
	JSONTokenID    string `json:"jti,omitempty" bson:"jti,omitempty"`
	NonValidBefore int64  `json:"nbf,omitempty" bson:"nbf,omitempty"` // start of the valid date (number of seconds from Unix epoch);
	RedirectURI    string `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseMode   string `json:"response_mode,omitempty" bson:"response_mode,omitempty"` // e.g.: "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"
	ResponseType   string `json:"response_type,omitempty" bson:"response_type,omitempty"` // shall be "code"
	Scope          string `json:"scope,omitempty" bson:"scope,omitempty"`
	Subject        string `json:"sub,omitempty" bson:"sub,omitempty"`
	ThreadID       string `json:"thid,omitempty" bson:"thid,omitempty"` // thread of the message, used instead of the optional OpenID State.
	To             string `json:"to,omitempty" bson:"to,omitempty"`     // OPTIONAL. Copy the "kid" field from the JWE header (recipient) of the body.request object before removing the encrypted request object in the body when storing on a DB's collection.
	Type           string `json:"type,omitempty" bson:"type,omitempty"` // The media type of the envelope MAY be set in the "typ" property
}
