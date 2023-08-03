package openidUtils

import (
	"encoding/json"
)

// SIOP v2:
// Self-Issued OpenID Provider Discovery: The value of the "iss" Claim in the ID Token indicates which Self-Issued OP discovery mechanism was used.
// see https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
// Self-Issued ID Token:
// - "iss" (REQUIRED). in case of a self-issued ID token, this claim MUST be set to the value of the "sub" claim in the same ID Token.
// - "sub" (REQUIRED). Subject identifier value. When Subject Syntax Type is JWK Thumbprint, the value is the base64url encoded representation of the thumbprint of the key in the sub_jwk Claim. When Subject Syntax Type is Decentralized Identifier, the value is a Decentralized Identifier. The thumbprint value of JWK Thumbprint Subject Syntax Type is computed as the SHA-256 hash of the octets of the UTF-8 representation of a JWK constructed containing only the REQUIRED members to represent the key, with the member names sorted into lexicographic order, and with no white space or line breaks.
// - "sub_jwk" (OPTIONAL). A JSON object that is a public key used to check the signature of an ID Token when Subject Syntax Type is JWK Thumbprint.
//
//
// 3.3 Generate SIOP Response
// The SIOP MUST generate and send the <SIOP Response> to the RP as described in the Self-Issued OpenID Provider Response section in [OIDC.Core]. The id_token represents the <SIOP Response> encoded as a JWS, or nested JWS/JWE.
// This specification introduces additional rules for claims in the id_token:
// REQUIRED. sub_jwk MUST contain a kid that is a DID URL referring to the verification method in the SIOP's DID Document that can be used to verify the JWS of the id_token directly or indirectly.

// see https://pkg.go.dev/go.step.sm/crypto and https://www.iana.org/assignments/jwt/jwt.xhtml
// urn:ietf:params:oauth:token-type:jwt and IANA "application/jwt"
// OpenidPayload represents public claim values (as specified in RFC 7519).
// - Client IP Address (cdniip) [optional] - The Client IP Address (cdniip) claim holds an IP address or IP prefix for which the Signed URI is valid. This is represented in CIDR notation with dotted decimal format for IPv4 addresses [RFC0791] or canonical text representation for IPv6 addresses [RFC5952]. The request MUST be rejected if sourced from a client outside the specified IP range. Since the Client IP is considered personally identifiable information, this field MUST be a JSON Web Encryption (JWE [RFC7516]) Object in compact serialization form
// - Universal Entity ID Claim (ueid): UEIDs are 33 bytes long (1 type byte and 256 bits). Type Byte 0x01 (RAND) is a 128, 192 or 256-bit random number generated once and stored in the entity (or the hash of a unique number).
// - Semi-permanent UEIDs (sueids) //An SEUID is of the same format as a UEID, but it MAY change to a different value on device life-cycle events. Examples of these events are change of ownership, factory reset and on-boarding into an IoT device management system. An entity MAY have both a UEID and SUEIDs, neither, one or the other.
// - ProofJSON-of-Possession Intended Use Claim (intended-use): An EAT consumer may require an attestation as part of an accompanying proof-of-possession (PoP) application. More precisely, a PoP transaction is intended to provide to the recipient cryptographically-verifiable proof that the sender has possession of a key. This kind of attestation may be necceesary to verify the security state of the entity storing the private key used in a PoP application.
type OpenidPayload struct {
	// Claims for both request and response flows
	Audience    *string `json:"aud,omitempty" bson:"aud,omitempty"`
	Expiry      *int64  `json:"exp,omitempty" bson:"exp,omitempty"`
	IssuedAt    *int64  `json:"iat,omitempty" bson:"iat,omitempty"`
	Issuer      *string `json:"iss,omitempty" bson:"iss,omitempty"`
	JSONTokenID *string `json:"jti,omitempty"`
	Nonce       *string `json:"nonce,omitempty"  bson:"nonce,omitempty"`
	NotBefore   *int64  `json:"nbf,omitempty" bson:"nbf,omitempty"`
	Subject     *string `json:"sub,omitempty" bson:"sub,omitempty"`
	Scope       *string `json:"scope,omitempty" bson:"scope,omitempty"`
	State       *string `json:"state,omitempty"  bson:"state,omitempty"`
	LocalesUI   *string `json:"ui_locales,omitempty" bson:"ui_locales,omitempty"`
	LoginHint   *string `json:"login_hint,omitempty" bson:"login_hint,omitempty"`

	// Claims for request
	Assertion           *string `json:"assertion,omitempty" bson:"assertion,omitempty"`
	ClientID            *string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	CodeChallenge       *string `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`     // when requesting a code
	CodeChallengeMethod *string `json:"code_challenge_method" bson:"code_challenge_method,omitempty"` // when requesting a code
	CodeVerifier        *string `json:"code_verifier,omitempty" bson:"code_verifier,omitempty"`       // when requesting a token
	GrantType           *string `json:"grant_type,omitempty" bson:"code_verifier,omitempty"`          // when requesting a code, it MUST be set to "authorization_code".
	RedirectURI         *string `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseType        *string `json:"response_type,omitempty" bson:"response_type,omitempty"` // e.g.: "code" or "access_token",

	// Claims for response
	Code *string `json:"code,omitempty" bson:"code,omitempty"`

	// Other claims
	// VC  *ebsiUtils.CredentialEBSI `json:"vc,omitempty" bson:"vc,omitempty"`
	// EAT *eatUtils.ClaimsEAT       `bson:"inline"` // An Entity Attestation Token (EAT) provides an attested claims set that describes state and characteristics of an entity, a device like a phone, IoT device, network equipment or such.

	// TODO: verififiable presentation (for self issued id_tokens)
}

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims OpenidPayload

// JWTCredClaims is JWT Claims extension by Verifiable CredentialAries (with custom "vc" claim).
type JWTCredClaims struct {
	Claims *OpenidPayload

	VC map[string]interface{} `json:"vc,omitempty"`
}

// GetJSON method returns a *map[string]interface{} with the JSON data or nil if error.
func (payload *OpenidPayload) GetJSON() (*map[string]interface{}, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	payloadJSON := map[string]interface{}{}
	err = json.Unmarshal(payloadBytes, &payloadJSON)
	if err != nil {
		return nil, err
	}

	return &payloadJSON, nil
}

// GetBytes method returns the marshall to bytes or nil if error.
func (payload *OpenidPayload) GetBytes() (*[]byte, error) {
	headersBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &headersBytes, nil
}

// SetJSON method puts the given JSON data(*map[string]interface{}) to the OpenidHeaders struct
func (payload *OpenidPayload) SetJSON(payloadJSON *map[string]interface{}) error {
	headersBytes, err := json.Marshal(payloadJSON)
	if err != nil {
		return err
	}

	err = json.Unmarshal(headersBytes, payload) // setting the data (bytes) in the OpenidHeaders struct
	if err != nil {
		return err
	}

	return nil
}
