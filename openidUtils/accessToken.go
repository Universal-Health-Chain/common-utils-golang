package openidUtils

import (
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
)

// AccessTokenHeaderType definition: https://datatracker.ietf.org/doc/html/rfc9068#section-2
// The "typ" value used SHOULD be "at+jwt", preventing OpenID Connect ID Tokens from being accepted as access tokens.
const AccessTokenHeaderType = "at+jwt"

var (
	ErrAccessTokenInvalid                    = `invalid access token`
	ErrAccessTokenWrongType                  = `invalid JWT access token type`
	ErrAccessTokenUnsupportedAlgorithm       = `unsupported algorithm for access token`
	ErrAccessTokenMissingIssuerKid           = `the issuer's keyID does not exist in the access token`
	ErrAccessTokenMissingRequiredPayloadData = `required data is missing in the access token`
	ErrAccessTokenExpired                    = `the access token is expired`
)

//	OpenidHeadersAccessToken structure.
//	The JOSE header of an Access Token JWT MUST contain at least following parameters:
//   *  "alg": a digital signature algorithm identifier such as per [RFC7518]. MUST NOT be "none".
//   *  "kid": thumbprint of the JWK representing the public key used by the issuer
//   *  "typ": with value "at+jwt", preventing OpenID Connect ID Tokens from being accepted as access tokens.
// 	See  https://datatracker.ietf.org/doc/html/rfc9068#section-2
type AccessTokenHeader struct {
	// For JWS: the cryptographic algorithm the issuer used to secure the JWS.
	Algorithm string `json:"alg,omitempty" bson:"alg,omitempty"` // "none" is only allowed for testing purposes.

	// For JWS: indicating which key the issuer used to secure the JWS.
	KeyID string `json:"kid,omitempty" bson:"kid,omitempty"` // JWK Thumbprint.

	// For JWS: used by JWS applications to declare the media type of this complete JWS.
	Type string `json:"typ,omitempty" bson:"typ,omitempty"` // "at+jwt".
}

//	AccessTokenPayload structure.
//	The payload of a JWT access token MUST contain at least the following claims:
//	- "iss": REQUIRED. Issuer organization's identity DID.
//	- "exp": REQUIRED. Expiry of the JWT.
//	- "sub": REQUIRED. Subject in UHC refers to a person (DID of an employee in an organization or a personal DID).
//  When no resource owner is involved "sub" SHOULD correspond to the client application identifier ("client_id").
//	- "client_id": REQUIRED.
//	In UHC, it is the cryptographic signature identifier of an employee who performs a role in a department (DID#kid),
//	of a patient or of an authorized person: legal guardian, family member or caregiver.
//	- "aud": REQUIRED. Audience of the JWT, it should be the "software_id" for the "client_id" (profile role)
//	- "iat":  REQUIRED - as defined in Section 4.1.6 of [RFC7519]. It identifies the time at which the JWT access token was issued.
//	- "jti":  REQUIRED - as defined in Section 4.1.7 of [RFC7519].
//
// Authorization claim: If an authorization request includes a scope parameter, it SHOULD include a "scope" claim.
// - "scope": CONDITIONAL - as defined in Section 4.2 of [RFC8693].
//
// SCIM: System for Cross-domain Identity Management (to be defined in an "id_token" or "vp_token" for the frontend):
// Memberships in roles and groups that are relevant to the resource being accessed,
// entitlements assigned to the resource owner for the targeted resource that the authorization server knows about, etc.
// - "groups": OPTIONAL. In UHC, they are the departments (healthcare services) a practitioner role ("sub") belongs to.
//	 Example: [{"value": <department DID>, "display": <official name>}]
// - "roles": OPTIONAL. In UHC, it refers to one or more professional SNOMED roles (e.g: generic M.D. and specialty).
// - "entitlements": OPTIONAL. In UHC, they can be the qualifications a practitioner role has.
// 	 Example: [{"value": <qualification DID>, "display": <official title>}]
// See: https://datatracker.ietf.org/doc/html/rfc7643.
//
// Additionally:
// - "auth_time": OPTIONAL - as defined in Section 2 of [OpenID.Core].
// - "acr":  OPTIONAL - as defined in Section 2 of [OpenID.Core].
// - "amr":  OPTIONAL - as defined in Section 2 of [OpenID.Core].
//
type AccessTokenPayload struct {
	Audience    string `json:"aud,omitempty" bson:"aud,omitempty"`
	ClientID    string `json:"client_id,omitempty" bson:"client_id,omitempty"`
	Expiry      int64  `json:"exp,omitempty" bson:"exp,omitempty"`
	IssuedAt    int64  `json:"iat,omitempty" bson:"iat,omitempty"`
	Issuer      string `json:"iss,omitempty" bson:"iss,omitempty"`
	JSONTokenID string `json:"jti,omitempty" bson:"jti,omitempty"`
	Scope       string `json:"scope,omitempty" bson:"scope,omitempty"`
	Subject     string `json:"sub,omitempty" bson:"sub,omitempty"`
}

// **FUNCTIONS**

// CheckCompactAccessToken returns DataJWT (can be nil) and error message (can be empty) after checking:
// - mandatory fields exist in the DPoP header ("alg", "kid", "typ") and are supported.
// - checks the mandatory fields exist for the access token ("aud", "iss", "exp", "nbf", "sub").
func CheckCompactAccessToken(compactJWT *string, audience, issuer, subject, client *string, expiry, notBefore int64) (*joseUtils.DataJWT, string) {
	dataJWT := joseUtils.GetDataJWT(compactJWT)
	if dataJWT == nil {
		return nil, ErrAccessTokenInvalid
	} else {
		return CheckDataAccessToken(dataJWT, audience, issuer, subject, client, expiry, notBefore)
	}

}

// CheckDataAccessToken returns DataJWT (can be nil) and error message (can be empty) after checking:
// - mandatory fields exist in the Access Token header ("alg", "jwk", "typ") and are supported.
// - checks the mandatory fields exist in the Access Token payload ("aud", "iss", "exp", "nbf", "sub")
// and additionally match with the provided ones (optional).
func CheckDataAccessToken(compactJWT *joseUtils.DataJWT, audience, issuer, subject, client *string, expiry, notBefore int64) (*joseUtils.DataJWT, string) {
	errorHeader := CheckBearerHeaderDataJWT(compactJWT)
	if errorHeader != nil {
		return nil, *errorHeader
	}

	errorPayload := CheckBearerPayloadDataJWT(compactJWT, audience, issuer, subject, client, expiry, notBefore)
	if errorPayload != nil {
		return nil, *errorPayload
	}

	return compactJWT, ""

}

// CheckBearerHeaderDataJWT returns DataJWT (can be nil) and error message (can be empty) after checking:
// - mandatory fields exist in the Access Token header ("alg", "jwk", "typ") and are supported.
// - checks the mandatory fields exist in the Access Token payload ("aud", "iss", "exp", "nbf", "sub")
// and additionally match with the provided ones (optional).
func CheckBearerHeaderDataJWT(dataJWT *joseUtils.DataJWT) (errMsg *string) {
	if dataJWT == nil {
		return &ErrAccessTokenInvalid
	}

	headerBytes, _ := json.Marshal(dataJWT.Header)
	accessTokenHeader := &AccessTokenHeader{}
	err := json.Unmarshal(headerBytes, accessTokenHeader)
	if err != nil {
		return &ErrAccessTokenInvalid
	}

	if accessTokenHeader.Type != AccessTokenHeaderType {
		return &ErrAccessTokenWrongType
	}

	if accessTokenHeader.Algorithm == "" {
		return &ErrAccessTokenUnsupportedAlgorithm
	}

	if accessTokenHeader.KeyID == "" {
		return &ErrAccessTokenMissingIssuerKid
	}

	// done!
	return nil
}

// CheckBearerPayloadDataJWT checks the mandatory fields exist and additionally match with the provided ones (optional):
//	- "aud": Audience of the JWT, in UHC it is the "software_id" (app URL) for the "client_id" (profile role)
//	- "iss": Issuer organization's identity DID.
//	- "sub":Subject in UHC refers to a person (DID of an employee in an organization or a personal DID).
//  When no resource owner is involved "sub" SHOULD correspond to the client application identifier ("client_id").
//	- "client_id": cryptographic signature identifier of an employee who performs a role in a department (DID#kid),
//	- "exp": Expiry of the JWT.
//	of a patient or of an authorized person: legal guardian, family member or caregiver.
//	- "iat": It identifies the time at which the JWT access token was issued.
//	- "jti": The ID of the issued JWT.
//
func CheckBearerPayloadDataJWT(bearerDataJWT *joseUtils.DataJWT, audience, issuer, subject, client *string, expiry, notBefore int64) (errMsg *string) {
	if bearerDataJWT == nil {
		return &ErrAccessTokenInvalid
	}

	payloadBytes, _ := json.Marshal(bearerDataJWT.Payload)
	openidPayload := &OpenidPayload{}
	err := json.Unmarshal(payloadBytes, openidPayload)
	if err != nil {
		return &ErrAccessTokenInvalid
	}

	if openidPayload.Issuer == nil ||
		openidPayload.Subject == nil ||
		openidPayload.NotBefore == nil ||
		openidPayload.Expiry == nil {
		return &ErrAccessTokenMissingRequiredPayloadData
	}

	return nil
}

/*
A verifiable credential (VC) is a tamper-evident credential that has authorship that can be cryptographically verified.
Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verified.

A Verifiable Presentation (VP) is a tamper-evident presentation of data from one or more verifiable credentials,
issued by one or more issuers, encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification.
Certain types of verifiable presentations might contain data that is synthesized from,
but do not contain, the original verifiable credentials (for example, zero-knowledge proofs).
*/

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
// The OpenID for Verifiable Presentations specification defines a mechanism on top of OAuth 2.0 to request and provide
// verifiable presentations of claims in the form of verifiable credentials
// (supporting W3C formats as well as other credential formats) as part of the protocol flow.
// Since OpenID Connect is based on OAuth 2.0, implementations can also be build on top of OpenID Connect,
// e.g. Self-Issued OP v2 [SIOPv2].
// It is used to enable use cases where the presentation of verifiable presentations alone is sufficient.
// This keeps this specification simple, whilst also enabling more complex use cases.

/*  6. Response
The response used to provide the VP Token to the client depends on the grant and response type used in the request.
If only "vp_token" is used as the "response_type", the VP Token is provided in the authorization response.
If the "id_token" is used as the "response_type" alongside "vp_token",
the VP Token is provided in the OpenID Connect authentication response along with the ID Token.
In all other cases, the VP Token is provided in the token (JWT?) response (e.g.: ??).
The VP Token either contains a single verifiable presentation or an array of verifiable presentations.
*/

/*
5. Request
5.1. presentation_definition
This parameter contains a JSON object conforming to the syntax defined for presentation_definition elements
in Section 4 of [DIF.PresentationExchange].

The following example shows how a Relaying Party (RP) can request selective disclosure
or certain claims from a credential of a particular type.

{
    "id": "vp token example",
    "input_descriptors": [
        {
            "id": "id card credential with constraints",
            "format": {
                "ldp_vc": {
                    "proof_type": [
                        "Ed25519Signature2018"
                    ]
                }
            },
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": [
                            "$.type"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "IDCardCredential"
                        }
                    },
                    {
                        "path": [
                            "$.credentialSubject.given_name"
                        ]
                    },
                    {
                        "path": [
                            "$.credentialSubject.family_name"
                        ]
                    },
                    {
                        "path": [
                            "$.credentialSubject.birthdate"
                        ]
                    }
                ]
            }
        }
    ]
}

*/

/*
RPs can also ask for alternative credentials being presented, which is shown in the next example:

{
    "id": "alternative credentials",
    "submission_requirements": [
        {
            "name": "Citizenship Information",
            "rule": "pick",
            "count": 1,
            "from": "A"
        }
    ],
    "input_descriptors": [
        {
            "id": "id card credential",
            "group": [
                "A"
            ],
            "format": {
                "ldp_vc": {
                    "proof_type": [
                        "Ed25519Signature2018"
                    ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.type"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "IDCardCredential"
                        }
                    }
                ]
            }
        },
        {
            "id": "passport credential",
            "format": {
                "jwt_vc": {
                    "alg": [
                        "RS256"
                    ]
                }
            },
            "group": [
                "A"
            ],
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.vc.type"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "PassportCredential"
                        }
                    }
                ]
            }
        }
    ]
}

The VC and VP formats supported by an Authorization Server (AS) should be published in its metadata (see Section 8.1).
The formats supported by a client may be set up using the client metadata parameter "vp_formats" (see Section 8.2.3).
The AS MUST ignore any format property inside a "presentation_definition" object
if that format was not included in the "vp_formats" property of the client metadata.
*/
