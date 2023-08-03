package openidUtils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
)

//	DPoP, or Demonstration of Proof of Possession, is an extension that describes a technique
//	to cryptographically bind access tokens to a particular client when they are issued.
//	This is one of many attempts at improving the security of Bearer Tokens
//	by requiring the application using the token to authenticate itself (to avoid replay attacks).
//
//	DPoP Proof JWT Syntax: A DPoP proof is a JWT ([RFC7519]) that is signed (using JSON Web Signature (JWS) [RFC7515])
//	with a private key chosen by the client.

const DPoPHeaderType = "dpop+jwt"

var (
	ErrDPoPInvalid                    = `invalid DPoP token`
	ErrDPoPMissingRequiredPayloadData = `required "htu", "htm", and/or "iat" data is missing in the DPoP token`
	ErrDPoPAccessTokenHashMissing     = `access token hash "ath" is missing in the DPoP token`
	ErrDPoPAccessTokenMismatch        = `access token hash does not match with the DPoP token`
	ErrDPoPMismatchHttpMethod         = `the HTTP method does not match in the DPoP token`
	ErrDPoPMismatchHttpURL            = `the URL does not match in the DPoP token`
	ErrDPoPExpired                    = `the DPoP token is expired`
	ErrDPoPUnsupportedAlgorithm       = `unsupported algorithm for DPoP token`
	ErrDPoPUnsupportedKey             = `unsupported JSON Web Key for DPoP token`
)

//	DPoPHeader structure.
//	The JOSE header of a DPoP JWT MUST contain at least following parameters:
//   *  "alg": a digital signature algorithm identifier such as per [RFC7518].
//  	MUST NOT be none or an identifier for a symmetric algorithm (MAC).
//   *  "jwk": representing the public key chosen by the client, in JSON Web Key (JWK) [RFC7517] format,
//  	as defined in Section 4.1.3 of [RFC7515].  MUST NOT contain a private key.
//   *  "typ": with value dpop+jwt, which explicitly types the DPoP proof JWT as recommended in Section 3.11 of [RFC8725].
// 	See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-4.2
type DPoPHeader struct {
	// For JWS: the cryptographic algorithm used to secure the JWS.
	Algorithm string `json:"alg,omitempty" bson:"alg,omitempty"`

	// For JWS: the public key that corresponds to the key used to digitally sign the JWS.
	JSONWebKey jwkUtils.JWK `json:"jwk,omitempty" bson:"jwk,omitempty"` // sender's public verification key

	// For JWS: used by JWS applications to declare the media type of this complete JWS.
	Type string `json:"typ,omitempty" bson:"typ,omitempty"` // "dpop+jwt"
}

//	DPoPPayload structure.
//   The payload of a DPoP proof MUST contain at least the following claims:
//   *  "htm": The HTTP method of the request to which the JWT is attached, as defined in [RFC9110].
//   *  "htu": The HTTP target URI (Section 7.1 of [RFC9110]), without query and fragment parts.
//   *  "iat": Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).
//   *  "jti": Unique identifier for the DPoP proof JWT (e.g.: by using a version 4 UUID string according to [RFC4122]).
//  	The jti can be used by the server for replay detection and prevention, see Section 11.1: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#section-11.1
//
//   When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access
//   the DPoP proof MUST also contain the following claim:
//
//   *  "ath": hash of the access token.  The value MUST be the result of a base64url encoding (Section 2 of [RFC7515])
//  	the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
//
//   When the authentication server or resource server provides a DPoP-Nonce HTTP header in a response (Section 8, Section 9),
//   the DPoP proof MUST also contain the following claim:
//
//   *  "nonce": A recent nonce provided via the DPoP-Nonce HTTP header (avoid replay attacks)
//
type DPoPPayload struct {
	AccessTokenHash string `json:"ath,omitempty" bson:"ath,omitempty"`
	HttpMethod      string `json:"htm,omitempty" bson:"htm,omitempty"`
	HttpURL         string `json:"htu,omitempty" bson:"htu,omitempty"`
	IssuedAt        int64  `json:"iat,omitempty" bson:"iat,omitempty"`
	JSONTokenID     string `json:"jti,omitempty" bson:"jti,omitempty"`
	Nonce           string `json:"nonce,omitempty"  bson:"nonce,omitempty"`
}

// **FUNCTIONS**

// CheckCompactDPoP returns DataJWT (can be nil) and error message (can be empty) after checking:
// - mandatory fields exist in the DPoP header ("alg", "jwk", "typ") and are supported.
// - mandatory fields in the DPoP payload exist and are valid: "jti", "iat" (and not expired), "htm" and "htu" match with the provided ones (optional).
// Additionally it checks:
// - the "ath" value which is the SHA-256 [SHS] hash of the ASCII encoding of the access token.
// - the "nonce" value (the parent function has stored it previously to authorize the request).
func CheckCompactDPoP(dpopCompactJWT *string, accessToken, httpMethod, httpURL *string) (*joseUtils.DataJWT, string) {
	dpopDataJWT := joseUtils.GetDataJWT(dpopCompactJWT)
	if dpopDataJWT == nil {
		return nil, ErrDPoPInvalid
	} else {
		return CheckDataDPoP(dpopDataJWT, accessToken, httpMethod, httpURL)
	}

}

// CheckDataDPoP returns DataJWT (can be nil) and error message (can be empty) after checking:
// - mandatory fields exist in the DPoP header ("alg", "jwk", "typ") and are supported.
// - mandatory fields in the DPoP payload exist and are valid: "jti", "iat" (and not expired), "htm" and "htu" match with the provided ones (optional).
// Additionally it checks:
// - the "ath" value which is the SHA-256 [SHS] hash of the ASCII encoding of the access token.
// - the "nonce" value (the parent function has stored it previously to authorize the request).
func CheckDataDPoP(dpopDataJWT *joseUtils.DataJWT, accessToken, httpMethod, httpURL *string) (*joseUtils.DataJWT, string) {
	errorHeader := CheckDPoPTokenHeaderDataJWT(dpopDataJWT)
	if errorHeader != nil {
		return nil, *errorHeader
	}

	errorPayload := CheckDPoPTokenPayloadDataJWT(dpopDataJWT, accessToken, httpMethod, httpURL)
	if errorPayload != nil {
		return nil, *errorPayload
	}

	return dpopDataJWT, ""

}

// CheckDPoPTokenHeaderDataJWT checks that the mandatory fields exist ("alg", "jwk", "typ") and are supported.
func CheckDPoPTokenHeaderDataJWT(dpopDataJWT *joseUtils.DataJWT) (errMsg *string) {
	if dpopDataJWT == nil {
		return &ErrDPoPInvalid
	}

	headerBytes, _ := json.Marshal(dpopDataJWT.Header)
	dpopHeader := &DPoPHeader{}
	err := json.Unmarshal(headerBytes, dpopHeader)
	if err != nil {
		return &ErrDPoPInvalid
	}

	if dpopHeader.Algorithm == "" {
		return &joseUtils.ErrMsgInvalidDPoPToken
	}

	// TODO: CheckPublicJWK format

	// done!
	return nil
}

// CheckDPoPTokenPayloadDataJWT checks that the mandatory fields exist ("htm", "htu", "iat", "jti"
// and additionally:
// - the "ath" value which is the SHA-256 [SHS] hash of the ASCII encoding of the access token.
// - the "nonce" value (the parent function has stored it previously to authorize the request).
func CheckDPoPTokenPayloadDataJWT(dpopDataJWT *joseUtils.DataJWT, accessToken, httpMethod, httpURL *string) (errMsg *string) {
	if dpopDataJWT == nil {
		return &ErrDPoPInvalid
	}

	payloadBytes, _ := json.Marshal(dpopDataJWT.Payload)
	dpopPayload := &DPoPPayload{}
	err := json.Unmarshal(payloadBytes, dpopPayload)
	if err != nil {
		return &ErrDPoPInvalid
	}

	if dpopPayload.HttpMethod == "" ||
		dpopPayload.HttpURL == "" ||
		dpopPayload.JSONTokenID == "" {
		return &ErrDPoPMissingRequiredPayloadData
	}

	if httpMethod != nil && *httpMethod != dpopPayload.HttpMethod {
		return &ErrDPoPMismatchHttpMethod
	}

	if httpURL != nil && *httpURL != dpopPayload.HttpURL {
		return &ErrDPoPMismatchHttpURL
	}

	if accessToken != nil {
		if dpopPayload.AccessTokenHash == "" {
			return &ErrDPoPAccessTokenHashMissing
		}

		accessTokenHashBytes := sha256.Sum256([]byte(*accessToken))
		accessTokenHashBase64Url := base64.RawURLEncoding.EncodeToString(accessTokenHashBytes[:])
		if accessTokenHashBase64Url != dpopPayload.AccessTokenHash {
			return &ErrDPoPAccessTokenMismatch
		}
	}

	expired := joseUtils.CheckNotExpiredDateEpochUNIX(dpopPayload.IssuedAt)
	if expired {
		return &ErrDPoPExpired
	}

	// done!
	return nil

}

// A DPoP proof MAY contain other JOSE header parameters or claims as
//   defined by extension, profile, or deployment specific requirements.
/*
   {
     "typ":"dpop+jwt",
     "alg":"ES256",
     "jwk": {
       "kty":"EC",
       "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
       "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
       "crv":"P-256"
     }
   }
   .
   {
     "jti":"-BwC3ESc6acc2lTc",
     "htm":"POST",
     "htu":"https://server.example.com/token",
     "iat":1562262616
   }
*/

// To sender-constrain the access token, after checking the validity of the DPoP proof,
// the authorization server associates the issued access token with the public key from the DPoP proof,
//
// A token_type of DPoP MUST be included in the access token response
// to signal to the client that the access token was bound to its DPoP key
//
// The example response shown in Figure 5 illustrates such a response.
//
//   HttpHeaders/1.1 200 OK
//   Content-Type: application/json
//   Cache-Control: no-store
//
//   {
//    "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
//    "token_type": "DPoP",
//    "expires_in": 2677,
//    "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
//   }
//                      Figure 5: Access Token Response
//
// The example response in Figure 5 includes a refresh token which the
//   client can use to obtain a new access token when the previous one expires.
// Refreshing an access token is a token request using the
//   refresh_token grant type made to the authorization server's token endpoint.
// As with all access token requests, the client makes it a DPoP request
// by including a DPoP proof, as shown in the Figure 6 example (extra line breaks and whitespace for display purposes only).
//
//   POST /token HttpHeaders/1.1
//   Host: server.example.com
//   Content-Type: application/x-www-form-urlencoded
//   DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
//    VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
//    nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
//    QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
//    oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
//    WF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5Qs
//    GSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA
//
//   grant_type=refresh_token
//   &refresh_token=Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g
//
//    Figure 6: Token Request for a DPoP-bound Token using a Refresh Token
//
// The client MUST present a DPoP proof for the same key that was
// used to obtain the refresh token each time that refresh token is used to obtain a new access token.
// (the profile's wallet key of a client app).
//
// The Dynamic Client Registration Protocol
//
// DPoP introduces the following client registration metadata [RFC7591] parameter
// to indicate that the client always uses DPoP when requesting tokens from the authorization server:
// "dpop_bound_access_tokens" (default value is false).
// Boolean value specifying whether the client always uses DPoP for token requests.
// If true, the authorization server MUST reject token requests from this client that do not contain the DPoP header.
//
// Resource servers MUST be able to reliably identify whether an access token is DPoP-bound
// and ascertain sufficient information to verify the binding to the public key of the DPoP proof.
//
// The public key information is represented using the "jkt" confirmation method.
// To convey the hash of a public key in a JWT, this specification introduces the following
// JWT Confirmation Method [RFC7800] member for use under the "cnf" claim.
//
//   "jkt": JWK SHA-256 Thumbprint Confirmation Method.  The value of the
//      jkt member MUST be the base64url encoding (as defined in
//      [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638])
//      of the DPoP public key (in JWK format) to which the access token is bound.
//
// JWK Thumbprint Confirmation Method in Token Introspection
//
//   OAuth 2.0 Token Introspection [RFC7662] defines a method for a
//   protected resource to query an authorization server about the active
//   state of an access token as well as to determine metaInformation
//   about the token.
//
//   For a DPoP-bound access token, the hash of the public key to which
//   the token is bound is conveyed to the protected resource as
//   metaInformation in a token introspection response.
//
// If the "token_type" member is included in the introspection response,
//   it MUST contain the value "DPoP".
//
//   The example introspection request in Figure 9 and corresponding
//   response in Figure 10 illustrate an introspection exchange for the
//   example DPoP-bound access token that was issued in Figure 5.
//
//   POST /as/introspect.oauth2 HttpHeaders/1.1
//   Host: server.example.com
//   Content-Type: application/x-www-form-urlencoded
//   Authorization: Basic cnM6cnM6TWt1LTZnX2xDektJZHo0ZnNON2tZY3lhK1Rp
//   token=Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
//                  Figure 9: Example Introspection Request
//
//   HttpHeaders/1.1 200 OK
//   Content-Type: application/json
//   Cache-Control: no-store
//   {
//     "active": true,
//     "sub": "someone@example.com",
//     "iss": "https://server.example.com",
//     "nbf": 1562262611,
//     "exp": 1562266216,
//     "cnf":
//     {
//       "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
//     }
//   }
//     Figure 10: Example Introspection Response for a DPoP-Bound Access
//                                   Token
//
// Figure 12 shows an example request to a protected resource with a
//  DPoP-bound access token in the Authorization header
//  and the DPoP proof in the DPoP header.
//
// Figure 13 shows the decoded content of that DPoP proof.
//  The JSON of the JWT header and payload are shown but the signature part is omitted.
//  As usual, line breaks and extra whitespace are included for formatting and readability in both examples.
//
//   GET /protectedResource HttpHeaders/1.1
//   Host: resource.example.org
//   Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
//   DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
//    VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
//    nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
//    QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj
//    oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z
//    WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF
//    c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E
//    OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA
//                 Figure 12: DPoP Protected Resource Request
//
//   {
//     "typ":"dpop+jwt",
//     "alg":"ES256",
//     "jwk": {
//       "kty":"EC",
//       "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
//       "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
//       "crv":"P-256"
//     }
//   }
//   .
//   {
//     "jti":"e1j3V_bKic8-LAEB",
//     "htm":"GET",
//     "htu":"https://resource.example.org/protectedresource",
//     "iat":1562262618,
//     "ath":"fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
//   }
//       Figure 13: Decoded Content of the DPoP Proof JWT in Figure 12
//
// Upon receipt of a request to a protected resource within the
//  protection space requiring DPoP authentication, if the request does
//  not include valid credentials or does not contain an access token
//  sufficient for access, the server can respond with a challenge to the
//  client to provide DPoP authentication information.
// Such a challenge is made using the
//	401 (Unauthorized) response status code ([RFC9110], Section 15.5.2)
//  and the WWW-Authenticate header field ([RFC9110], Section 11.6.1).
// The server MAY include the "WWW-Authenticate" header in response to other conditions as well.
//
// For example, in response to a protected resource request without authentication:
//
//    HttpHeaders/1.1 401 Unauthorized
//    WWW-Authenticate: DPoP algs="ES256 PS256"
//
//    Figure 14: HttpHeaders 401 Response to a Protected Resource Request without
//                               Authentication
//
// And in response to a protected resource request that was rejected
//   because the confirmation of the DPoP binding in the access token failed:
//
//    HttpHeaders/1.1 401 Unauthorized
//    WWW-Authenticate: DPoP error="invalid_token",
//      error_description="Invalid DPoP key binding", algs="ES256"
//
//     Figure 15: HttpHeaders 401 Response to a Protected Resource Request with
//                              an Invalid Token
//
// Authorization Server-Provided Nonce
//
//   This section specifies a mechanism using opaque nonces provided by
//   the server that can be used to limit the lifetime of DPoP proofs.
//   Without employing such a mechanism, a malicious party controlling the
//   client (including potentially the end-user) can create DPoP proofs
//   for use arbitrarily far in the future.
//
