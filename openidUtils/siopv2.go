package openidUtils

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
