package joseUtils

import "github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"

// joseUtils.HeaderRequestJWS contains the JOSE header of a signed DIDComm-JAR message.
//- the **"alg"** field value is the identifier of the digital signature algorithm. MUST NOT be "none".
//- the **"cty"** field value is set to *"didcomm-signed+json"*.
//- the "jwks" (optional) field value contains an array of public keys that corresponds in UHC to the sender's public signature JWK (first) and public encryption JWK (second, it can be already in the JWE "jwk" header).
//- the **"kid"** field value is the keyID (*kid*) calculated by the JWK Thumbprint of the public key used by the issuer.
//- the **"to"** field value is the DID Service Endpoint. It should be the same as the payload's "aud" field in case of the Authorization flow or the "htu" field when using a DPoP token bound to an access token.
//- the **"typ"** field value is *"jwt"*.
//- the "zip" (optional) field value can be "DEF" (deflated, compressed)
type HeaderRequestJWS struct {
	// Algorithm ("alg") is the cryptographic algorithm used to secure the JWS. MUST NOT be "none".
	Algorithm string `json:"alg,omitempty" bson:"alg,omitempty"`

	// ContentType ("cty") is used to declare the media type of secured content (the payload). It is set to
	ContentType string `json:"cty,omitempty" bson:"cty,omitempty"`

	// JSONWebKeySet ("jwks", optional) contains an array of public keys that corresponds in UHC to the sender's public signature JWK (first) and public encryption JWK (second, it can be already in the JWE "jwk" header).
	JSONWebKeySet *jwkUtils.JWKeySet `json:"jwks,omitempty" bson:"jwks,omitempty"` // JSON

	// KeyID ("kid") indicates which key was used to secure the JWS. It can be already defined in the payload's "client_id" (DID#KID URI).
	KeyID string `json:"kid,omitempty" bson:"kid,omitempty"`

	// To ("to") is the DID Service Endpoint.
	// It should be the same as the payload's "aud" field in case of the Authorization flow
	// or the "htu" field when using a DPoP token bound to an access token.
	To string `json:"to,omitempty" bson:"to,omitempty"`

	// Type ("typ") is used to declare the media type of the complete JWS. It is "jwt" as per the OpenID specification.
	Type string `json:"typ,omitempty" bson:"typ,omitempty"`

	// specifies if the payload bytes are compressed or not
	ZipCompression *string `json:"zip,omitempty" bson:"zip,omitempty"` // CompressionAlgorithm
}
