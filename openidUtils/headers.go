package openidUtils

import (
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
)

// JARHeader only contains data that can be sent by bluetooth:
// - decoded "Bearer" Access Token (to check scopes).
// - decoded "DPoP" token (to avoid replay attacks), which contains in the payload "nonce", "htm" (HTTP Method), "htu" (target URL without query and fragment parts).
type JARHeader struct {
	Bearer joseUtils.DataJWT `json:"bearer,omitempty" bson:"bearer,omitempty"` // decoded Bearer (signature is removed before storage)
	DPoP   joseUtils.DataJWT `json:"dpop,omitempty" bson:"dpop,omitempty"`     // decoded DPoP (signature is removed before storage)
}

// see https://www.iana.org/assignments/jose/jose.xhtml
type OpenidHeaders struct {
	// HeaderAPU *string `json:"apu,omitempty" bson:"zzz,omitempty"` // *byteBuffer
	// HeaderAPV *string `json:"apv,omitempty" bson:"zzz,omitempty"` // *byteBuffer
	// HeaderEPK *string `json:"epk,omitempty" bson:"zzz,omitempty"` // *JSONWebKey

	// HeaderP2C *string `json:"p2c,omitempty" bson:"zzz,omitempty"` // *byteBuffer (int)
	// HeaderP2S *string `json:"p2s,omitempty" bson:"zzz,omitempty"` // *byteBuffer ([]byte)

	HeaderCompression *string `json:"zip,omitempty" bson:"zip,omitempty"`     // CompressionAlgorithm
	HeaderNonce       *string `json:"nonce,omitempty" bson:"nonce,omitempty"` // string
	HeaderB64         *string `json:"b64"  bson:"b64,omitempty"`              // bool
	HeaderIV          *string `json:"iv" bson:"iv,omitempty"`                 // *byteBuffer
	HeaderTag         *string `json:"tag,omitempty" bson:"tag,omitempty"`     // *byteBuffer

	// HeaderJSONWebKeySet in UHC is:
	// For JWS: array of public keys that corresponds to the sender's signature and encryption keys.
	// For JWE: do not use here
	HeaderJSONWebKeySet *jwkUtils.JWKeySet `json:"jwks,omitempty" bson:"jwks,omitempty"` // JSON

	// from Hyperledger Aries: https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/doc/jose

	// IANA registered JOSE headers (https://tools.ietf.org/html/rfc7515#section-4.1)

	// HeaderAlgorithm identifies:
	// For JWS: the cryptographic algorithm used to secure the JWS.
	// For JWE: the cryptographic algorithm used to encrypt or determine the value of the CEK.
	HeaderAlgorithm *string `json:"alg,omitempty" bson:"alg,omitempty"` // string

	// HeaderEncryption identifies the JWE content encryption algorithm.
	HeaderEncryption *string `json:"enc,omitempty" bson:"enc,omitempty"` // string

	// HeaderJWKSetURL is a URI that refers to a resource for a set of JSON-encoded public keys, one of which:
	// For JWS: corresponds to the key used to digitally sign the JWS.
	// For JWE: corresponds to the public key to which the JWE was encrypted.
	HeaderJWKSetURL *string `json:"jku,omitempty" bson:"jku,omitempty"` // string

	// HeaderJSONWebKey is:
	// For JWS: the public key that corresponds to the key used to digitally sign the JWS.
	// For JWE: the public key to which the JWE was encrypted.
	HeaderJSONWebKey *jwkUtils.JWK `json:"jwk,omitempty" bson:"jwk,omitempty"` // JSON

	// HeaderKeyID is a hint:
	// For JWS: indicating which key was used to secure the JWS (not used when the payload's "client_id" is a DID#KID URI)
	// For JWE: which references the public key to which the JWE was encrypted.
	HeaderKeyID *string `json:"kid,omitempty" bson:"kid,omitempty"` // string

	// HeaderSenderKeyID is a hint:
	// For JWS: not used.
	// For JWE: which references the (sender) public key used in the JWE key derivation/wrapping to encrypt the CEK.
	HeaderSenderKeyID *string `json:"skid,omitempty" bson:"skid,omitempty"` // string

	// HeaderX509URL is a URI that refers to a resource for the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509URL *string `json:"x5u" bson:"x5u,omitempty"`

	// HeaderX509CertificateChain contains the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateChain *string `json:"x5c" bson:"x5c,omitempty"`

	// HeaderX509CertificateDigest (X.509 certificate SHA-1 thumbprint) is a base64url-encoded
	// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha1 *string `json:"x5t" bson:"x5t,omitempty"`

	// HeaderX509CertificateDigestSha256 (X.509 certificate SHA-256 thumbprint) is a base64url-encoded SHA-256
	// thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha256 *string `json:"x5t#S256,omitempty" bson:"x5t#S256,omitempty"` // string

	// HeaderType is:
	// For JWS: used by JWS applications to declare the media type of this complete JWS.
	// For JWE: used by JWE applications to declare the media type of this complete JWE.
	HeaderType *string `json:"typ,omitempty" bson:"typ,omitempty"` // string

	// HeaderContentType is used by JWS applications to declare the media type of:
	// For JWS: the secured content (the payload).
	// For JWE: the secured content (the plaintext).
	HeaderContentType *string `json:"cty,omitempty" bson:"cty,omitempty"` // string

	// HeaderCritical indicates that extensions to:
	// For JWS: this JWS header specification and/or JWA are being used that MUST be understood and processed.
	// For JWE: this JWE header specification and/or JWA are being used that MUST be understood and processed.
	HeaderCritical *[]string `json:"crit,omitempty" bson:"crit,omitempty"` // array

	// HeaderEPK is used by JWE applications to wrap/unwrap the CEK for a recipient.
	HeaderEPK *string `json:"epk,omitempty" bson:"epk,omitempty"` // JSON
}

// GetJSON method returns a *map[string]interface{} with the JSON data or nil if error.
func (headers *OpenidHeaders) GetJSON() (*map[string]interface{}, error) {
	headersBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}

	var headersJSON map[string]interface{}
	err = json.Unmarshal(headersBytes, &headersJSON)
	if err != nil {
		return nil, err
	}

	return &headersJSON, nil
}

// GetBytes method returns the marshall to bytes or nil if error.
func (headers *OpenidHeaders) GetBytes() (*[]byte, error) {
	headersBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}

	return &headersBytes, nil
}

// SetJSON method puts the given JSON data(*map[string]interface{}) to the OpenidHeaders struct
func (headers *OpenidHeaders) SetJSON(headersJSON *map[string]interface{}) error {
	headersBytes, err := json.Marshal(headersJSON)
	if err != nil {
		return err
	}

	err = json.Unmarshal(headersBytes, headers) // setting the data (bytes) in the OpenidHeaders struct
	if err != nil {
		return err
	}

	return nil
}
