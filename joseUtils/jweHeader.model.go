package joseUtils

import "github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"

// 	HeaderRequestJWE contains the JOSE header of an encrypted DIDComm-JAR message
// 	following both JOSE ([RFC7516](https://www.rfc-editor.org/rfc/rfc7516.html#section-4)) and DIDComm specifications:
//	- the **"typ"** (*required*) field value is *"jwt"*.
//	- the **"cty"** (*required*) field value is set to *"didcomm-signed+json"* when the plaintext is a nested signed DIDComm message.
//	- the **"alg"** (*required*) field value identifies the **algorithm used to encrypt (encapsulate) the value of the CEK**.
//	- the **"enc"** (*required*) field value identifies the **algorithm used to encrypt the data using the CEK** (e.g.: *"A256GCM"* for AES data encryption).
//	- the **"skid"** (*required*) field value is the sender's public encryption keyID, and it is required in UHC for authenticated encryption.
//	- the **"kid"** (*conditional*) field value is the recipient's keyID (*kid*) to which the CEK was encrypted, calculated by the JWK Thumbprint of the recipient's public encryption key.
//	- the **"jku"** (*conditional*) field value is the recipient's JWK Set URL, to get the public key to which the JWE was encrypted by using the *"kid"* field as identifier.
//	- the **"jwk"** (*conditional*) field value is the recipient's public JWK to which the CEK was encrypted (rather than using both "kid" and "jku").
//	The main JWE "kid" header claim field is the recipient's public encryption keyID.
//
//	Note: *"x5u"* is not used in JAR because the certificate data can be included in the JWK (use the *"jwk"* or *"jku"* fields instead).
// todo:
type HeaderRequestJWE struct {
	// Algorithm ("alg", required) is the cryptographic algorithm used to encrypt (encapsulate) the value of the CEK (Crystals-Kyber).
	Algorithm string `json:"alg,omitempty" bson:"alg,omitempty"`

	// ContentType ("cty", required in UHC) is used to declare the media type of secured content (the "plaintext" encrypted data).
	ContentType string `json:"cty,omitempty" bson:"cty,omitempty"`

	// Encryption ("enc", required) identifies the cryptographic algorithm used to encrypt the data using the CEK (e.g.: *"A256GCM"* for AES data encryption).
	Encryption string `json:"enc,omitempty" bson:"enc,omitempty"` // string

	// JSONWebKey ("jwk", conditional) is the public key to which the JWE was encrypted.
	JSONWebKey *jwkUtils.JWK `json:"jwk,omitempty" bson:"jwk,omitempty"` // JSON

	// JWKSetURL ("jku", conditional) is a URI that refers to a resource for a set of JSON-encoded public keys or the recipient, one of which
	// corresponds to the  public key to which the JWE was encrypted (determined by the recipient's encryption KeyID).
	JWKSetURL *string `json:"jku,omitempty" bson:"jku,omitempty"` // string

	// KeyID ("kid", conditional) indicates the recipient's public key to which the JWE was encrypted.
	KeyID *string `json:"kid,omitempty" bson:"kid,omitempty"`

	// SenderKeyID ("skid", required in UHC) is a hint which references the sender's public encryption key for authenticated encryption.
	SenderKeyID string `json:"skid,omitempty" bson:"skid,omitempty"` // string

	// Type ("typ", required) is used to declare the media type of the complete JWS. It is "jwt" as per the OpenID specification.
	Type string `json:"typ,omitempty" bson:"typ,omitempty"`
}
