package jwkUtils

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
	"github.com/lestrrat-go/jwx/jwk"
)

// NOTE: Aries has jwksupport.PubKeyBytesToJWK and jwksupportPublicKeyFromJWK

const JWKeySignType = "sig"
const JWKeyEncType = "enc"

var JWAlgorithmToJWKCrvAndHashType = map[string]map[string]string{
	"ES256": {jwk.ECDSACrvKey: "P-256", "hash": "SHA256", jwk.KeyTypeKey: "EC", jwk.KeyUsageKey: JWKeySignType},
	"ES384": {jwk.ECDSACrvKey: "P-384", "hash": "SHA384", jwk.KeyTypeKey: "EC", jwk.KeyUsageKey: JWKeySignType},
	"ES512": {jwk.ECDSACrvKey: "P-521", "hash": "SHA512", jwk.KeyTypeKey: "EC", jwk.KeyUsageKey: JWKeySignType}, // P-521 is not a typo (not P-512)
}

// BaseThumbprintJWK is to calculate the Thumbprint of a public key.
type BaseThumbprintJWK struct {
	Alg  string  `json:"alg,omitempty"` // for Crystals-Dilithium and Crystals-Kyber
	Crv  *string `json:"crv,omitempty"` // for non-PQC Elliptic Curve keys
	Kty  string  `json:"kty,omitempty"`
	Pset *string `json:"pset,omitempty"` // for Crystals-Dilithium
	X    string  `json:"x,omitempty"`    // for public Dilithium, Kyber and Elliptic Curve keys
	Y    *string `json:"y,omitempty"`    // for public Elliptic Curve keys
}

// Extends BaseThumbprintJWK with "kid" and hash of "x" such as "h" (hpk) or "xs".
type PublicJWK struct {
	Alg  string  `json:"alg,omitempty" bson:"alg,omitempty"`   // for Crystals-Dilithium and Crystals-Kyber
	Crv  *string `json:"crv,omitempty" bson:"crv,omitempty"`   // for non-PQC Elliptic Curve keys
	H    *string `json:"h,omitempty" bson:"h,omitempty"`       // hashed public key (32 bytes). Kyber uses SHA3-256 as H by default
	Kid  string  `json:"kid,omitempty" bson:"kid,omitempty"`   // the JWK Thumbprint id the keyID (kid) as per RFC
	Kty  string  `json:"kty,omitempty" bson:"kty,omitempty"`   // "EC", "PQK"
	Pset *string `json:"pset,omitempty" bson:"pset,omitempty"` // for Crystals-Dilithium
	X    string  `json:"x,omitempty" bson:"x,omitempty"`       // for public Dilithium, Kyber and Elliptic Curve keys
	Xs   *string `json:"xs,omitempty" bson:"xs,omitempty"`     // for Dilithium: shake256 of the public key (not the JWK) encoded in raw base64url [RFC4648]
	Y    *string `json:"y,omitempty" bson:"y,omitempty"`       // for public Elliptic Curve keys
	Use  *string `json:"use,omitempty" bson:"use,omitempty"`   // 'enc' or 'sig'
}

// All possible properties including the private key "d" (RSA not supported for now)
type JWK struct {
	Alg  string  `json:"alg,omitempty" bson:"alg,omitempty"`   // for Crystals-Dilithium and Crystals-Kyber
	Crv  *string `json:"crv,omitempty" bson:"crv,omitempty"`   // for non-PQC Elliptic Curve keys
	H    *string `json:"h,omitempty" bson:"h,omitempty"`       // Crystals-Kyber SHA3-256 of public key bytes: H(pk)
	Kid  string  `json:"kid,omitempty" bson:"kid,omitempty"`   // the JWK Thumbprint id the keyID (kid) as per RFC
	Kty  string  `json:"kty,omitempty" bson:"kty,omitempty"`   // "EC", "PQK"
	Pset *string `json:"pset,omitempty" bson:"pset,omitempty"` // for Crystals-Dilithium
	X    string  `json:"x,omitempty" bson:"x,omitempty"`       // for public Dilithium, Kyber and Elliptic Curve keys
	Xs   *string `json:"xs,omitempty" bson:"xs,omitempty"`     // for Dilithium: shake256 of the public key (not the JWK) encoded in raw base64url [RFC4648]
	Y    *string `json:"y,omitempty" bson:"y,omitempty"`       // for public Elliptic Curve keys
	Use  *string `json:"use,omitempty" bson:"use,omitempty"`   // 'enc' or 'sig'
	D    *string `json:"d,omitempty" bson:"d,omitempty"`       // for Crystals-Dilithium, Crystals-Kyber and Elliptic Curve keys
	Ds   *string `json:"ds,omitempty" bson:"ds,omitempty"`     // for Dilithium: shake256 of the private key (not the JWK) encoded in raw base64url [RFC4648]
	// N *string `json:"n,omitempty" bson:"n,omitempty"`       // for RSA keys
	// E *string `json:"e,omitempty" bson:"e,omitempty"`       // for RSA keys
	K *string `json:"k,omitempty" bson:"k,omitempty"` // for Symmetric Keys
	// T *string `json:"t,omitempty" bson:"t,omitempty"`  	// use X for public Kyber keys too
	// TODO: add X509
}

func SetPrivateKeyBytes(publicJWK *JWK, privateKeyBytesASN1 *[]byte) (privateJWK *JWK) {
	if privateKeyBytesASN1 == nil || publicJWK == nil {
		return nil
	}

	privateKeyBase64Url := base64.RawURLEncoding.EncodeToString(*privateKeyBytesASN1)
	result := SetPrivateKeyBase64Url(publicJWK, &privateKeyBase64Url)
	return &result
}

func SetPrivateKeyBase64Url(jwk *JWK, privateKeyBase64Url *string) JWK {
	privateJWK := *jwk // copy the data, not the pointer
	privateJWK.D = privateKeyBase64Url
	return privateJWK
}

var ErrUnsupportedKey = errors.New("unsupported key")

// GetPublicJWK returns only the public data of a JWK.
func GetPublicJWK(jwk *JWK) (publicJWK *JWK) {
	publicJWK = &JWK{} // initialize the object
	publicJWK.Alg = jwk.Alg
	publicJWK.Crv = jwk.Crv
	publicJWK.Kid = jwk.Kid
	publicJWK.Kty = jwk.Kty
	publicJWK.H = jwk.H
	publicJWK.Pset = jwk.Pset
	publicJWK.X = jwk.X
	publicJWK.Xs = jwk.Xs
	publicJWK.Use = jwk.Use
	return publicJWK
}

// ExportPublicJWK copies the private key and removes the private data.
func ExportPublicJWK(jwk *JWK) (publicJWK JWK) {
	publicJWK = *jwk
	publicJWK.D = nil
	publicJWK.Ds = nil
	return publicJWK
}

// CalculateThumbprintJWK returns the SHA-256 hash Base64Url encoded or empty string ("") if error.
func CalculateThumbprintJWK(jwk *JWK) string {
	// TODO: check if the Dilithium or ECDSA required fields are present
	jwkBaseThumbprint := BaseThumbprintJWK{
		Alg:  jwk.Alg,
		Crv:  jwk.Crv,
		Kty:  jwk.Kty,
		Pset: jwk.Pset,
		X:    jwk.X,
		Y:    jwk.Y,
	}
	jwkBytes, err := json.Marshal(&jwkBaseThumbprint)
	if err != nil {
		return ""
	} else {
		return contentUtils.CalculateSHA256(&jwkBytes)
	}
}

/* JWK Thumbprint is The digest value for a JWK.
The thumbprint of a JSON Web Key (JWK) is computed as follows:
   1.  Construct a JSON object [RFC7159] containing only the required
       members of a JWK representing the key and with no whitespace or
       line breaks before or after any syntactic elements and with the
       required members ordered lexicographically by the Unicode
       [UNICODE] code points of the member names.  (This JSON object is
       itself a legal JWK representation of the key.)

   2.  Hash the octets of the UTF-8 representation of this JSON object
       with a cryptographic hash function H.  For example, SHA-256 [SHS]
       might be used as H.  See Section 3.4 for a discussion on the
       choice of hash function.

*/

/* CRYSTALS DILITHIUM Key Representations
https://www.ietf.org/id/draft-prorock-cose-post-quantum-signatures-00.html#name-crydi-key-representations
The parameter “kty” MUST be “PQK”.
The parameter “alg” MUST be specified, and its value MUST be one of the values specified in table TBD (“CRYDI3" for Crystals Dilithium 3).
The parameter “x” MUST be present and contain the public key encoded using the base64url [RFC4648] encoding.
The parameter “xs” MAY be present and contain the shake256 of the public key encoded using the base64url [RFC4648] encoding.
The parameter “d” MUST be present for private keys and contain the private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.
The parameter “ds” MAY be present for private keys and contain the shake256 of the private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.

CRYSTALS KYBER Key Representations
https://www.ietf.org/id/draft-uni-qsckeys-00.html#name-kyber
t is the public key
H(pk): hashed public key (32 bytes). Kyber uses SHA3-256 as H by default
d secret key (partial encoded, it does not include the public key)
4.4. Secret Key Partial Encoding The partially populated parameter set uses of the fact that some parameters can be regenerated. In this case, only the initial seed ‘d’ (nonce) is stored and used to regenerate the full key.
kty is “PQK” (Post Quantum Key Pair)
alg is “kyber768-r3"
*/
