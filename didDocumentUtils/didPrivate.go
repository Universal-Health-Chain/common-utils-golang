package didDocumentUtils

type DidPrivateKey struct {
	Alg             string  `json:"alg,omitempty"` // for Crystals-Dilithium and Crystals-Kyber
	Crv             *string `json:"crv,omitempty"` // for non-PQC Elliptic Curve keys
	Kty             string  `json:"kty,omitempty"`
	PrivateKeyBytes []byte
	Kid             string  `json:"kid,omitempty" bson:"kid,omitempty"` // the JWK Thumbprint id the keyID (kid) as per RFC
	D               *string `json:"d,omitempty" bson:"d,omitempty"`     // for Crystals-Dilithium, Crystals-Kyber and Elliptic Curve keys
	Ds              *string `json:"ds,omitempty" bson:"ds,omitempty"`   // for Dilithium: shake256 of the private key (not the JWK) encoded in raw base64url [RFC4648]
}
