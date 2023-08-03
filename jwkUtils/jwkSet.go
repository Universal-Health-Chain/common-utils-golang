package jwkUtils

import "strings"

// JSON Web Key (JWK) is a JSON object that represents a cryptographic key.
// JWK specification to represent the cryptographic keys used for signing and encryption defines
// two high level data structures: JSON Web Key (JWK) and JSON Web Key Set (JWKS).
// The JWKS is a set of keys containing the public keys that should be used to verify any JWT issued
// and/or any JWE encrypted by the server.
// The endpoint <serverBaseUrl>/.well-known/jwks.json contains the JSON Web Key Set (JWKS) with
// the public keys used to sign and encrypt all data issued for the tenant.
// HttpHeaders Response:
// Code: 200.
// Content-Type: application/json.
// Body: {object} The server's JWK Set.

// TODO: get set of public signature verification keys.
// TODO: get set of public encryption keys.

// JWKeySet is a JWK Set data structure that represents a set of public JWKs
// for signature verification and / or data encryption.
// See: https://datatracker.ietf.org/doc/html/rfc7517
type JWKeySet struct {
	Keys []JWK `json:"keys"`
}

// it returns an array of keys containing the given string in the alg property or nil.
// E.g. looking for "kyber" can return "kyber-768-r3" amd "kyber-1024-r3" keys if both exist.
func (jwks *JWKeySet) SearchJWKeyByAlg(searchStr string) *[]JWK {
	if jwks == nil || jwks.Keys == nil || len(jwks.Keys) < 1 {
		return nil
	}

	var publicKeys []JWK

	for _, jwk := range jwks.Keys {
		if strings.Contains(jwk.Alg, searchStr) {
			publicKeys = append(publicKeys, jwk)
		}
	}
	return &publicKeys
}

// CreateJWKeySet returns a JWK Set data structure that represents a set of public JWKs
// for signature verification and / or data encryption.
// See: https://datatracker.ietf.org/doc/html/rfc7517
func CreateJWKeySet(jwKeys *[]JWK) *JWKeySet {
	if jwKeys == nil || len(*jwKeys) < 1 {
		return nil
	}

	jwkeySet := &JWKeySet{
		Keys: []JWK{}, // empty
	}

	for _, jwk := range *jwKeys {
		publicJWK := GetPublicJWK(&jwk)
		jwkeySet.Keys = append(jwkeySet.Keys, *publicJWK)
	}

	// fmt.Printf(`number of keys in the JWKS = %v\n`, len(jwkeySet.Keys))
	return jwkeySet
}
