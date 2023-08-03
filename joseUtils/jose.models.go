package joseUtils

// This has the 3 parts encoded in Base64url format.
type PartsJWT struct {
	Header    string  // Is the protected header (because signed claims)
	Payload   string  // payload claims to be signed also
	Signature *string // it does not exist when preparing the data for signature
}

// PayloadClaims represents public claim values (as specified in RFC 7519).
type PayloadClaims struct {
	Issuer    string        `json:"iss,omitempty"`
	Subject   string        `json:"sub,omitempty"`
	Audience  AudienceSlice `json:"aud,omitempty"`
	Expiry    *NumericDate  `json:"exp,omitempty"`
	NotBefore *NumericDate  `json:"nbf,omitempty"`
	IssuedAt  *NumericDate  `json:"iat,omitempty"`
	ID        string        `json:"jti,omitempty"`
}

// NumericDate represents date and time as the number of seconds since the
// epoch, ignoring leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
// See RFC7519 Section 2: https://tools.ietf.org/html/rfc7519#section-2
type NumericDate int64