package joseUtils

var ErrMsgInvalidRequest = "request is empty or invalid"
var ErrMsgInvalidBearerAccessToken = "invalid bearer access token"
var ErrMsgInvalidAccessTokenJWT = "invalid access token format"
var ErrMsgMissingDPoP = "missing DPoP token"
var ErrMsgInvalidDPoPToken = "invalid DPoP token format"
var ErrMsgInvalidResponseType = "invalid response type"
var ErrMsgMissingDecryptionKey = "missing decryption key"
var ErrMsgMissingSignVerificationKey = "missing signature verification key"

// ErrMsgUnmarshalAudience indicates that aud claim could not be unmarshalled.
var ErrMsgUnmarshalAudience = "expected string or array value to unmarshal to AudienceSlice"

// ErrMsgUnmarshalNumericDate indicates that JWT NumericDate could not be unmarshalled.
var ErrMsgUnmarshalNumericDate = "expected number value to unmarshal NumericDate"

// ErrInvalidClaims indicates that given claims have invalid type.
var ErrMsgInvalidClaims = "expected claims to be value convertible into JSON object"

// ErrInvalidIssuer indicates invalid iss claim.
var ErrMsgInvalidIssuer = "validation failed, invalid issuer claim (iss)"

// ErrMsgInvalidSubject indicates invalid sub claim.
var ErrMsgInvalidSubject = "validation failed, invalid subject claim (sub)"

// ErrMsgInvalidAudience indicated invalid aud claim.
var ErrMsgInvalidAudience = "validation failed, invalid audience claim (aud)"

// ErrMsgInvalidID indicates invalid jti claim.
var ErrMsgInvalidID = "validation failed, invalid ID claim (jti)"

// ErrMsgNotValidYet indicates that token is used before time indicated in nbf claim.
var ErrMsgNotValidYet = "validation failed, token not valid yet (nbf)"

// ErrMsgExpired indicates that token is used after expiry time indicated in exp claim.
var ErrMsgExpired = "validation failed, token is expired (exp)"

// ErrMsgIssuedInTheFuture indicates that the iat field is in the future.
var ErrMsgIssuedInTheFuture = "validation field, token issued in the future (iat)"

// ErrMsgInvalidContentType indicates that token requires JWT cty header.
var ErrMsgInvalidContentType = "expected content type to be JWT (cty header)"
