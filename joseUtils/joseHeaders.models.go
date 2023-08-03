package joseUtils

// from go-jose header constants
const (
	// HeaderType        = "typ" // string
	// HeaderContentType = "cty" // string

	// These are set by go-jose and shouldn't need to be set by consumers of the library.
	// HeaderAlgorithm   = "alg"  // string
	// HeaderEncryption  = "enc"  // ContentEncryption
	HeaderCompression = "zip" // CompressionAlgorithm
	// HeaderCritical    = "crit" // []string

	HeaderAPU = "apu" // *byteBuffer
	HeaderAPV = "apv" // *byteBuffer
	// HeaderEPK = "epk" // *JSONWebKey
	HeaderIV  = "iv"  // *byteBuffer
	HeaderTag = "tag" // *byteBuffer
	HeaderX5c = "x5c" // []*x509.Certificate

	HeaderJWK = "jwk" // *JSONWebKey
	// HeaderKeyID = "kid"   // string
	HeaderNonce = "nonce" // string
	HeaderB64   = "b64"   // bool

	HeaderP2C = "p2c" // *byteBuffer (int)
	HeaderP2S = "p2s" // *byteBuffer ([]byte)
)

// from Hyperledger Aries
// IANA registered JOSE headers (https://tools.ietf.org/html/rfc7515#section-4.1)
const (
	// HeaderAlgorithm identifies:
	// For JWS: the cryptographic algorithm used to secure the JWS.
	// For JWE: the cryptographic algorithm used to encrypt or determine the value of the CEK.
	HeaderAlgorithm = "alg" // string

	// HeaderEncryption identifies the JWE content encryption algorithm.
	HeaderEncryption = "enc" // string

	// HeaderJWKSetURL is a URI that refers to a resource for a set of JSON-encoded public keys, one of which:
	// For JWS: corresponds to the key used to digitally sign the JWS.
	// For JWE: corresponds to the public key to which the JWE was encrypted.
	HeaderJWKSetURL = "jku" // string

	// HeaderJSONWebKey is:
	// For JWS: the public key that corresponds to the key used to digitally sign the JWS.
	// For JWE: the public key to which the JWE was encrypted.
	HeaderJSONWebKey = "jwk" // JSON

	// HeaderJSONWebKeySet in UHC is:
	// For JWS: array of public keys that corresponds to the sender's signature and encryption keys.
	// For JWE: do not use here
	HeaderJSONWebKeySet = "jwks" // JSON

	// HeaderKeyID is a hint:
	// For JWS: indicating which key was used to secure the JWS.
	// For JWE: which references the public key to which the JWE was encrypted.
	HeaderKeyID = "kid" // string

	// HeaderSenderKeyID is a hint:
	// For JWS: not used.
	// For JWE: which references the (sender) public key used in the JWE key derivation/wrapping to encrypt the CEK.
	HeaderSenderKeyID = "skid" // string

	// HeaderX509URL is a URI that refers to a resource for the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509URL = "x5u"

	// HeaderX509CertificateChain contains the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateChain = "x5c"

	// HeaderX509CertificateDigest (X.509 certificate SHA-1 thumbprint) is a base64url-encoded
	// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha1 = "x5t"

	// HeaderX509CertificateDigestSha256 (X.509 certificate SHA-256 thumbprint) is a base64url-encoded SHA-256
	// thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha256 = "x5t#S256" // string

	// HeaderType is:
	// For JWS: used by JWS applications to declare the media type of this complete JWS.
	// For JWE: used by JWE applications to declare the media type of this complete JWE.
	HeaderType = "typ" // string

	// HeaderContentType is used by JWS applications to declare the media type of:
	// For JWS: the secured content (the payload).
	// For JWE: the secured content (the plaintext).
	HeaderContentType = "cty" // string

	// HeaderCritical indicates that extensions to:
	// For JWS: this JWS header specification and/or JWA are being used that MUST be understood and processed.
	// For JWE: this JWE header specification and/or JWA are being used that MUST be understood and processed.
	HeaderCritical = "crit" // array

	// HeaderEPK is used by JWE applications to wrap/unwrap the CEK for a recipient.
	HeaderEPK = "epk" // JSON
)

// Header defined in https://tools.ietf.org/html/rfc7797
const (
	// HeaderB64 determines whether the payload is represented in the JWS and the JWS Signing
	// Input as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload value itself with no encoding performed.
	HeaderB64Payload = "b64" // bool
	// A256GCMALG is the default content encryption algorithm value as per
	// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
	A256GCMALG = "A256GCM"
	// XC20PALG represents XChacha20Poly1305 content encryption algorithm value.
	XC20PALG = "XC20P"
	// A128CBCHS256ALG represents AES_128_CBC_HMAC_SHA_256 encryption algorithm value.
	A128CBCHS256ALG = "A128CBC-HS256"
	// A192CBCHS384ALG represents AES_192_CBC_HMAC_SHA_384 encryption algorithm value.
	A192CBCHS384ALG = "A192CBC-HS384"
	// A256CBCHS384ALG represents AES_256_CBC_HMAC_SHA_384 encryption algorithm value (not defined in JWA spec above).
	A256CBCHS384ALG = "A256CBC-HS384"
	// A256CBCHS512ALG represents AES_256_CBC_HMAC_SHA_512 encryption algorithm value.
	A256CBCHS512ALG = "A256CBC-HS512"
)

// Headers represents JOSE headers.
type Headers map[string]interface{}

