package joseUtils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
)

// JWEncryptionGo represents a JWE in Go (defined in https://tools.ietf.org/html/rfc7516).
// OpenID Connect specification mandates to use JWS compact serialization and JWE compact serialization whenever necessary
// Any JWT must follow compact serialization. A JWS or JWE token following JSON serialization cannot be called as a JWT.
// In contrast to the JWS compact serialization, the JWS JSON serialization can produce multiple signatures
// over the same JWS payload along with multiple JOSE headers.
// JWE COMPACT serialization is built with five key components, each separated by a period (.):
//  - 1) JOSE header
//  - 2) JWE Encrypted Key (CEK) // recipients list does not exist in compact serialization
//  - 3) JWE Initialization Vector (IV)
//  - 4) JWE Additional Authentication Data (AAD),
//  - 5) JWE Ciphertext and JWE Authentication Tag// The header has the algorithm to encrypt the CEK to the recipients "alg" (Kyber) and the CEK symmetric encryption algorithm "enc" (A256GCM) algorithm.
type JWEncryptionGo struct {
	ProtectedHeaders   map[string]interface{}
	OrigProtectedHders string                 `json:"protected,omitempty"` // the original protected headers Base64Url encoded
	UnprotectedHeaders map[string]interface{} `json:"unprotected,omitempty"`
	Recipients         []*RecipientJWE        `json:"recipients,omitempty"`
	AAD                string                 `json:"aad,omitempty"`
	IV                 string                 `json:"iv,omitempty"`
	Ciphertext         string                 `json:"ciphertext,omitempty"`
	Tag                string                 `json:"tag,omitempty"`
}

// DecryptedOpenidJWE represents a RAW JSON decrypted JWE.
//  - ProtectedHeaders
//	- UnprotectedHeaders
//	- Recipients
//	- NestedJWT: headers, payload and signature (if any)
type DecryptedOpenidJWE struct {
	ProtectedHeaders   map[string]interface{}
	UnprotectedHeaders map[string]interface{}
	Recipients         []*RecipientJWE
	NestedJWT          DataJWT
}

// JWEncryptionRawJSON represents a RAW JSON JWE that is used for serialization/deserialization (JWEncryptionGo)
// OpenID Connect specification mandates to use JWS compact serialization and JWE compact serialization whenever necessary
// Any JWT must follow compact serialization. A JWS or JWE token following JSON serialization cannot be called as a JWT.
// In contrast to the JWS compact serialization, the JWS JSON serialization can produce multiple signatures
// over the same JWS payload along with multiple JOSE headers.
// JWE compact serialization is built with five key components, each separated by a period (.):
//  - 1) JOSE header
//  - 2) JWE Encrypted Key (CEK)
//  - 3) JWE Initialization Vector (IV)
//  - 4) JWE Additional Authentication Data (AAD),
//  - 5) JWE Ciphertext and JWE Authentication Tag// The header has the algorithm to encrypt the CEK to the recipients "alg" (Kyber) and the CEK symmetric encryption algorithm "enc" (A256GCM) algorithm.
type JWEncryptionRawJSON struct {
	B64ProtectedHeaders      string          `json:"protected,omitempty"`
	UnprotectedHeaders       json.RawMessage `json:"unprotected,omitempty"`
	Recipients               json.RawMessage `json:"recipients,omitempty"`
	B64SingleRecipientEncKey string          `json:"encrypted_key,omitempty"`
	SingleRecipientHeader    json.RawMessage `json:"header,omitempty"`
	B64AAD                   string          `json:"aad,omitempty"`
	B64IV                    string          `json:"iv,omitempty"`
	B64Ciphertext            string          `json:"ciphertext,omitempty"`
	B64Tag                   string          `json:"tag,omitempty"`
}

// RecipientJWE is a recipient of a JWE including the shared encryption key.
type RecipientJWE struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EncryptedKey string            `json:"encrypted_key,omitempty"`
}

// RecipientHeaders are the recipient headers.
type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	APV string          `json:"apv,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
}

const (
	compactJWERequiredNumOfParts      = 5
	errCompactSerializationCommonText = "unable to compact serialize: "
)

var (
	errWrongNumberOfCompactJWEParts = errors.New("invalid compact JWE: it must have five parts")
	errEmptyCiphertext              = errors.New("ciphertext cannot be empty")
	errProtectedHeaderMissing       = errors.New(errCompactSerializationCommonText +
		"no protected header found")
)

var errNotOnlyOneRecipient = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization only supports JWE with exactly one single recipient")

var errUnprotectedHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support a shared unprotected header")

var errAADHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support AAD")

var errPerRecipientHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support a per-recipient unprotected header")

// Used to pass the json.Marshal functions to the methods
type JsonMarshalFunc func(interface{}) ([]byte, error)

// SerializeMultiRecipientBytes serializes the bytes of a JWE, as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
// The full serialization syntax is used for multi-recipient JWE.
func (jweGo *JWEncryptionGo) SerializeMultiRecipientBytes(marshal JsonMarshalFunc) ([]byte, error) {
	b64ProtectedHeaders, unprotectedHeaders, err := jweGo.PrepareHeadersJSON(marshal)
	if err != nil {
		return nil, err
	}

	recipientsJSON, b64SingleRecipientEncKey, singleRecipientHeader, err := jweGo.PrepareRecipientsJSON(marshal)
	if err != nil {
		return nil, err
	}

	b64AAD := base64.RawURLEncoding.EncodeToString([]byte(jweGo.AAD))
	b64IV := base64.RawURLEncoding.EncodeToString([]byte(jweGo.IV))

	if jweGo.Ciphertext == "" {
		return nil, errEmptyCiphertext
	}

	b64Ciphertext := base64.RawURLEncoding.EncodeToString([]byte(jweGo.Ciphertext))
	b64Tag := base64.RawURLEncoding.EncodeToString([]byte(jweGo.Tag))

	preparedJWE := JWEncryptionRawJSON{
		B64ProtectedHeaders:      b64ProtectedHeaders,
		UnprotectedHeaders:       unprotectedHeaders,
		Recipients:               recipientsJSON,
		B64SingleRecipientEncKey: b64SingleRecipientEncKey,
		SingleRecipientHeader:    singleRecipientHeader,
		B64AAD:                   b64AAD,
		B64IV:                    b64IV,
		B64Ciphertext:            b64Ciphertext,
		B64Tag:                   b64Tag,
	}

	return marshal(preparedJWE)
}

// SerializeMultiRecipientStringified serializes and strigifies the JSON data, as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
// The full serialization syntax is used for multi-recipient JWE.
func (jweGo *JWEncryptionGo) SerializeMultiRecipientStringified() (string, error) {
	serializedJWE, err := jweGo.SerializeMultiRecipientBytes(json.Marshal)
	if err != nil {
		return "", err
	}

	return string(serializedJWE), nil
}

// SerializeMultiRecipientJSON returns JSON as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
// The full serialization syntax is used for multi-recipient JWE.
func (jweGo *JWEncryptionGo) SerializeMultiRecipientJSON() (map[string]interface{}, error) {
	jweSerializedBytes, err := jweGo.SerializeMultiRecipientBytes(json.Marshal)
	if err != nil {
		return nil, err
	}

	var jweSerialzedJSON map[string]interface{}
	err = json.Unmarshal(jweSerializedBytes, &jweSerialzedJSON)
	return jweSerialzedJSON, err
}

// SerializeMultiRecipientRawJSON serializes the JWE into RawMessage, as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
// The full serialization syntax is used for multi-recipient JWE.
func (jweGo *JWEncryptionGo) SerializeMultiRecipientRawJSON() (json.RawMessage, error) {
	jweSerializedBytes, err := jweGo.SerializeMultiRecipientBytes(json.Marshal)
	if err != nil {
		return nil, err
	}

	jweSerializedRawJSON, errMsg := contentUtils.ConvertBytesToRawJson(&jweSerializedBytes)
	return jweSerializedRawJSON, errors.New(errMsg)
}

// TODO: This servers both for JWE and JWS Headers?
func (jweGo *JWEncryptionGo) PrepareHeadersJSON(jsonMarshal JsonMarshalFunc) (string, json.RawMessage, error) {
	var b64ProtectedHeaders string

	if jweGo.ProtectedHeaders != nil {
		protectedHeadersJSON, err := jsonMarshal(jweGo.ProtectedHeaders)
		if err != nil {
			return "", nil, err
		}

		b64ProtectedHeaders = base64.RawURLEncoding.EncodeToString(protectedHeadersJSON)
	}

	var unprotectedHeaders json.RawMessage

	if jweGo.UnprotectedHeaders != nil {
		unprotectedHeadersJSON, err := jsonMarshal(jweGo.UnprotectedHeaders)
		if err != nil {
			return "", nil, err
		}

		unprotectedHeaders = unprotectedHeadersJSON
	}

	return b64ProtectedHeaders, unprotectedHeaders, nil
}

func (jweGo *JWEncryptionGo) PrepareRecipientsJSON(jsonMarshal JsonMarshalFunc) (json.RawMessage, string, []byte, error) {
	var recipientsJSON json.RawMessage
	var b64SingleRecipientEncKey string
	var singleRecipientHeader []byte

	switch len(jweGo.Recipients) {
	case 0:
		// The spec requires that the "recipients" field must always be an array and be present,
		// even if some or all of the array values are the empty JSON object "{}".
		recipientsJSON = json.RawMessage("[{}]")
	case 1:
		// Use flattened JWE JSON serialization syntax as defined in https://tools.ietf.org/html/rfc7516#section-7.2.2.
		b64SingleRecipientEncKey = base64.RawURLEncoding.EncodeToString([]byte(jweGo.Recipients[0].EncryptedKey))

		if jweGo.Recipients[0].Header != nil {
			var errMarshal error
			// preparing for future compact serialization for the sole recipient
			singleRecipientHeader, errMarshal = jsonMarshal(jweGo.Recipients[0].Header)
			if errMarshal != nil {
				return nil, "", nil, errMarshal
			}
		}
	default:
		// Make copy of Recipients array so we don't change the underlying object
		recipientsToMarshal := make([]RecipientJWE, len(jweGo.Recipients))
		for i, recipient := range jweGo.Recipients {
			recipientsToMarshal[i].EncryptedKey = base64.RawURLEncoding.EncodeToString([]byte(recipient.EncryptedKey))
			recipientsToMarshal[i].Header = recipient.Header
		}

		nonEmptyRecipientsJSON, errMarshal := jsonMarshal(recipientsToMarshal)
		if errMarshal != nil {
			return nil, "", nil, errMarshal
		}

		recipientsJSON = nonEmptyRecipientsJSON
	}

	return recipientsJSON, b64SingleRecipientEncKey, singleRecipientHeader, nil
}

// CompactSoleRecipientJWE serializes the given JWE into a compact, URL-safe string as defined in
// https://tools.ietf.org/html/rfc7516#section-7.1 (e.g.: for OpenID)
// OpenID Connect specification mandates to use JWS compact serialization and JWE compact serialization whenever necessary
// Any JWT must follow compact serialization. A JWS or JWE token following JSON serialization cannot be called as a JWT.
// JWE compact serialization is built with five key components, each separated by a period (.):
//  - 1) JOSE header
//  - 2) JWE Encrypted Key (CEK)
//  - 3) JWE Initialization Vector (IV)
//  - 4) JWE Additional Authentication Data (AAD),
//  - 5) JWE Ciphertext and JWE Authentication Tag
func (jweGo *JWEncryptionGo) CompactSoleRecipientJWE(jsonMarshal JsonMarshalFunc) (string, error) {
	if jweGo.ProtectedHeaders == nil {
		return "", errProtectedHeaderMissing
	}

	if len(jweGo.Recipients) != 1 {
		return "", errNotOnlyOneRecipient
	}

	if jweGo.UnprotectedHeaders != nil {
		return "", errUnprotectedHeaderUnsupported
	}

	if jweGo.AAD != "" {
		return "", errAADHeaderUnsupported
	}

	if jweGo.Recipients[0].Header != nil {
		return "", errPerRecipientHeaderUnsupported
	}

	protectedHeadersJSON, err := jsonMarshal(jweGo.ProtectedHeaders)
	if err != nil {
		return "", err
	}

	b64ProtectedHeader := base64.RawURLEncoding.EncodeToString(protectedHeadersJSON)
	b64EncryptedKey := base64.RawURLEncoding.EncodeToString([]byte(jweGo.Recipients[0].EncryptedKey))
	b64IV := base64.RawURLEncoding.EncodeToString([]byte(jweGo.IV))
	b64Ciphertext := base64.RawURLEncoding.EncodeToString([]byte(jweGo.Ciphertext))
	b64Tag := base64.RawURLEncoding.EncodeToString([]byte(jweGo.Tag))

	return fmt.Sprintf("%s.%s.%s.%s.%s", b64ProtectedHeader, b64EncryptedKey, b64IV, b64Ciphertext, b64Tag), nil
}

/* JWE with compact serialization can envelope with AES a JWT:
    BASE64URL(UTF8(JWT Protected Header)) ‘.’
    BASE64URL(NestedJWT Payload) ‘.’ // it contains the custom claims
    BASE64URL(NestedJWT Signature) // if signed

The fourth element of the JWE token is the base64url-encoded value of the JWE ciphertext.
The JWE ciphertext is computed by encrypting the plaintext JSON payload using the Content Encryption Key (CEK).
the JWE initialization vector and the Additional Authentication Data (AAD) value, with the encryption algorithm defined by the header element enc.
The algorithm defined by the enc header element should be a symmetric Authenticated Encryption with Associated Data (AEAD) algorithm.
The AEAD algorithm, which is used to encrypt the plaintext payload, also allows specifying Additional Authenticated Data (AAD).

The base64url-encoded value of the JWE Authenticated Tag is the final element of the JWE token.
As discussed before the value of the authentication tag is produced during the AEAD encryption process, along with the ciphertext.
The authentication tag ensures the integrity of the ciphertext and the Additional Authenticated Data (AAD).

JWE Compact Serialization steps:
1. 	The 1st element of the JWE token is the base64url-encoded value of the JOSE header with UTF8 encoding.
2.	The 2nd element of the JWE token is the JWE Encrypted Key: base64url-encoded value of C (Encapsulated Key in PQC is CEK / SS encrypted with the recipient's public key) based on the key management mode (AES 256-bit key).
2a.	The CEK (Content Encryption Key) / SS (Symmetric Shared Key) is an ephemeral key. The CEK is later used to encrypt the JSON payload.
2b.	Encrypt the CEK with the recipient's public key to obtain the Encapsulated Key (C). There is only one C element in the JWE token (1 recipient).
2c.	The 2nd element of the JWE token is the JWE Encrypted Key: base64url-encoded C (Encapsulated Key) of the connection's SS (CEK).
3.	The 3rd element of the JWT token is the JWE Initialization Vector: base64url-encoded random value (irrespective of the serialization technique).
4a.	If token compression is needed, the JSON payload in plaintext must be compressed following the compression algorithm defined under the zip header element.
4b.	Compute ASCII value of the encoded JOSE header from the previous step and use it as the AAD.
4c.	Encrypt the compressed JSON payload using the CEK, the JWE Initialization Vector and the Additional Authenticated Data (AAD),
following the content encryption algorithm defined by the header enc header element (AEAD algorithm).
It produce the ciphertext and the Authentication Tag.
4d.	Compute the base64url-encoded value of the ciphertext, which is produced by the step one before the previous.
This is the 4th element of the JWE token.
5.	Compute the base64url-encoded value of the Authentication Tag, which is produced by the step one before the previous.
This is the 5th element of the JWE token.

Now we have all the elements to build the JWE token in the following manner. The line breaks are introduced only for clarity.
BASE64URL-ENCODE(UTF8(JWE Protected Header)) ‘.’
BASE64URL-ENCODE(JWE Encrypted Key) ‘.’
BASE64URL-ENCODE(JWE Initialization Vector) ‘.’
BASE64URL-ENCODE(JWE Ciphertext) ‘.’
BASE64URL-ENCODE(JWE Authentication Tag)

---

A signed or an encrypted message can be serialized in two ways by following the NestedJWT or JWE specification:
A. NestedJWT compact serialization (OpenID Connect specification): only 1 recipient.
B. NestedJWT JSON serialization can produce multiple signatures over the same NestedJWT payload along with multiple JOSE headers: several recipients.
   This JSON object includes 2 top-level elements: payload and signatures (which is a JSON array),
	and three sub elements under each entry of the signatures array: protected, header and signature.

Compact serialized NestedJWT token for 1 recipient ingredients:
1a. Create a JSON object including all the JOSE header elements, issuer should advertise in the jku, jwk, kid, x5u, x5c, x5t or x5t#s256 claims
	of the JOSE header the sender's universal health identifier for PQC resistance (instead of the sender's public key).
1b. Compute the base64url-encoded value against the UTF-8 encoded JOSE header from the 1st step, to produce the 1st element of the NestedJWT token.
2a. Construct the payload or the content to be signed (known as the NestedJWT payload). The payload is not necessarily JSON.
2b. Compute the base64url-encoded value of the NestedJWT payload from the previous step to produce the 2nd element of the NestedJWT token.
3a. Build the message to compute the digital signature or the Mac: ASCII(BASE64URL-ENCODE(UTF8(JOSE Header)) ‘.’ BASE64URL-ENCODE(NestedJWT Payload))
3b. Compute the signature over the message constructed, following the signature algorithm defined by the JOSE header element 'alg'
	and using the signature key of the corresponding universal health identifier.
3c. Compute the base64url encoded value of the NestedJWT signature produced in the previous step, which is the 3rd element of the serialized NestedJWT token.
4a. Finally the complete NestedJWT payload (with the 3 parts) can be enveloped using AES or other PQC secure algorithm,
	using the connection's shared key and can be included as part of a JWM or as the body of an HttpHeaders request or response.

Non-compact NestedJWT serialization for 2 or more recipients:
1a. JSON object includes 2 top-level elements: payload and signatures (which is a JSON array)
	and three sub elements under each entry of the signatures array: protected, header and signature.
1b. The payload top-level element of the JSON object includes the base64url-encoded value of the complete NestedJWT payload (not necessarily needs to be a JSON payload).
	The payload top-level is encrypted by using the encryption key corresponding with the kid element (universal health identifier) for PQC resistance.
2a. The message carries with 2 or more signatures over the same payload.
	Each signature uses a different key to sign, represented by the corresponding kid header element: sender's universal health identifier instead of sender's public key for PQC resistance.
2b.
3a.

The JWE specification introduces two new elements (enc and zip), which are included in the JOSE header of the JWE token,
in addition to what’s defined by the JSON Web Signature (NestedJWT) specification

The enc element of the JOSE header defines the content encryption algorithm
and it should be a symmetric Authenticated Encryption with Associated Data (AEAD) algorithm.
The alg element of the JOSE header defines the encryption algorithm to encrypt the Content Encryption Key (CEK).
This algorithm can also be defined as the key wrapping algorithm, as it wraps the CEK.

For content encryption, it uses A256GCM algorithm (A256GCM is defined in the JWA specification)
Authenticated Encryption with Associated Data (AEAD) is a block cipher mode of operation which simultaneously provides
confidentiality, integrity, and authenticity assurances on the data; decryption is combined in single step with integrity verification
{“alg”:”A256KW”,”enc”:”A256GCM”}
{“alg”:”A256GCMKW”,”enc”:”A256GCM”}

| JWE		| XML ENC										| JCA				| OID
| A256GCM	| http://www.w3.org/2009/xmlenc11#aes256-gcm	| AES/GCM/NoPadding	| 2.16.840.1.101.3.4.1.46

| "alg" Param	| Key Management										| More			| Implementation
| A256KW		| AES Key wrap with default initial using 256-bit key	| none			| Recommended
| A256GCMKW		| Key wrapping with AES GCM using 256-bit key			| "iv",  "tag"	| Optional

Algorithm Name: "A256GCMKW"
   o  Algorithm Description: Key wrapping with AES GCM using 256-bit key
   o  Algorithm Usage Location(s): "alg"
   o  JOSE Implementation Requirements: Optional
   o  Change Controller: IESG
   o  Specification Document(s): Section 4.7 of RFC 7518
Algorithm Name: "A256GCM"
   o  Algorithm Description: AES GCM using 256-bit key
   o  Algorithm Usage Location(s): "enc"
   o  JOSE Implementation Requirements: Recommended
   o  Change Controller: IESG
   o  Specification Document(s): Section 5.3 of RFC 7518

Example A256KW (AES 256 bit default Key Wrapping):
eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.66xZoxFI18zfvLMO6WU1zzqqX1tT8xu_qZzMQyPcfVuajPNkOJUXQA.
X5ZL8yaOektXmfny.
brz-Lg.
xG-EvM-9hrw0XRiuRW7HrA

         JWE Header:  {"alg":"A256KW","enc":"A256GCM"}
Encrypted key (CEK):  66xZoxFI18zfvLMO6WU1zzqqX1tT8xu_qZzMQyPcfVuajPNkOJUXQA
                 IV:  X5ZL8yaOektXmfny
         Ciphertext:  brz-Lg
 Authentication Tag:  xG-EvM-9hrw0XRiuRW7HrA

*/
