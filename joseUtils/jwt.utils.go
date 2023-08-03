package joseUtils

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"strings"
)

var (
	ErrUnsupportedKey   = errors.New("unsupported key")
	ErrCannotCreateData = errors.New("cannot create data")
	ErrCannotGetData    = errors.New("cannot get data")
	ErrSignature        = errors.New("signature error")
)

/* FINANCIAL GRADE API (FAPI): https://openid.net/specs/openid-financial-api-part-2-1_0.html
Mitigate:
    attacks that leverage the weak binding of endpoints in RFC6749, and
    attacks that modify authorization requests and responses unprotected in RFC6749.

JWT Secured Authorization Response Mode for OAuth 2.0 (Oauth JARM)
https://openid.net/specs/openid-financial-api-jarm.html
https://www.rfc-editor.org/rfc/rfc9101.html
https://connect2id.com/blog/request-objects-in-oauth-and-openid-connect
https://kb.authlete.com/en/s/oauth-and-openid-connect/a/enabling-jarm
It allows a client to request that an authorization server encodes any response type in a JWT.
This specification facilitates use of JARM in conjunction with the response type code.
If the 'response_type' value 'code' is used in conjunction with the 'response_mode' value 'jwt',
the authorization server shall create JWT-secured authorization responses as specified in JARM, Section 4.3.
JARM enhances the security of the standard authorization response adding support for signing and encryption,
sender authentication, audience restriction as well as protection from replay, credential leakage, and mix-up attacks.
This means JARM protects the authentication response (instead of the ID Token)
and the ID Token containing End-User PayloadClaims is obtained from the token endpoint.
This facilitates privacy since no End-User PayloadClaims are sent through the front channel.
It also provides decoupling of message protection and identity providing since a client (or RP) can basically
use JARM to protect all authorization responses and turn on OpenID if needed (e.g. to log the user in).

A Request Object has the media type (RFC2046) application/oauth-authz-req+jwt.
Note that some existing deployments may alternatively be using the type application/jwt.
The following is an example of the PayloadClaims in a Request Object before base64url [RFC7515] encoding and signing.
Note that it includes the extension parameters nonce and max_age.
  {
   "iss": "s6BhdRkqt3",
   "aud": "https://server.example.com",
   "response_type": "code id_token",
   "client_id": "s6BhdRkqt3",
   "redirect_uri": "https://client.example.org/cb",
   "scope": "openid",
   "state": "af0ifjsldkj",
   "nonce": "n-0S6_WzA2Mj",
   "max_age": 86400
  }
The Authorization Request Object MUST be one of the following:
(a) NestedJWT signed
(b) NestedJWT signed and JWE encrypted
*/

func (partsJWT *PartsJWT) Compact() string {
	unsignedCompactJWT := partsJWT.Header + "." + partsJWT.Payload + "."
	if partsJWT.Signature != nil {
		signedJWT := unsignedCompactJWT + *partsJWT.Signature
		return signedJWT
	} else {
		return unsignedCompactJWT
	}
}

// GetData returns DataJWT with headers, payload and optional signature or nil
func (partsJWT *PartsJWT) GetData() *DataJWT {
	return GetDataByPartsJWT(partsJWT)
}

type DataJWT struct {
	Header    Headers                // The protected Header claims
	Payload   map[string]interface{} // JSON Payload claims
	Signature *[]byte                // Signature if already signed
}

// CreatePartsUnsignedJWT method converts both headers and payload data to RawBase64UrlSafe format to return the encoded parts.
// (payload is compressed when the "zip" header claim is "DEF")
// It does not return the signature (nil).
func (dataJWT *DataJWT) PartsUnsignedJWT() *PartsJWT {
	partsJWT, err := CreatePartsUnsignedJWT(dataJWT.Header, dataJWT.Payload)
	if err != nil {
		return nil
	} else {
		return partsJWT
	}
}

// CompactUnsignedJWT method returns an unsigned compact JWT which is an string with the format
// "base64url(headerBytes).base64url(payloadBytes)." (no signature after the last dot).
// It creates both the base64url encoded header and payload and concatenates it (empty signature).
// The last character "." SHALL be removed before doing the signature and then the signature SHALL added (concatenated).
func (dataJWT *DataJWT) CompactUnsignedJWT() string {
	partsJWT := dataJWT.PartsUnsignedJWT()
	return partsJWT.Compact()
}

func (dataJWT *DataJWT) GetIssuer() string {
	if dataJWT == nil {
		return ""
	} else {
		return fmt.Sprint(dataJWT.Payload["iss"]) // fmt.Sprint(val) is equivalent to fmt.Sprintf("%v", val)
	}
}

// GetDataJWT returns nil or a deserialized JWT with header and payload as JSON data and signature as bytes.
var GetDataJWT = func(compactJWT *string) *DataJWT {
	partsJWT := GetPartsJWT(compactJWT)
	if partsJWT == nil {
		return nil
	}

	// getting the data or nil
	data := GetDataByPartsJWT(partsJWT)
	return data
}

// GetInflatedDataByCompactJWT decompress a JWT payload if required and returns payload bytes and header claims or nil if some error
func GetInflatedDataByCompactJWT(compactJWT *string) (headerJSON map[string]interface{}, payloadBytes []byte) {
	partsJWT := GetPartsJWT(compactJWT)
	return GetInflatedDataByPartsJWT(partsJWT)
}

// GetInflatedDataByPartsJWT decompress a JWT payload if required and returns payload bytes and header claims or nil if some error
func GetInflatedDataByPartsJWT(partsJWT *PartsJWT) (headerJSON map[string]interface{}, payloadBytes []byte) {
	if partsJWT == nil {
		return nil, nil
	}

	// getting the JSON headers
	headerBytes, err := base64.RawURLEncoding.DecodeString(partsJWT.Header)

	if err != nil {
		return nil, nil
	}

	// WRONG: var pointerHeadersJSON map[string]interface{}
	pointerHeadersJSON := &map[string]interface{}{}       // do not use a "var" but a pointer to a not nil Object (initialized) to Unmarshall, or it will be an error
	err = json.Unmarshal(headerBytes, pointerHeadersJSON) // If v is nil or not a pointer, Unmarshal returns an InvalidUnmarshalError.
	if err != nil {
		return nil, nil
	}
	// getting the payload data
	headersJSON := *pointerHeadersJSON
	isCompressed := headersJSON[HeaderCompression] == "DEF"
	if isCompressed {
		compressedBytes, err := base64.RawURLEncoding.DecodeString(partsJWT.Payload)
		if err != nil {
			return nil, nil
		}

		payloadBytes, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedBytes)))
		if err != nil {
			return nil, nil
		}

	} else {
		payloadBytes, _ = base64.RawURLEncoding.DecodeString(partsJWT.Payload)
	}

	return headersJSON, payloadBytes
}

// GetDataByPartsJWT decodes and decompress the parts or the JWT and returns DataJWT
func GetDataByPartsJWT(partsJWT *PartsJWT) *DataJWT {

	// getting headers and payload data
	var dataJWT = DataJWT{}
	headerJSON, payloadBytes := GetInflatedDataByPartsJWT(partsJWT)

	dataJWT.Header = headerJSON

	err := json.Unmarshal(payloadBytes, &dataJWT.Payload)
	if err != nil {
		return nil
	}

	if partsJWT.Signature != nil {
		signatureBytes, _ := base64.RawURLEncoding.DecodeString(*partsJWT.Signature)
		if signatureBytes != nil {
			dataJWT.Signature = &signatureBytes
		}
	} else {
		// nothing
		// dataJWT.Signature = nil
	}
	return &dataJWT
}

// GetPartsJWT gets a compact JWT/PartsJWT (string, not JSON) and returns an
// object with header, payload and signature (base64url encoded), or nil if error.
func GetPartsJWT(compactToken *string) *PartsJWT {
	if compactToken == nil {
		return nil
	}
	splittedJWT := strings.Split(*compactToken, ".")
	if len(splittedJWT) != 3 {
		return nil
	}
	return &PartsJWT{
		Header:    splittedJWT[0],
		Payload:   splittedJWT[1],
		Signature: &splittedJWT[2],
	}
}

// CreatePartsUnsignedJWT function converts both headers and payload data to RawBase64UrlSafe format to return the encoded parts.
// (payload is compressed when the "zip" header claim is "DEF")
// It does not return the signature (nil).
func CreatePartsUnsignedJWT(headerClaims Headers, payloadClaims interface{}) (*PartsJWT, error) {

	// converting the JSON payload claims data to bytes and compressing if specified
	payloadBytes, err := json.Marshal(payloadClaims)
	if err != nil {
		return nil, ErrCannotCreateData
	}

	// do payload compression if "zip" is in the header
	if headerClaims[HeaderCompression] == "DEF" {
		payloadBuffer := new(bytes.Buffer)
		if compressionWriter, err := flate.NewWriter(payloadBuffer, flate.BestCompression); err != nil {
			return nil, err
		} else {
			if _, err = compressionWriter.Write(payloadBytes); err != nil {
				return nil, ErrCannotCreateData
			}
			if err = compressionWriter.Close(); err != nil {
				return nil, ErrCannotCreateData
			}
		}
	}
	payloadBase64Url := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// encoding the header JSON data and the payload bytes to base64-url format
	headerBytes, err := json.Marshal(headerClaims)
	if err != nil {
		return nil, ErrCannotCreateData
	}
	headerBase64Url := base64.RawURLEncoding.EncodeToString(headerBytes)

	// returning the object with the encoded base64 strings
	jwtParts := PartsJWT{
		Header:  headerBase64Url,
		Payload: payloadBase64Url,
	}

	return &jwtParts, nil
}
