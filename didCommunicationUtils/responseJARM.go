package didCommunicationUtils

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Universal-Health-Chain/common-utils-golang/httpUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/openidUtils"
)

// Note: In JAR the JWT data container is named "Request Object" and in JARM it is named "Response Document"
// Note: the OpenID "id_token" (data) is the Response Document JARM,
// but not the Request Object JAR (it is the response to an authentication request).

// ReturnResponseJARM replies to the request with:
// - an HTML web page which contains a form and a javascript redirection when loading the web page in a browser (by default)
// - or a redirect URL with response parameter containing the JARM compact JWT response
//	 where status code should be in the 3xx range and is usually StatusMovedPermanently, StatusFound or StatusSeeOther.
//
// Note: "query.jwt" MUST NOT be used in conjunction with response types that contain "token" or "id_token"
// unless the response JWT is encrypted to prevent token leakage in the URL.
//
// REVIEW:
// If the Content-Type header has not been set, it sets to "text/html; charset=utf-8" and writes a small HTML body.
// Setting the Content-Type header to any value, including nil, disables that behavior.

func ReturnResponseJARM(w http.ResponseWriter, r *http.Request, decodedRequestJAR *DecodedRequestPayloadJAR, compactJWT *string, redirectURL string) {
	responseMode := ""

	if decodedRequestJAR != nil && decodedRequestJAR.ResponseMode != nil {
		responseMode = *decodedRequestJAR.ResponseMode
	}

	switch responseMode {

	case "query.jwt":
		{
			responseJARM := openidUtils.CreateResponseRedirectedUrlQueryJARM(redirectURL, *compactJWT)
			http.Redirect(w, r, responseJARM, http.StatusFound)
			return
		}

	case "fragment.jwt":
		{
			responseJARM := openidUtils.CreateResponseRedirectUrlFragmentJARM(redirectURL, *compactJWT)
			http.Redirect(w, r, responseJARM, http.StatusFound)
			return
		}

	case "jwt":
		{
			if strings.Contains(*decodedRequestJAR.ResponseType, "code") {
				responseJARM := openidUtils.CreateResponseRedirectedUrlQueryJARM(redirectURL, *compactJWT)
				http.Redirect(w, r, responseJARM, http.StatusFound)
				return
			}

			if strings.Contains(*decodedRequestJAR.ResponseType, "token") {
				responseJARM := openidUtils.CreateResponseRedirectUrlFragmentJARM(redirectURL, *compactJWT)
				http.Redirect(w, r, responseJARM, http.StatusFound)
				return
			}

			// else it goes to the default form_post.jwt response
		}

	// the default is the default form_post.jwt response
	default:
		responseForm := openidUtils.ResponseFormJARM{
			Response: *compactJWT,
		}
		responseForm.ReturnWebPageFormData(w)
		return
	}
}

// ResponseDocumentPayloadBodyJARM is a JSON:API Primary Document which can have HTTP Headers and API Data.
// It MUST be at the body of every request / response DIDComm message containing data.
// It MUST contain at least one of the following top-level members:
// - Data: the document’s "primary data" (see https://jsonapi.org/format/1.1/).
// - Errors: an array of JSON:API Error objects.
// - Meta: a Meta object that contains non-standard meta-information specific for the protocol, such as decoded "Bearer" and "DPoP" tokens.
//   (they can be set when using bluetooth or decoded from tht HTTP Headers)
//   and it is removed before creating a FormData (to be sent to an API).
// 	 Note: "Data.Meta" can contain metadata for each resource object, distinct to this specific protocol's "Meta" data.
// Additionally, any other member can be defined by an applied extension:
// - HttpHeader: HTTP response header fields (e.g.: Authorization, DPoP, Content-Type).
// The document MAY contain any of these top-level members:
// - jsonapi: an object describing the server’s implementation.
// - links: a links object related to the primary data.
// - included: an array of resource objects that are related to the primary data and/or each other (“included resources”).
type ResponseDocumentPayloadBodyJARM struct {
	Data     *[]map[string]interface{} `json:"data,omitempty" bson:"data,omitempty"`     // an array of JSON:API Resource Objects.
	Errors   *[]ErrorObject            `json:"errors,omitempty" bson:"errors,omitempty"` // an array of JSON:API Error Objects.
	Meta     *DIDCommBodyMetaJAR       `json:"meta,omitempty" bson:"meta,omitempty"`     // decoded "Bearer" access token and "DPoP".
	Jsonapi  *map[string]interface{}   `json:"jsonapi,omitempty" bson:"jsonapi,omitempty"`
	Links    *[]LinkObject             `json:"links,omitempty" bson:"links,omitempty"`       // A "link object" is an object that represents a web link, related to the primary data.
	Included *[]ResourceObject         `json:"included,omitempty" bson:"included,omitempty"` // an array of resource objects that are related to the primary data and/or each other (“included resources”).
	// difference with request:
	HttpHeader *httpUtils.HttpResponseHeaders `json:"http,omitempty" bson:"http,omitempty"` // HTTP header fields (when sent by HTTP protocol).
	// JARHeader is not in a response
}

// ResponseDocumentPayloadJARM is the payload of the JWT Response Document utilized to secure the transmission:
// - Audience: the client_id of the client the response is intended for (it is not an array of strings);
// - Expiration: expiration of the JWT (it is not a string);
// - Issuer: the issuer URL of the authorization server that created the response;
// - HttpHeaders Status-Code;
// - State - the state value as sent by the client in the authorization request (if applicable);
// - the result Data from the API (see https://jsonapi.org/format/1.1/#document-top-level)
// - OR the Error response data as per the OpenID JARM error response parameters defined in RFC6749 section 4.1.2.1
// (see JARM at https://bitbucket.org/openid/fapi/src/master) with the Error code and optional ErrorDescription and ErrorURI.
type ResponseDocumentPayloadJARM struct {
	// OpenID JARM mandatory fields
	Audience   string `json:"aud"` // the API(s) the JWT is intended for (it is converted to a space separated string)
	Expiration int64  `json:"exp"` // the expiration time of the JWT (it is not a string);
	Issuer     string `json:"iss"` // the issuer URL of the authorization server that created the response

	// OpenID Error fields
	Error            *string `json:"error,omitempty"`             // OpenID Authentication error: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
	ErrorDescription *string `json:"error_description,omitempty"` // a human-readable description of the error
	ErrorURI         *string `json:"error_uri,omitempty"`         // a URI identifying a human-readable web page with information about the error (e.g.: with info for developers)

	// OpenID Code flow response fields
	Code        *string `json:"code,omitempty"`
	IssuedAt    *int64  `json:"iat,omitempty"`
	JSONTokenID *string `json:"jti,omitempty"`
	NotBefore   *int64  `json:"nbf,omitempty"`
	Scope       *string `json:"scope,omitempty"`

	// OpenID AccessToken flow response fields
	AccessToken  *string `json:"access_token,omitempty"`
	ExpiresIn    *int64  `json:"expires_in,omitempty"`
	IdToken      *string `json:"id_token,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	TokenType    *string `json:"token_type,omitempty"`

	// Open ID Additional fields
	State *string `json:"state,omitempty"` // the state value as sent by the client in the authorization request (if applicable)

	// DIDComm fields
	// Attachments *[]didCommunicationUtils.DIDComm
	Body      ResponseDocumentPayloadBodyJARM
	MediaType *string `json:"typ,omitempty"`
}

func (responsePayloadData *ResponseDocumentPayloadJARM) ToJSON() map[string]interface{} {
	responsePayloadJSON := map[string]interface{}{} // empty JSON

	responsePayloadBytes, err := json.Marshal(*responsePayloadData)
	if err != nil {
		return responsePayloadJSON
	}

	err = json.Unmarshal(responsePayloadBytes, &responsePayloadJSON)
	if err != nil {
		return responsePayloadJSON
	}

	return responsePayloadJSON
}

// TODO: CreateResponseDocument functions should always return iss, nbf, ... (review)

// CreateResponseDocumentPayloadWithOpenidCode receives the HTTP Status-Code and an array of JSON objects
// and returns a ResponseDocumentPayloadJARM (to create the compact JWT Response Document for the JARM Redirect URL response).
var CreateResponseDocumentPayloadWithOpenidCode = func(httpStatusCode int, openidCode string) ResponseDocumentPayloadJARM {
	httpHeaders := httpUtils.HttpResponseHeaders{StatusCode: httpStatusCode}
	responseDocument := ResponseDocumentPayloadJARM{
		Body: ResponseDocumentPayloadBodyJARM{
			HttpHeader: &httpHeaders,
		},
		Code: &openidCode,
		// NotBefore:
		// Issued:
		// ...
	}

	return responseDocument
}

// CreateResponseDocumentPayloadWithAccessToken receives the HTTP Status-Code and OpenidAccessTokenResponseData
// and returns a ResponseDocumentPayloadJARM (to create the compact JWT Response Document for the JARM Redirect URL response).
var CreateResponseDocumentPayloadWithAccessToken = func(httpStatusCode int, accessTokenResponseData openidUtils.OpenidAccessTokenResponseData) ResponseDocumentPayloadJARM {
	httpHeaders := httpUtils.HttpResponseHeaders{StatusCode: httpStatusCode}

	tokenType := openidUtils.AuthorizationBearerType // "Bearer" (not lowercase, see https://www.rfc-editor.org/rfc/rfc6750#section-4)

	responseDocument := ResponseDocumentPayloadJARM{
		Body: ResponseDocumentPayloadBodyJARM{
			HttpHeader: &httpHeaders,
		},
		AccessToken:  &accessTokenResponseData.AccessToken,
		TokenType:    &tokenType,
		ExpiresIn:    &accessTokenResponseData.ExpiresIn, // "expires_in" is different to "exp"
		Scope:        &accessTokenResponseData.Scope,
		RefreshToken: accessTokenResponseData.RefreshToken,
		IdToken:      accessTokenResponseData.IDToken,

		// NotBefore:
		// Issued:
		// ...
	}

	return responseDocument
}

// CreateResponseDocumentPayloadWithData receives the HTTP Status-Code and an array of JSON objects
// and returns a ResponseDocumentPayloadJARM (to create the compact JWT Response Document for the JARM Redirect URL response).
var CreateResponseDocumentPayloadWithData = func(httpStatusCode int, dataObjects *[]map[string]interface{}, errorObjects *[]ErrorObject) ResponseDocumentPayloadJARM {
	// creating the HTTP headers with the HTTP status code
	httpHeaders := httpUtils.HttpResponseHeaders{StatusCode: httpStatusCode}
	// setting both data and errors (if any) and HTTP Status code
	responseDocument := ResponseDocumentPayloadJARM{
		Body: ResponseDocumentPayloadBodyJARM{
			Data:       dataObjects,
			Errors:     errorObjects,
			HttpHeader: &httpHeaders,
		},
		// NotBefore:
		// Issued:
		// ...
	}

	return responseDocument
}

// CreateResponseDocumentPayloadWithError receives the HTTP Status-Code and error data (see https://www.rfc-editor.org/rfc/rfc6749.html#page-45)
// and returns a ResponseDocumentPayloadJARM (to create the compact JWT Response Document for the JARM Redirect URL response).
var CreateResponseDocumentPayloadWithError = func(httpStatusCode int, errorType *string, errorMsg string, errorURI *string) ResponseDocumentPayloadJARM {
	httpHeaders := httpUtils.HttpResponseHeaders{StatusCode: httpStatusCode}
	responseDocument := ResponseDocumentPayloadJARM{
		Body: ResponseDocumentPayloadBodyJARM{
			HttpHeader: &httpHeaders,
		},
		ErrorDescription: &errorMsg,
		Error:            errorType, // OpenID errors:
		ErrorURI:         errorURI,
		// NotBefore:
		// Issued:
		// ...
	}

	return responseDocument
}
var GetRecipientEncryptionKeyByDecodedRequestPayloadJAR = func(decodedRequestPayloadJAR *DecodedRequestPayloadJAR) *jwkUtils.JWK {
	if decodedRequestPayloadJAR == nil {
		return nil
	}

	requesterJwKeySet := decodedRequestPayloadJAR.Body.Meta.JWS.JSONWebKeySet
	requesterPublicKyberKeys := requesterJwKeySet.SearchJWKeyByAlg("kyber")
	if requesterPublicKyberKeys == nil || len(*requesterPublicKyberKeys) < 1 {
		return nil
	} else {
		recipientKeys := *requesterPublicKyberKeys
		return &recipientKeys[0]
	}
}

