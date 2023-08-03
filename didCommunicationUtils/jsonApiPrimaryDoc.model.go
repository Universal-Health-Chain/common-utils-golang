package didCommunicationUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
)

// PrimaryDocument MUST be at the body of every request and response DIDComm message containing data.
// The document MUST contain at least one of the following top-level members:
// - data: the document’s “primary data”.
// - errors: an array of error objects.
// - meta: a metaObject that contains non-standard meta-information.
// Additionally, any other member can be defined by an applied extension and
// the document MAY contain any of these top-level members:
// - jsonapi: an object describing the server’s implementation.
// - links: a links object related to the primary data.
// - included: an array of resource objects that are related to the primary data and/or each other (“included resources”).
type PrimaryDocument struct {
	Data   []ResourceObject `json:"data,omitempty" bson:"data,omitempty"`
	Errors *[]ErrorObject   `json:"errors,omitempty" bson:"errors,omitempty"`
	// JARProtocol openidUtils.JARHeader `json:"jar,omitempty" bson:"jar,omitempty"` // JOSE Headers from the decoded JWE and JWT/JWS (nested JWT).
	Meta DIDCommBodyMetaJAR `json:"meta,omitempty" bson:"meta,omitempty"`
	// Jsonapi  *map[string]interface{} `json:"jsonapi,omitempty" bson:"jsonapi,omitempty"`
	// Links    *[]LinkObject           `json:"links,omitempty" bson:"links,omitempty"`       // A "link object" is an object that represents a web link, related to the primary data.
	// Included *[]ResourceObject       `json:"included,omitempty" bson:"included,omitempty"` // an array of resource objects that are related to the primary data and/or each other (“included resources”).
}

type DIDCommBodyMetaJAR struct {
	BearerData joseUtils.DataJWT `json:"bearer,omitempty" bson:"bearer,omitempty"` // the access token
	DPoPData   joseUtils.DataJWT `json:"dpop,omitempty" bson:"dpop,omitempty"`
	// - decoded JWE protected headers such as "skid" (sender's encryption keyID), "kid" (recipient's public encryption) and "enc" (encryption algorithm). It can contain mixed unprotected headers for the recipient.
	// - decoded JWS headers such as "kid" (sender's keyID), "alg" (signature algorithm) and "jwks" (JSON Web Key Set)
	// 	 which contains both sender's public signature JWK (first) and encryption JWK (second).
	JWE joseUtils.HeaderRequestJWE `json:"jwe,omitempty" bson:"jwe,omitempty"`
	JWS joseUtils.HeaderRequestJWS `json:"jws,omitempty" bson:"jws,omitempty"`
	// HTTP headers are not included because only Authorization Bearer and DPoP are relevant for the JAR Protocol
	// HTTP   httpUtils.HttpRequestHeaders `json:"http,omitempty" bson:"http,omitempty"`     // HTTP header fields (when sent by HTTP protocol).

}

// ErrorObject object MAY have the following members, and MUST contain at least one of:
// https://jsonapi.org/format/1.1/#error-objects
type ErrorObject struct {
	ID     *string                 `json:"id,omitempty" bson:"id,omitempty"`         // a unique identifier for this particular occurrence of the problem.
	Links  *[]JsonApiErrorLink     `json:"links,omitempty" bson:"links,omitempty"`   // a links object MAY contain about and type.
	Status *string                 `json:"status,omitempty" bson:"status,omitempty"` // the HTTP status code applicable to this problem, expressed as a string value. This SHOULD be provided.
	Code   *string                 `json:"code,omitempty" bson:"code,omitempty"`     // an application-specific error code, expressed as a string value.
	Title  *string                 `json:"title,omitempty" bson:"title,omitempty"`   // a short, human-readable summary of the problem that SHOULD NOT change from occurrence to occurrence of the problem, except for purposes of localization.
	Detail *string                 `json:"detail,omitempty" bson:"detail,omitempty"` // a human-readable explanation specific to this occurrence of the problem. Like title, this field’s value can be localized.
	Source *JsonApiErrorSource     `json:"source,omitempty" bson:"source,omitempty"` // an object containing references to the primary source of the error. It SHOULD include one of the following members or be omitted:
	Meta   *map[string]interface{} `json:"meta,omitempty" bson:"meta,omitempty"`     // a metaObject containing non-standard meta-information about the error.
}

// JsonApiErrorSource SHOULD include one of pointer, parameter or header
type JsonApiErrorSource struct {
	Pointer   *string `json:"pointer,omitempty" bson:"pointer,omitempty"`     // a JSON Pointer [RFC6901] to the value in the request document that caused the error [e.g. "/data" for a primary data object, or "/data/attributes/title" for a specific attribute]. This MUST point to a value in the request document that exists; if it does not, the client SHOULD simply ignore the pointer.
	Parameter *string `json:"parameter,omitempty" bson:"parameter,omitempty"` // a string indicating which URI query parameter caused the error.
	Header    *string `json:"header,omitempty" bson:"header,omitempty"`       // a string indicating the name of a single request header which caused the error.
}

// JsonApiErrorLink object MAY contain the following members:
// - about: a link that leads to further details about this particular occurrence of the problem. When dereferenced, this URI SHOULD return a human-readable description of the error.
// - type: a link that identifies the type of error that this particular error is an instance of. This URI SHOULD be dereferenceable to a human-readable explanation of the general error.
type JsonApiErrorLink struct {
	About string `json:"about,omitempty" bson:"about,omitempty"` // about: a link that leads to further details about this particular occurrence of the problem. When dereferenced, this URI SHOULD return a human-readable description of the error.
	Type  string `json:"type,omitempty" bson:"type,omitempty"`   // type: a link that identifies the type of error that this particular error is an instance of. This URI SHOULD be dereferenceable to a human-readable explanation of the general error.
}
