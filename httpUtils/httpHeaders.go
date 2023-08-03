package httpUtils

// HttpResponseHeaders contains the HttpRequestHeaders Response Header Fields, see:
// - RFC7531 https://httpwg.org/specs/rfc7231.html#request.header.fields
// 	 and https://httpwg.org/specs/rfc7231.html#status.codes;
// - RFC9110 https://www.rfc-editor.org/rfc/rfc9110.html
//
// The response-header fields (case insensitive)
// - Accept-Ranges
// - Age
// - ETag
// - Location
// - Proxy-Authenticate
// - Status
// - Retry-After
// - Server
// - Status-Code: The status-code element is a three-digit integer code giving the result of the attempt to understand and satisfy the request (https://httpwg.org/specs/rfc7231.html#status.codes)
// - Vary
// - WWW-Authenticate: A server generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one challenge. A server MAY generate a WWW-Authenticate header field in other response messages to indicate that supplying credentials (or different credentials) might affect the response. (https://www.rfc-editor.org/rfc/rfc9110.html#field.www-authenticate)
type HttpResponseHeaders struct {
	StatusCode      int     `json:"status-code"`                // The status-code element is a three-digit integer code giving the result of the attempt to understand and satisfy the request
	WWWAuthenticate *string `json:"www-authenticate,omitempty"` // only required when bluetooth DIDComm messages
}

// HttpPrivateHeadersOpenid contains the HTTP Headers used in the OpenID protocol
// see https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Field_names
type HttpPrivateHeadersOpenid struct {
	// 5.3. Content Negotiation: fields are sent by a user agent to engage in proactive negotiation of the response content.
	// The preferences sent in these fields apply to any content in the response, including representations of the target resource, representations of error or processing status, and potentially even the miscellaneous text strings that might appear within the protocol.
	Accept string `json:"accept,omitempty" bson:"accept,omitempty"`

	// 5.4. Authentication Credentials
	Authorization string `json:"authorization,omitempty" bson:"authorization,omitempty"`

	// Representation headers: https://developer.mozilla.org/en-US/docs/Glossary/Representation_header
	ContentType string `json:"content-type,omitempty" bson:"content-type,omitempty"`

	// OpenID headers: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11
	DPoP string `json:"dpop,omitempty" bson:"dpop,omitempty"`
}

// HttpRequestHeaders contains the HTTP headers (to be sent in the body of a DIDComm message in bluetooth connections)
// See https://httpwg.org/specs/rfc7231.html#request.header.fields
// and https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
// Representation headers may be present in both HTTP request and response messages.
// Representation headers include: Content-Type, Content-Encoding, Content-Language, and Content-Location.
// (see https://developer.mozilla.org/en-US/docs/Glossary/Representation_header)
type HttpRequestHeaders struct {
	// 5.1. Controls: direct specific handling of the request.
	CacheControl *string `json:"cache-control,omitempty" bson:"cache-control,omitempty"`
	Expect       *string `json:"expect,omitempty" bson:"expect,omitempty"`
	Host         *string `json:"hostl,omitempty" bson:"host,omitempty"`
	MaxForwards  *string `json:"max-forwards,omitempty" bson:"max-forwards,omitempty"`
	Pragma       *string `json:"pragma,omitempty" bson:"pragma,omitempty"`
	Range        *string `json:"range,omitempty" bson:"range,omitempty"`
	TE           *string `json:"te-control,omitempty" bson:"te,omitempty"`

	// 5.2. Conditionals: allow a client to place a precondition on the state of the target resource,
	// so that the action corresponding to the method semantics will not be applied if the precondition evaluates to false.
	IfMatch           *string `json:"if-match,omitempty" bson:"if-match,omitempty"`
	IfNoneMatch       *string `json:"if-none-match,omitempty" bson:"if-none-match,omitempty"`
	IfModifiedSince   *string `json:"if-modified-since,omitempty" bson:"if-modified-since,omitempty"`
	IfUnmodifiedSince *string `json:"if-unmodified-since,omitempty" bson:"if-unmodified-since,omitempty"`
	IfRange           *string `json:"if-range,omitempty" bson:"if-range,omitempty"`

	// 5.3. Content Negotiation: fields are sent by a user agent to engage in proactive negotiation of the response content.
	// The preferences sent in these fields apply to any content in the response, including representations of the target resource, representations of error or processing status, and potentially even the miscellaneous text strings that might appear within the protocol.
	Accept         *string `json:"accept,omitempty" bson:"accept,omitempty"`
	AcceptCharset  *string `json:"accept-charset,omitempty" bson:"accept-charset,omitempty"`
	AcceptEncoding *string `json:"accept-encoding,omitempty" bson:"accept-encoding,omitempty"`
	AcceptLanguage *string `json:"accept-language,omitempty" bson:"accept_language,omitempty"`

	// 5.4. Authentication Credentials
	Authorization      *string `json:"authorization,omitempty" bson:"authorization,omitempty"`
	ProxyAuthorization *string `json:"proxy-authorization,omitempty" bson:"proxy-authorization,omitempty"`

	// 5.5. Request Context: provide additional information about the request context, including information about the user, user agent, and resource behind the request.
	From      *string `json:"from,omitempty" bson:"from,omitempty"`
	Referer   *string `json:"referer,omitempty" bson:"referer,omitempty"`
	UserAgent *string `json:"user-agent,omitempty" bson:"user-agent,omitempty"`

	// Representation headers: https://developer.mozilla.org/en-US/docs/Glossary/Representation_header
	ContentType     *string `json:"content-type,omitempty" bson:"content-type,omitempty"`
	ContentEncoding *string `json:"content-encoding,omitempty" bson:"content-encoding,omitempty"`
	ContentLanguage *string `json:"content-language,omitempty" bson:"content-language,omitempty"`
	ContentLocation *string `json:"content-location,omitempty" bson:"content-location,omitempty"`

	// Additional headers
	ECT           *string `json:"ect,omitempty" bson:"ect,omitempty"` //  effective connection type: slow-2g, 2g, 3g, 4g.
	Etag          *string `json:"etag,omitempty" bson:"etag,omitempty"`
	ContentLength *string `json:"content-length,omitempty" bson:"content-length,omitempty"`
	KeepAlive     *string `json:"keep-alive,omitempty" bson:"keep-alive,omitempty"`
	Via           *string `json:"via,omitempty" bson:"via,omitempty"`
	Vary          *string `json:"vary,omitempty" bson:"vary,omitempty"`

	// OpenID headers: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11
	DPoP *string `json:"dpop,omitempty" bson:"dpop,omitempty"`
	// IDToken       joseUtils.DataJWT `json:"id_token,omitempty" bson:"idToken,omitempty"`
	// ContentLength *string `json:"contentLength,omitempty" bson:"contentLength,omitempty"` // convert to number to check content size
}
