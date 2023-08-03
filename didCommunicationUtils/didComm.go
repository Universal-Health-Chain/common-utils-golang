package didCommunicationUtils

// const OpenidDIDCommMimeType = "application/didcomm-plain+json"

// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml

const (
	ContentTypeDIDCommSignedJSON    = "didcomm-signed+json"    // DIDComm specification, but the HTTP Content-type will be "uhc-didcomm.api+json" as per the JSON:API specification.
	ContentTypeDIDCommEncryptedCBOR = "didcomm-encrypted+cbor" // (see CBOR RFC 8949, section 9.5: https://www.rfc-editor.org/rfc/rfc8949#section-9.5)
	CodeChallengeMethod             = "S256"
	HeaderTypeJWT                   = "jwt" // TODO: what if it is CBOR encoded?
	PayloadTypeNewProfileCode       = "profile-code+jwt"
	PayloadTypeLoginCode            = "login-code+jwt"
	PayloadTypeProfileTokenDCR      = "dcr-token+jwt"
	PayloadTypeData                 = "data+jwt"
	ResponseModeJWT                 = "jwt"
	ResponseModeQueryJWT            = "query.jwt"
	ResponseModeFragmentJWT         = "fragment.jwt"
	ResponseModeFormPostJWT         = "form_post.jwt"
	ResponseTypeCODE                = "code"
	ResponseTypeIDTOKEN             = "id_token"
	ResponseTypeAccessTOKEN         = "token"
	ResponseTypeDATA                = "data"
	ScopeOpenidGeneric              = "openid"
)

var (
	ErrCodeRequestInvalid = `invalid code request`
)

var (
	Encrypted = "application/didCommunicationUtils-encrypted+json" // for Authcrypted and/or anoncrypted, also for Signed and anoncrypted.
	Signed    = "application/didCommunicationUtils-signed+json"
	Plaintext = "application/didCommunicationUtils-plain+json"
)

// A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) and hides its content from all but authorized recipients,
//  discloses and proves the sender to exactly and only those recipients, and provides integrity guarantees.
//  https://github.com/decentralized-identity/didcomm-messaging/blob/master/docs/spec-files/message_structure.md
//
//  The body of a DIDComm message is the JSON 'body' object into a JWM message.
//
//  Headers in DIDComm Messaging are intended to be extensible in much the same way that headers in HttpHeaders or SMTP are extensible.
//  A few headers are predefined:
//  - attachments: OPTIONAL. See attachments.
//  - body: REQUIRED. The body attribute contains all the message type specific attributes of the message type indicated in the type attribute. This attribute MUST be present, even if empty. It MUST be a JSON object conforming to RFC 7159.
//  - id: REQUIRED. Message ID. The id attribute value MUST be unique to the sender.
//  - type: REQUIRED. Plaintext message type ('<message-type-uri>'), useful for message handling in application-level protocols. The type attribute value MUST be a valid Message Type URI, that when resolved gives human readable information about the message. The attribute's value SHOULD predict the content in the body of the message.
//  - typ: OPTIONAL. Media type of the JWM content (application/didCommunicationUtils-encrypted+json, application/didCommunicationUtils-signed+json OR application/didCommunicationUtils-plain+json).
//  - from: OPTIONAL: when the message is to be encrypted via anoncrypt. REQUIRED when the message is encrypted via authcrypt. Sender identifier. The form attribute MUST be a string that is a valid DID or DID URL (without the fragment component) which identifies the sender of the message. When a message is encrypted, the sender key MUST be authorized for encryption by this DID. Authorization of the encryption key for this DID MUST be verified by message recipient with the proper proof purposes. When the sender wishes to be anonymous using authcrypt, it is recommended to use a new DID created for the purpose to avoid correlation with any other behavior or identity. Peer DIDs are lightweight and require no ledger writes, and therefore a good method to use for this purpose. See the message authentication section for additional details.
//  - to: OPTIONAL. Identifier(s) for recipients. MUST be an array of strings where each element is a valid DID or DID URL (without the fragment component) that identifies a member of the message's intended audience. These values are useful for recipients to know which of their keys can be used for decryption. It is not possible for one recipient to verify that the message was sent to a different recipient.
//  - thid: OPTIONAL: Thread identifier. Uniquely identifies the thread that the message belongs to. If not included, the id property of the message MUST be treated as the value of the thid.
//  - pthid: OPTIONAL. Parent thread identifier. If the message is a child of a thread the pthid will uniquely identify which thread is the parent.
//  - created_time: OPTIONAL. Message Created Time. The created_time attribute is used for the sender to express when they created the message, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute is informative to the recipient, and may be relied on by protocols.
//  - expires_time: OPTIONAL. Message Expired Time. The expires_time attribute is used for the sender to express when they consider the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute signals when the message is considered no longer valid by the sender. When omitted, the message is considered to have no expiration by the sender.

// - DIDComm attachments are deliberately used in messages to isolate the protocol flow/semantics
//	 from the credential artifacts themselves as separate constructs.
// - The attachment items in the messages are arrays.
// - The arrays are provided to support the issuing of different credential formats (e.g. ZKP, JSON-LD JWT, or other)
//	 containing the same data (claims).
// - The arrays are not to be used for issuing credentials with different claims.
//	 (see https://github.com/decentralized-identity/waci-presentation-exchange/blob/main/issue_credential/README.md)

/** Minimize VC for JWT
if minimizeVC {
	vcCopy := *vc
	vcCopy.Expired = nil
	vcCopy.Issuer.ID = ""
	vcCopy.Issued = nil
	vcCopy.ID = ""
*/

// A JWT with a VC for blockchain notarization has:
// - "iss" instead of "vc.issuer"
// - "nbf" instead of "vc.validFrom"
// - "exp" instead of "vc.validUntil"
// - "sub" instead of "vc.subject"
// - "jti" instead of "vc.id"
// - "iat" instead of "vc.issued" (the transaction timestamp)
// - "txn" is the transaction ID
// - "cnf" is the creator's JWK
// - "did" is an object containing the DID "doc" with the controllers and the DID "meta"
