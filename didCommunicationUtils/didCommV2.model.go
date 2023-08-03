package didCommunicationUtils

import (
	"encoding/json"
	"time"
)

// ** DIDCommV2 is an JWM (JSON Web Messages) which can_hide its content from all but authorized recipients if encrypted,
// *  disclose and prove the sender to exactly and only those recipients, and provide integrity guarantees.
// *  https://github.com/decentralized-identity/didcomm-messaging/blob/master/docs/spec-files/message_structure.md
// *
// *  The body of a DIDComm message is the JSON 'body' object into a JWM message.
// *
// *  Headers in DIDComm Messaging are intended to be extensible in much the same way that headers in HttpHeaders or SMTP are extensible.
// *  A few headers are predefined:
// *  - attachments: OPTIONAL. See attachments.
// *  - body: REQUIRED. The body attribute contains all the message type specific attributes of the message type indicated in the type attribute. This attribute MUST be present, even if empty. It MUST be a JSON object conforming to RFC 7159.
// *  - id: REQUIRED. Message ID. The id attribute value MUST be unique to the sender.
// *  - type: REQUIRED. Plaintext message type ('<message-type-uri>'), useful for message handling in application-level protocols. The type attribute value MUST be a valid Message Type URI, that when resolved gives human readable information about the message. The attribute's value SHOULD predict the content in the body of the message.
// *  - typ: OPTIONAL. Media type of the JWM content (application/didCommunicationUtils-encrypted+json, application/didCommunicationUtils-signed+json OR application/didCommunicationUtils-plain+json).
// *  - from: OPTIONAL: when the message is to be encrypted via anoncrypt. REQUIRED when the message is encrypted via authcrypt. Sender identifier. The from attribute MUST be a string that is a valid DID or DID URL (without the fragment component) which identifies the sender of the message. When a message is encrypted, the sender key MUST be authorized for encryption by this DID. Authorization of the encryption key for this DID MUST be verified by message recipient with the proper proof purposes. When the sender wishes to be anonymous using authcrypt, it is recommended to use a new DID created for the purpose to avoid correlation with any other behavior or identity. Peer DIDs are lightweight and require no ledger writes, and therefore a good method to use for this purpose. See the message authentication section for additional details.
// *  - to: OPTIONAL. Identifier(s) for recipients. MUST be an array of strings where each element is a valid DID or DID URL (without the fragment component) that identifies a member of the message's intended audience. These values are useful for recipients to know which of their keys can be used for decryption. It is not possible for one recipient to verify that the message was sent to a different recipient.
// *  - thid: OPTIONAL: Thread identifier. Uniquely identifies the thread that the message belongs to. If not included, the id property of the message MUST be treated as the value of the thid.
// *  - pthid: OPTIONAL. Parent thread identifier. If the message is a child of a thread the pthid will uniquely identify which thread is the parent.
// *  - created_time: OPTIONAL. Message Created Time. The created_time attribute is used for the sender to express when they created the message, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute is informative to the recipient, and may be relied on by protocols.
// *  - expires_time: OPTIONAL. Message Expired Time. The expires_time attribute is used for the sender to express when they consider the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute signals when the message is considered no longer valid by the sender. When omitted, the message is considered to have no expiration by the sender.
type DIDCommV2 struct {
	Attachments    []AttachmentV2         `json:"attachments,omitempty" bson:"attachments,omitempty"`   // OPTIONAL. See Attachments for detail. *[]DIDCommAttachment
	Body           map[string]interface{} `json:"body,omitempty" bson:"body,omitempty"`                 // REQUIRED. The body attribute contains all the message type specific attributes of the message type indicated in the type attribute. This attribute MUST be present, even if empty. It MUST be a JSON object conforming to RFC 7159.
	CreatedTime    *string                `json:"created_time,omitempty" bson:"created_time,omitempty"` // OPTIONAL. Message Created Time. The created_time attribute is used for the sender to express when they created the message, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute is informative to the recipient, and may be relied on by protocols.
	ExpiresTime    *string                `json:"expires_time,omitempty" bson:"expires_time,omitempty"` // OPTIONAL. Message Expired Time. The expires_time attribute is used for the sender to express when they consider the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC) [link](1970-01-01T00:00:00Z UTC). This attribute signals when the message is considered no longer valid by the sender. When omitted, the message is considered to have no expiration by the sender.
	From           *string                `json:"from,omitempty" bson:"from,omitempty"`                 // OPTIONAL: when the message is to be encrypted via anoncrypt. REQUIRED when the message is encrypted via authcrypt. Sender identifier. The from attribute MUST be a string that is a valid DID or DID URL (without the fragment component) which identifies the sender of the message. When a message is encrypted, the sender key MUST be authorized for encryption by this DID. Authorization of the encryption key for this DID MUST be verified by message recipient with the proper proof purposes. When the sender wishes to be anonymous using authcrypt, it is recommended to use a new DID created for the purpose to avoid correlation with any other behavior or identity. Peer DIDs are lightweight and require no ledger writes, and therefore a good method to use for this purpose. See the message authentication section for additional details.
	ID             *string                `json:"id,omitempty" bson:"id,omitempty"`                     // REQUIRED. Message ID. The id attribute value MUST be unique to the sender.
	To             *[]string              `json:"to,omitempty" bson:"to,omitempty"`                     // OPTIONAL. Identifier(s) for recipients. MUST be an array of strings where each element is a valid DID or DID URL (without the fragment component) that identifies a member of the message's intended audience. These values are useful for recipients to know which of their keys can be used for decryption. It is not possible for one recipient to verify that the message was sent to a different recipient.
	Type           string                 `json:"type,omitempty" bson:"type,omitempty"`                 // REQUIRED. Plaintext message type ('<message-type-uri>'), useful for message handling in application-level protocols. The type attribute value MUST be a valid Message Type URI, that when resolved gives human readable information about the message. The attribute's value SHOULD predict the content in the body of the message.
	ParentThreadID *string                `json:"pthid,omitempty" bson:"pthid,omitempty"`               // OPTIONAL. Parent thread identifier. If the message is a child of a thread the pthid will uniquely identify which thread is the parent.
	ThreadID       *string                `json:"thid,omitempty" bson:"thid,omitempty"`                 // OPTIONAL: Thread identifier. Uniquely identifies the thread that the message belongs to. If not included, the id property of the message MUST be treated as the value of the thid.
}

// AttachmentData contains attachment payload.
type AttachmentData struct {
	// Sha256 is a hash of the content. Optional. Used as an integrity check if content is inlined.
	// if content is only referenced, then including this field makes the content tamper-evident.
	// This may be redundant, if the content is stored in an inherently immutable container like
	// content-addressable storage. This may also be undesirable, if dynamic content at a specified
	// link is beneficial. Including a hash without including a way to fetch the content via link
	// is a form of proof of existence.
	Sha256 string `json:"sha256,omitempty"`
	// Links is a list of zero or more locations at which the content may be fetched.
	Links []string `json:"links,omitempty"`
	// Base64 encoded data, when representing arbitrary content inline instead of via links. Optional.
	Base64 string `json:"base64,omitempty"`
	// JSON is a directly embedded JSON data, when representing content inline instead of via links,
	// and when the content is natively conveyable as JSON. Optional.
	JSON interface{} `json:"json,omitempty"`
	// JWS is a JSON web signature over the encoded data, in detached format.
	JWS json.RawMessage `json:"jws,omitempty"`
}

// AttachmentV2 is intended to provide the possibility to include files, links or even JSON payload to the message.
// To find out more please visit https://identity.foundation/didcomm-messaging/spec/#attachments
type AttachmentV2 struct {
	// ID is a JSON-LD construct that uniquely identifies attached content within the scope of a given message.
	// Recommended on appended attachment descriptors. Possible but generally unused on embedded attachment descriptors.
	// Never required if no references to the attachment exist; if omitted, then there is no way
	// to refer to the attachment later in the thread, in error messages, and so forth.
	// Because @id is used to compose URIs, it is recommended that this name be brief and avoid spaces
	// and other characters that require URI escaping.
	ID string `json:"id,omitempty"`
	// Description is an optional human-readable description of the content.
	Description string `json:"description,omitempty"`
	// FileName is a hint about the name that might be used if this attachment is persisted as a file.
	// It is not required, and need not be unique. If this field is present and mime-type is not,
	// the extension on the filename may be used to infer a MIME type.
	FileName string `json:"filename,omitempty"`
	// MediaType describes the MIME type of the attached content. Optional but recommended.
	MediaType string `json:"media_type,omitempty"`
	// LastModTime is a hint about when the content in this attachment was last modified.
	LastModTime time.Time `json:"lastmod_time,omitempty"`
	// ByteCount is an optional, and mostly relevant when content is included by reference instead of by value.
	// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage, to fully fetch the attachment.
	ByteCount int64 `json:"byte_count,omitempty"`
	// Data is a JSON object that gives access to the actual content of the attachment.
	Data AttachmentData `json:"data,omitempty"`
	// Format describes the format of the attachment if the media_type is not sufficient.
	Format string `json:"format,omitempty"`
}
