package didCommunicationUtils

// DIDCommV2IssueCredentialBody is part of the Issuer Credential DIDComm message:
// -replacement_id: an optional field that provides an identifier used to manage credential replacement.
//	When this value is present and matches the replacement_id of a previously issued credential,
//	this credential may be considered as a replacement for that credential.
//	This value is unique to the issuer. It must not be used in a credential presentation.
// -comment: an optional field that provides human readable information about the issued credential, so it can be evaluated by human judgment. Follows DIDComm conventions for l10n.
// -goal_code: optional field that indicates the goal of the message.
// https://github.com/decentralized-identity/waci-presentation-exchange/blob/main/issue_credential/README.md
type DIDCommV2IssueCredentialBody struct {
	ReplacementID *string `json:"replacement_id,omitempty" bson:"replacement_id,omitempty"` // identifier used to manage credential replacement
	Comment       *string `json:"comment,omitempty" bson:"comment,omitempty"`               // human-readable information about the issued credential, so it can be evaluated by human judgment. Follows DIDComm conventions for l10n.
	GoalCode      *string `json:"goal_code,omitempty" bson:"goal_code,omitempty"`           // goal of the message
}

/* Example:
{
  "type": "https://didcomm.org/issue-credential/%VER/issue-credential",
  "id": "<uuid of issue message>",
  "body": { // the DIDCommV2IssueCredentialBody
    "goal_code": "<goal-code>",
    "replacement_id": "<issuer unique id>",
    "comment": "some comment"
  },
  "attachments": [
    {
      "id": "<attachment identifier>",
      "mime-type": "application/json",
      "format": "<format-and-version>",
      "data": {
        "json": "<json>"
      }
    }
  ]
}
*/

// DIDCommV2OfferCredentialBody is part of the  Offer Credential DIDComm message
// A message sent by the Issuer to the potential Holder, describing the credential they intend to offer and possibly the price they expect to be paid.
// -credential_preview: a JSON-LD object that represents the credential data that Issuer is willing to issue. It matches the schema of Credential Preview;
// -replacement_id: an optional field that provides an identifier used to manage credential replacement.
//	When this value is present and matches the replacement_id of a previously issued credential,
//	this credential may be considered as a replacement for that credential.
//	This value is unique to the issuer. It must not be used in a credential presentation.
// -comment: an optional field that provides human readable information about the issued credential, so it can be evaluated by human judgment. Follows DIDComm conventions for l10n.
// -goal_code: optional field that indicates the goal of the message.
// https://github.com/decentralized-identity/waci-presentation-exchange/blob/main/issue_credential/README.md
type DIDCommV2OfferCredentialBody struct {
	ReplacementID     *string            `json:"replacement_id,omitempty" bson:"replacement_id,omitempty"`         // identifier used to manage credential replacement
	Comment           *string            `json:"comment,omitempty" bson:"comment,omitempty"`                       // human-readable information about the issued credential, so it can be evaluated by human judgment. Follows DIDComm conventions for l10n.
	GoalCode          *string            `json:"goal_code,omitempty" bson:"goal_code,omitempty"`                   // goal of the message
	CredentialPreview *CredentialPreview `json:"credential_preview,omitempty" bson:"credential_preview,omitempty"` // credential data that Issuer is willing to issue. It matches the schema of Credential Preview;
}

type CredentialPreview struct {
	Attributes []CredentialAttribute `json:"attributes,omitempty" bson:"goattributesal_code,omitempty"` // an array of (object) attribute specifications
}

// CredentialAttribute has the attribute data of a credential's claim.
// It is used construct a preview of the data for the credential that is to be issued.
// Its schema follows:
// - 'name' (MANDATORY): key maps to the attribute name as a string.
// - 'mime-type' (Optional): advises the issuer how to render a binary attribute, to judge its content for applicability before issuing a credential containing it. Its value parses case-insensitively in keeping with MIME type semantics of RFC 2045. If mime-type is missing, its value is null.
// - 'value' (MANDATORY): holds the attribute value base64 encoded if mime-type or as a single string value if not.
//    if mime-type is missing (null), then value is a string. In other words, implementations interpret it the same as any other key+value pair in JSON.
//    if mime-type is not null, then value is always a base64url-encoded string that represents a binary BLOB, and mime-type tells how to interpret the BLOB after base64url-decoding.
type CredentialAttribute struct {
	Name     string `json:"name,omitempty" bson:"name,omitempty"`           // an array of (object) attribute specifications
	MimeType string `json:"mime-type,omitempty" bson:"mime-type,omitempty"` //
	Value    string `json:"value,omitempty" bson:"value,omitempty"`         //
}

/* Offer Credential DIDComm message example:
{
    "type": "https://didcomm.org/issue-credential/%VER/offer-credential",
    "id": "<uuid of offer message>",
    "body": {
        "goal_code": "<goal-code>",
        "comment": "some comment",
        "replacement_id": "<issuer unique id>",
        "credential_preview": {
			"attributes": [
      			{
					"name": "<attribute name>",
					"mime-type": "<type or nil>",
					"value": "<value base64 encoded or single value string>"
				}
				// more attributes
			]
		}
    },
    "attachments": [
        {
            "id": "<attachment identifier>",
            "mime-type": "application/json",
            "format": "<format-and-version>",
            "data": {
                "json": "<json>"
            }
        }
    ]
}
*/

// Payment flow
// A '~payment-request' may decorate a Credential Offer from Issuer to Holder
// When they do, a corresponding' ~payment-receipt' should be provided on the Credential Request returned to the Issuer.
// During credential presentation, the Verifier may pay the Holder as compensation for Holder for disclosing data.
// This would require a '~payment-request' in a Presentation Proposal message, and a corresponding '~payment-receipt' in the subsequent Presentation Request.
// If such a workflow begins with the Presentation Request, the Prover may sending back a Presentation (counter-)Proposal with appropriate decorator inside it.
