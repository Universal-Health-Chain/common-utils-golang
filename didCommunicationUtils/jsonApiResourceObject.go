package didCommunicationUtils

import (
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
)

// A ResourceObject MUST contain "attributes", "type" ("Department", "HealthcareService", "Office", "Employee", etc.)
// but also a DID ("didData.didDocument.id") and the created time
//   - attachments (Optional): additional data as DIDComm attachments
//   - attributes (Required): an attributes object representing some of the resource’s data.
//   - didData (Required): contains the DID at "didData.didDocument.id"
//   - id (Optional): CAUTION, it is an optional hashed ID from the blockchain, not a valid UUID or DID.
//   - meta (Optional): optional meta-information about a resource that can not be represented as an attribute or relationship.
//   - relationships: a relationships object describing relationships between the resource and other JSON:API resources.
//   - links: a links object containing links related to the resource.
//   - type (Required): internal resource type the request is about, e.g.: "Department", "HealthcareService", "Office", "Employee", "Profile", etc.
//   - fullURL (Optional): added from FHIR Bundle.Entry specification
//   - resource (Optional): added from FHIR Bundle.Entry specification
type ResourceObject struct {
	// using DIDComm attachments for the JSON:API resource
	Attachments   *[]AttachmentV2          `json:"attachments,omitempty" bson:"attachments,omitempty"`
	Attributes    map[string]interface{}   `json:"attributes,omitempty" bson:"attributes,omitempty"`
	DidData       didDocumentUtils.DidData `json:"didData,omitempty" bson:"didData,omitempty"`
	IdHashed      string                   `json:"id,omitempty" bson:"id,omitempty"` // CAUTION, it is a hashed ID from the blockchain, not a valid UUID or DID.
	Included      []map[string]interface{} `json:"included,omitempty" bson:"included,omitempty"`
	Meta          *map[string]interface{}  `json:"meta,omitempty" bson:"meta,omitempty"`
	Relationships *map[string]interface{}  `json:"relationships,omitempty" bson:"relationships,omitempty"`
	Request       *RequestData             `json:"request,omitempty" bson:"request,omitempty"`
	Type          string                   `json:"type,omitempty" bson:"type,omitempty"`         // internal resource type for the API
	FullURL       string                   `json:"fullUrl,omitempty" bson:"fullUrl,omitempty"`   // added from FHIR Bundle.Entry specification
	Resource      map[string]interface{}   `json:"resource,omitempty" bson:"resource,omitempty"` // added from FHIR Bundle.Entry specification
	// Links         interface{}            `json:"links,omitempty" bson:"links,omitempty"`
}

func (resourceObject *ResourceObject) GetDID() string {
	return resourceObject.DidData.DidDocument.ID
}

// FromJSON marshals the JSON data to bytes and then unmarshal the bytes to ResourceObject
func (resourceObject *ResourceObject) ExportToJSON() map[string]interface{} {
	// converting struct to JSON: first to bytes and then to map[string]interface{}
	dataJSON := map[string]interface{}{} // empty JSON
	dataBytes, err := json.Marshal(*resourceObject)
	if err != nil {
		return dataJSON
	}
	_ = json.Unmarshal(dataBytes, &dataJSON)

	// done!
	return dataJSON
}

// FromJSON marshals the JSON data to bytes and then unmarshal the bytes to ResourceObject
func (resourceObject *ResourceObject) FromJSON(dataJSON *map[string]interface{}) {
	// converting struct to ResourceObject: first to bytes and then to ResourceObject
	dataBytes, _ := json.Marshal(*dataJSON)

	resourceObject = &ResourceObject{}            // empty object but not nil, to avoid Unmarshal to fail
	_ = json.Unmarshal(dataBytes, resourceObject) // resourceObject is a pointer to a not nil object

	// done, if some error the resourceObject will be empty but not nil
}

type RequestData struct {
	Method string `json:"method,omitempty" bson:"method,omitempty"`
	URL    string `json:"url,omitempty" bson:"url,omitempty"`
}

/*
A “link object” is an object that represents a web link.

A link object MUST contain the following member:

	href: a string whose value is a URI-reference [RFC3986 Section 4.1] pointing to the link’s target.

A link object MAY also contain any of the following members:

	rel: a string indicating the link’s relation type. The string MUST be a valid link relation type.
	describedby: a link to a description document (e.g. OpenAPI or JSON Schema) for the link target.
	title: a string which serves as a label for the destination of a link such that it can be used as a human-readable identifier (e.g., a menu entry).
	type: a string indicating the media type of the link’s target.
	hreflang: a string or an array of strings indicating the language(s) of the link’s target. An array of strings indicates that the link’s target is available in multiple languages. Each string MUST be a valid language tag [RFC5646].
	meta: a metaObject containing non-standard meta-information about the link.

	Note: the type and hreflang members are only hints; the target resource is not guaranteed to be available in the indicated media type or language when the link is actually followed.
*/
type LinkObject struct {
}
