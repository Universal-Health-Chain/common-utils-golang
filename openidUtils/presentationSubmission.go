package openidUtils

// Federated OpenID device-local mode: https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-07.html
// For every authentication request, the native user experience first checks whether this request can be fulfilled
// using the locally stored credentials. If so, it generates a presentation signed with the user's keys
// in order to prevent replay of the credential.This approach dramatically reduces latency
// and reduces load on the OP's servers. Moreover, the user identification, authentication, and authorization
// can be done even in situations with unstable or no internet connectivity.

// Presentation Submission: https://identity.foundation/presentation-exchange/#presentation-submission
// 7.1 Submission Requirement Feature: introduces extensions enabling Verifiers to express what combinations of
// inputs must be submitted to comply with its requirements for proceeding in a flow
// (e.g. credential issuance, allowing entry, accepting an application).

// 7.2 Predicate Feature: introduces properties enabling Verifier to request that Holder apply a predicate and return the result.
// When using the 'predicate' Feature, the fields object MAY contain a predicate property.
// If the predicate property is present, the set of JSON Schema descriptors which comprise the
// value of the filter property MUST be restricted according to the desired predicate operation, as follows:
// To express the following range proofs, use the JSON Schema numeric range properties:
// - exclusiveMinimum: greater-than, e.g.: {"type": "number", "exclusiveMinimum": 10000}
// - exclusiveMaximum: less-than
// - minimum: greater-than or equal-to
// - maximum: less-than or equal-to
// - const: 'equal-to' or 'not equal-to', e.g.: { "const": "Karen"} or { "not": { "const": "Karen"}}
// - enum: 'not-in-set' or 'set-membership proofs' , e.g.: {"enum": ["red", "yellow", "blue"], "type": "string"} or {"not": {"enum": ["red", "yellow", "blue"]}

//PresentationSubmission are objects embedded within target Claim negotiation formats that express how the inputs presented as proofs to a Verifier are provided in accordance with the requirements specified in a Presentation Definition. Embedded Presentation Submission objects MUST be located within target data format as the value of a presentation_submission property, which is composed and embedded as follows:
//
//    The presentation_submission object MUST be included at the top-level of an Embed Target, or in the specific location described in the Embed Locations table in the Embed Target section below.
//    The presentation_submission object MUST contain an id property. The value of this property MUST be a unique identifier, such as a UUID.
//    The presentation_submission object MUST contain a definition_id property. The value of this property MUST be the id value of a valid Presentation Definition.
//    The presentation_submission object MUST include a descriptor_map property. The value of this property MUST be an array of Input Descriptor Mapping Objects.
type PresentationSubmission struct {
	ID            string              `json:"id,omitempty" bson:"id,omitempty"`
	DefinitionID  string              `json:"definition_id,omitempty" bson:"definition_id,omitempty"`
	DescriptorMap []DescriptorMapping `json:"descriptor_map,omitempty" bson:"descriptor_map,omitempty"`
}

// DescriptorMapping has
// - 'id' property. The value of this property MUST be a string that matches the id property of the Input Descriptor in the Presentation Definition that this Presentation Submission is related to.
// - 'format' property. The value of this property MUST be a string that matches one of the Claim Format Designation. This denotes the data format of the Claim.
// - 'path' property. The value of this property MUST be a JSONPath string expression. The path property indicates the Claim submitted in relation to the identified Input Descriptor, when executed against the top-level of the object the Presentation Submission is embedded within.
// - 'path_nested' object to indicate the presence of a multi-Claim envelope format. This means the Claim indicated is to be decoded separately from its parent enclosure.
//            The format of a path_nested object mirrors that of a descriptor_map property. The nesting may be any number of levels deep. The id property MUST be the same for each level of nesting.
//            The path property inside each path_nested property provides a relative path within a given nested value.
type DescriptorMapping struct {
	ID         string               `json:"id,omitempty" bson:"id,omitempty"`
	Format     string               `json:"format,omitempty" bson:"format,omitempty"`
	Path       string               `json:"path,omitempty" bson:"path,omitempty"`
	PathNested DescriptorMapNested1 `json:"path_nested,omitempty" bson:"path_nested,omitempty"`
}

type DescriptorMapNested1 struct {
	ID         string               `json:"id,omitempty" bson:"id,omitempty"`
	Format     string               `json:"format,omitempty" bson:"format,omitempty"`
	Path       string               `json:"path,omitempty" bson:"path,omitempty"`
	PathNested DescriptorMapNested2 `json:"path_nested,omitempty" bson:"path_nested,omitempty"`
}

type DescriptorMapNested2 struct {
	ID     string `json:"id,omitempty" bson:"id,omitempty"`
	Format string `json:"format,omitempty" bson:"format,omitempty"`
	Path   string `json:"path,omitempty" bson:"path,omitempty"`
	// PathNested DescriptorMapNested3 `json:"path_nested,omitempty" bson:"path_nested,omitempty"`
}

// 6. Processing of Submission Entries
// To process the Submission Entries of a Presentation Submission, use the following process:
//    1) For each Submission Entry in the descriptor_map array:
//       1.1) Execute the path field’s JSONPath expression string on the Current Traversal Object, or if none is designated, the top level of the Embed Target.
//       1.2) Decode and parse the value returned from JSONPath execution in accordance with the Claim Format Designation specified in the object’s format property.
//       1.3) If the value parses and validates in accordance with the Claim Format Designation specified, let the resulting object be the Current Traversal Object
//       1.4) If the path_nested property is present, process the Nested Submission Traversal Object value using the process described in Step 1.1?
//    2) If parsing of the Submission Entry (and any Nested Submission Traversal Objects present within it) produces a valid result, process it as the submission against the Input Descriptor indicated by the id property of the containing Input Descriptor Mapping Object.

// 7. Features
// Submission Requirement Feature
//
// The Submission Requirement Feature introduces extensions enabling Verifiers to express what combinations of inputs must be submitted to comply with its requirements for proceeding in a flow (e.g. credential issuance, allowing entry, accepting an application).
