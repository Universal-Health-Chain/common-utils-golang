package didDocumentUtils

import (
	"strings"

)

// DidDetailsAudit contains additional data on the blockchain (can be duplicated on the local DB or not).
// Some DID parameters are completely independent of any specific DID method and function the same way for all DIDs.
// Other DID parameters are not supported by all DID methods: https://www.w3.org/TR/did-core/#did-parameters
//  - Txn and TxTime are non-standard parameters.
//  - Hl (HashLink) example: "did:example:123?hl=zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e"
//  - VersionTime: identifies a certain version timestamp of a DID document to be resolved.
//	The DID document was valid for a DID at a certain time.
//	This datetime value MUST be normalized to UTC 00:00:00 (seconds, without sub-second decimal precision).
// 	Example for VersionTime parameter request: "did:example:123?versionTime=2016-10-17T02:41:00Z"
type DidDetailsAudit struct {
	// JWKSet      jwkUtils.JWKeySet `json:"jwks,omitempty" bson:"jwks,omitempty"`
	Active      bool    `json:"active,omitempty" bson:"active,omitempty"`
	Hl          string  `json:"hl,omitempty" bson:"hl,omitempty"`                   // hash
	VersionId   string  `json:"versionId,omitempty" bson:"versionId,omitempty"`     // identifies a specific version of a DID document to be resolved (the version ID could be sequential, or a UUID, or method-specific).
	VersionTime string  `json:"versionTime,omitempty" bson:"versionTime,omitempty"` // identifies a certain version timestamp of a DID document to be resolved. The DID document was valid for a DID at a certain time. This datetime value MUST be normalized to UTC 00:00:00 and without sub-second decimal precision.
	Txn         *string `json:"txn,omitempty" bson:"txn,omitempty"`
	TxTime      *string `json:"txTime,omitempty" bson:"txTime,omitempty"`
}

// DidData is the DID resolution data: https://w3c-ccg.github.io/did-resolution/
// EBSIv2 DID resolution only returns the DID Document but not the metadata:
// https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/Verifiable+Credential+API+and+Library
type DidData struct {
	DidDocument           DidDoc                                `json:"didDocument,omitempty" bson:"didDocument,omitempty"`
	DidDocumentMetadata   DidDocumentMetadata                   `json:"didDocumentMetadata,omitempty" bson:"didDocumentMetadata,omitempty"`
	DidResolutionMetadata DidDetailsAudit `json:"didResolutionMetadata,omitempty" bson:"didResolutionMetadata,omitempty"`
}

func CheckDidDataAndSintax(didData *DidData, didBase, resourceType, identifierKind string) string {
	compareString := CreateDidPrefix(didBase, resourceType, identifierKind)
	if didData != nil {
		if strings.Contains(didData.DidDocument.ID, compareString) {
			return ""
		} else {
			return "invalid didDocument format"
		}
	} else {
		return "did document is invalid"
	}
}

// DidLocalStorage uses the JSON API structure where Attributes object represents some of the resource’s data.
// (see https://jsonapi.org/format/#document-resource-objects)
type DidLocalStorage struct {
	Attributes DidData `json:"attributes,omitempty" bson:"attributes,omitempty"`
}

/*
"didResolutionMetadata": {
	"content-type": "application/did+ld+json",
	"retrieved": "2024-06-01T19:73:24Z",
},
"didDocumentMetadata": {
	"created": "2019-03-23T06:35:22Z",
	"updated": "2023-08-10T13:40:06Z",
    }
*/

// DidDocumentMetadata contains additional data on the local DB
type DidDocumentMetadata struct { // extends DidUrlResolution / DidVersionDetailsOnBlockchain
	Deactivated bool    `json:"deactivated,omitempty" bson:"deactivated,omitempty"` // deactivation data will be the updated date.
	Created     string  `json:"created,omitempty" bson:"created,omitempty"`
	Updated     *string `json:"updated,omitempty" bson:"updated,omitempty"`
	VersionId   *string `json:"versionId,omitempty" bson:"versionId,omitempty"`
}

//
// 6.3 DID Resolution Metadata
// This is a metadata structure (see section Metadata Structure in [DID-CORE]) that contains metadata about the DID Resolution process.
// This metadata typically changes between invocations of the DID Resolution functions as it represents data about the resolution process itself.
// The source of this metadata is the DID resolver.
// Examples of DID Resolution Metadata include:
//    Media type of the returned content (the contentType metadata property).
//    Error code (the error metadata property).
//    Duration of the DID resolution process.
//    Caching information about the DID document (see Section 10.2 Caching).
//    Various URLs, IP addresses or other network information that was used during the DID resolution process.
//    Proofs added by a DID resolver (e.g. to establish trusted resolution).
// See also section DID Resolution Metadata in [DID-CORE].
//
// 6.4 DID Document Metadata
// This is a metadata structure (see section Metadata Structure in [DID-CORE]) that contains metadata about a DID Document.
// This metadata typically does not change between invocations of the DID Resolution function unless the DID document changes, as it represents data about the DID document.
// The sources of this metadata are the DID controller and/or the DID method.
// Examples of DID Document Metadata include:
//    Timestamps when the DID and its associated DID document were created or updated (the created and updated metadata properties).
//    Metadata about controllers, capabilities, delegations, etc.
//    Versioning information about the DID document (see Section 10.3 Versioning).
//    Proofs added by a DID controller (e.g. to establish control authority).
// DID Document Metadata may also include method-specific metadata, e.g.:
//    State proofs from the verifiable data registry.
//    Block number, index, transaction hash, number of confirmations, etc. of a record in the blockchain or other verifiable data registry.
// See also section DID Document Metadata in [DID-CORE].
// (https://www.w3.org/TR/did-core/#did-document-metadata)

/* Signing JWT with DID. A verification response is an object resembling:
{
  payload: {
    iat: 1571692448,
    exp: 1957463421,
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  didResolutionResult: {
    didDocumentMetadata: {},
    didResolutionMetadata: {},
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
      publicKey: [ [Object] ],
      authentication: [ [Object] ]
    }
  },
*/

// CHANGES:
// 1. Replacement of publicKeyBase58 with publicKeyMultibase to encode Raw binary data.
// Multibase is to differentiate one base-encoding from another: z (Base58), u (base64url)
// https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03#appendix-D.1
//
// 2. Use publicKeyJwk. It is a map representing a JSON Web Key that conforms to [RFC7517].
// The map MUST NOT contain "d", or any other members of the private information class as described in Registration Template.
// It is RECOMMENDED that verification methods that use JWKs [RFC7517]
// to represent their public keys use the value of kid as their fragment identifier.
// It is RECOMMENDED that JWK kid values are set to the public key fingerprint [RFC7638].
//

// To verify a change of DID controller, implementers are advised to authenticate
// the new DID controller against the verification methods in the revised DID document
// https://www.w3.org/TR/did-core/#did-controller

// DID datetime: A JSON String serialized as an XML Datetime normalized to UTC 00:00:00
// and without sub-second decimal precision (without miliseconds).
// For example: 2020-12-20T19:17:47Z

// 9.17 Level of Assurance (LOA): https://www.w3.org/TR/did-core/#level-of-assurance
// Level of assurance frameworks are classified and defined by regulations and standards
// such as eIDAS, NIST 800-63-3 and ISO/IEC 29115:2013, including their requirements for the security context,
// and making recommendations on how to achieve them.
// This might include strong user authentication where FIDO2/WebAuthn can fulfill the requirement.
//
// Whether and how to encode this information in the DID document data model is out of scope of the specification:
// 1) the information could be transmitted using Verifiable Credentials [VC-DATA-MODEL], and
// 2) the DID document data model can be extended to incorporate this information
//    as described in § 4.1 Extensibility, and where § 10. Privacy Considerations is applicable for such extensions.
//

/*
Verification Method properties
Property 	          Req? 	Value constraints
id                  yes 	A string that conforms to the rules in § 3.2 DID URL Syntax.
controller 	        yes 	A string that conforms to the rules in § 3.1 DID Syntax.
type 	              yes 	A string.
publicKeyJwk 	      no 	  A map representing a JSON Web Key that conforms to [RFC7517]. See definition of publicKeyJwk for additional constraints.
publicKeyMultibase  no 	  A string that conforms to a [MULTIBASE] encoded public key.

Service properties
Property 	        Req? 	Value constraints
id 	              yes 	A string that conforms to the rules of [RFC3986] for URIs.
type              yes 	A string or a set of strings.
serviceEndpoint   yes 	A string that conforms to the rules of [RFC3986] for URIs, a map, or a set composed of a one or more strings that conform to the rules of [RFC3986] for URIs and/or maps.
*/

//

//
// Interface describing the expected shape of a Decentralized Identity Document.
// https://www.w3.org/TR/did-core/#core-properties
//

// export interface DidDocument {

// The standard context for DID Documents if 'application/did+ld+json'
// but not for 'application/did+json'
// https://www.w3.org/TR/did-core/#representations
//
// '@context'?:  'https://w3id.org/did/v1'; // only for output, to be removed before storing on blockchain

// The DID to which this DID Document pertains.//
// id?: string; // only for output, to be removed before storing on blockchain

// Array of public keys associated with the DID.//
// publicKey?: DidDocumentPublicKey[];

// Array of services associated with the DID.//
// service?: DidDocumentServiceDescriptor[];

// Array of authentication methods.
// A set of either Verification Method maps that conform to the rules in § Verification Method properties
// or strings that conform to the rules in § 3.2 DID URL Syntax.
//
// authentication?: (string | object)[];

// A set of strings that conform to the rules of [RFC3986] for URIs.//
// alsoKnownAs?:         string[]; // not for DLT

// A string or a set of strings that conform to the rules in § 3.1 DID Syntax.//
// controller?: 	          any;

// A set of Verification Method maps that conform to the rules in § Verification Method properties.//
// verificationMethod?: 	  any;

// assertionMethod?: 	    any;
// keyAgreement?: 	        any;
// capabilityInvocation?:  DidDocumentPublicKey[];
// capabilityDelegation?:  DidDocumentPublicKey[];
// }

// DID URL dereferencer implementations will reference [DID-RESOLUTION] for additional implementation details.//
// export interface DidUrlResolution {
//
// versionTime identifies a certain version timestamp of a DID document to be resolved.
// That is, the DID document that was valid for a DID at a certain time.
// If present, the associated value MUST be an ASCII string which is a valid XML datetime value, as defined in section 3.3.7 of W3C XML Schema Definition Language (XSD) 1.1 Part 2: Datatypes [XMLSCHEMA11-2].
// This datetime value MUST be normalized to UTC 00:00:00 and without sub-second decimal precision.
// For example: 2020-12-20T19:17:47Z.
// (WITHOUT miliseconds)
//
// versionTime?: string;

// hl: A resource hash of the DID document to add integrity protection, as specified in [HASHLINK]. This parameter is non-normative.
// hl?:  string;

//
// A relative URI reference according to RFC3986 Section 4.2 that identifies a resource at a service endpoint,
// which is selected from a DID document by using the service parameter.
// If present, the associated value MUST be an ASCII string and MUST use percent-encoding for certain characters as specified in RFC3986 Section 2.1.
//
// relativeRef?: string;

//
// versionId identifies a specific version of a DID document to be resolved (the version ID could be sequential, or a UUID, or method-specific).
// If present, the associated value MUST be an ASCII string.
//
// versionId?: string;

// Identifies a service from the DID document by service ID. If present, the associated value MUST be an ASCII string//
// service
// }

//
// 7.1.3 - DID Document Metadata
//  The possible properties within this structure and their possible values
//  SHOULD be registered in the DID Specification Registries [DID-SPEC-REGISTRIES].
//  DID URL dereferencer implementations will reference [DID-RESOLUTION] for additional implementation details.
//  The specification defines the following common properties:
//
//  - created: DID document metadata SHOULD include a created property to indicate the timestamp of the Create operation.
//    The value of the property MUST be a string formatted as an XML Datetime normalized to UTC 00:00:00 and without sub-second decimal precision.
//    For example: 2020-12-20T19:17:47Z.
//
//  - updated: metadata SHOULD include an updated property to indicate the timestamp of the last Update operation for the document version which was resolved.
//    The value of the property MUST follow the same formatting rules as the created property.
//    The updated property is omitted if an Update operation has never been performed on the DID document.
//    If an updated property exists, it can be the same value as the created property when the difference between the two timestamps is less than one second.
//
//  - deactived: true or false (default). Deactivation data is the updated date.
//
//  - versionId: metadata SHOULD include a versionId property to indicate the version of the last Update operation for the document version which was resolved.
//    The value of the property MUST be an ASCII string.
//    It can be the Transaction ID in Base58 encoding when updating the DID Document.
//
//  - equivalentId: e.g. FHIR resource id?
//
//  - canonicalId: is identical to the equivalentId property except:
//    - a) it is associated with a single value rather than a set, and
//    - b) the DID is defined to be the canonical ID for the DID subject within the scope of the containing DID document.
//
// export interface MetaDidDocument extends DidUrlResolution {
// created?:       string;
// updated?:       string;
// deactivated?:   boolean;  // deactivation data will be the updated date.
// versionId?:     string;
// nextUpdate?:    string;
// nextVersionId?: string;
// equivalentId?:  string;
// canonicalId?:   string;
// }

/*
function CheckDidDocumentID(didData)

didData["didDocument"] is required
didData["didDocument"] has the "id" property and has as prefix the organization DID
*/

func CreateDidPrefix(didBase, resourceType, identifierKind string) string {
	return didBase + ":" + resourceType + ":" + identifierKind + ":"
}

func CheckDidSintax(did, didBase, resourceType, identifierKind string) string {
	compareString := CreateDidPrefix(didBase, resourceType, identifierKind)
	if did != "" {
		if strings.Contains(did, compareString) {
			return ""
		} else {
			return "invalid didDocument format"
		}
	} else {
		return "did document is invalid"
	}
}
