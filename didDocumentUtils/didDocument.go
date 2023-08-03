package didDocumentUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
	"time"
)

// VerificationRelationship defines a verification relationship between DID subject and a verification method.
type VerificationRelationship int

const (
	// VerificationRelationshipGeneral is a special case of verification relationship: when a verification method
	// defined in Verification is not used by any Verification.
	VerificationRelationshipGeneral VerificationRelationship = iota

	// Authentication defines verification relationship.
	Authentication

	// AssertionMethod defines verification relationship.
	AssertionMethod

	// CapabilityDelegation defines verification relationship.
	CapabilityDelegation

	// CapabilityInvocation defines verification relationship.
	CapabilityInvocation

	// KeyAgreement defines verification relationship.
	KeyAgreement

	TypeVerificationJsonWebKey2020 = "JsonWebKey2020"
)

// DidDoc DID Document definition: https://www.w3.org/TR/did-core/#core-properties
// The Controller property is OPTIONAL. If present, the value MUST be a string or a set of strings that conform to the rules in § 3.1 DID Syntax.
type DidDoc struct {
	AlsoKnownAs          *[]string             `json:"alsoKnownAs,omitempty" bson:"alsoKnownAs,omitempty"`
	Context              []string              `json:"@context,omitempty" bson:"@context,omitempty"`
	Controller           *[]string             `json:"controller,omitempty" bson:"controller,omitempty"`
	ID                   string                `json:"id,omitempty" bson:"id,omitempty"`
	VerificationMethod   []VerificationMethod  `json:"verificationMethod,omitempty" bson:"verificationMethod,omitempty"`
	Service              []Service             `json:"service,omitempty" bson:"service,omitempty"`
	Authentication       *[]VerificationMethod `json:"authentication,omitempty" bson:"authentication,omitempty"`
	AssertionMethod      *[]VerificationMethod `json:"assertionMethod,omitempty" bson:"assertionMethod,omitempty"`
	CapabilityDelegation *[]VerificationMethod `json:"capabilityDelegation,omitempty" bson:"capabilityDelegation,omitempty"`
	CapabilityInvocation *[]VerificationMethod `json:"capabilityInvocation,omitempty" bson:"capabilityInvocation,omitempty"`
	KeyAgreement         *[]VerificationMethod `json:"keyAgreement,omitempty" bson:"keyAgreement,omitempty"`
	Created              *time.Time            `json:"created,omitempty" bson:"created,omitempty"`
	Updated              *time.Time            `json:"updated,omitempty" bson:"updated,omitempty"`
	Proof                []ProofGo             `json:"proof,omitempty" bson:"proof,omitempty"`
	// processingMeta       processingMeta
}

/*
// Verification authentication verification.
type Verification struct {
	VerificationMethod VerificationMethod
	Relationship       VerificationRelationship
	Embedded           bool
}
*/

// Service DID doc service.
type Service struct {
	ID              string                 `json:"id"` // profile-code-authorization
	Type            string                 `json:"type"`
	Priority        uint                   `json:"priority,omitempty"`
	RecipientKeys   []string               `json:"recipientKeys,omitempty"`
	RoutingKeys     []string               `json:"routingKeys,omitempty"`
	ServiceEndpoint string                 `json:"serviceEndpoint"`
	Accept          []string               `json:"accept,omitempty"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
}

// VerificationMethod DID doc verification method.
// The value of the verification method is defined either as raw public key bytes (Value field) or as JSON Web Key.
// In the first case the Type field can hold additional information to understand the nature of the raw public key.
type VerificationMethod struct {
	ID           string        `json:"id,omitempty" bson:"id,omitempty"`
	Type         string        `json:"type,omitempty" bson:"type,omitempty"`
	Controller   string        `json:"controller,omitempty" bson:"controller,omitempty"`
	PublicKeyJwk *jwkUtils.JWK `json:"publicKeyJwk,omitempty" bson:"publicKeyJwk,omitempty"`
}

// ProofGo is cryptographic proof of the integrity of the DID Document.
type ProofGo struct {
	Type         string
	Created      *time.Time
	Creator      string
	ProofValue   []byte
	Domain       string
	Nonce        []byte
	ProofPurpose string
	relativeURL  bool
}
