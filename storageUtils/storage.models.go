package storageUtils

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"encoding/json"

	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// Query represents an incoming vault query.
// See https://identity.foundation/edv-spec/#searching-encrypted-documents for more info.
// An empty attribute value is treated as a wildcard, whereby any attribute value for that attribute name can be
// matched (similar to a "has" query - but the spec doesn't have a way to do this for more complex queries yet).
// ReturnFullDocuments is optional and can only be used if the "ReturnFullDocumentsOnQuery" extension is enabled.
type Query struct {
	ReturnFullDocuments bool                `json:"returnFullDocuments"`
	Index               string              `json:"index"`
	Equals              []map[string]string `json:"equals"`
	Has                 string              `json:"has"`
}

// StructuredDocument is an unencrypted JSON (structured) Document.
// EncryptedDocument represents an Encrypted Document in a Secure Storage.
type EncryptedDocument struct {
	ID                          string                              `json:"id,omitempty"`
	Sequence                    uint64                              `json:"sequence,omitempty"`
	IndexedAttributeCollections []models.IndexedAttributeCollection `json:"indexed,omitempty"`
	JWE                         json.RawMessage                     `json:"jwe,omitempty"`
	// VaultID is just used internally for storing to MongoDB.
	// It's always removed before returning data to a client.
	VaultID string `json:"vaultID,omitempty"`
}

// Note: If the data is greather than the chunk size, the data is sharded into chunks by the client app,
// and each chunk is encrypted and sent to the server.
// In this case, content contains a manifest-like listing of URIs to individual chunks (integrity-protected by [HASHLINK]).

// IndexedAttributeCollection represents a collection of indexed attributes, all of which share a common MAC algorithm and key.
// This format is based on https://identity.foundation/confidential-storage/#creating-encrypted-indexes.
// Encrypted indexes can be created and used to perform efficient searching
// while protecting the privacy of entities that are storing information in the data vault.
// When creating an encrypted resource, blinded index properties MAY be used to perform efficient searches.

// IndexedAttribute represents a single indexed attribute.

// IDTypePair represents an ID+type pair.

// Batch represents a batch of operations to be performed in a vault.
type Batch []VaultOperation

const (
	// UpsertDocumentVaultOperation represents an upsert operation to be performed in a batch.
	UpsertDocumentVaultOperation = "upsert"
	// DeleteDocumentVaultOperation represents a delete operation to be performed in a batch.
	DeleteDocumentVaultOperation = "delete"
)

// VaultOperation represents an upsert or delete operation to be performed in a vault.
type VaultOperation struct {
	Operation         string            `json:"operation"`          // Valid values: upsert,delete
	DocumentID        string            `json:"id,omitempty"`       // Only used if Operation=delete
	EncryptedDocument EncryptedDocument `json:"document,omitempty"` // Only used if Operation=upsert
}

// JSONWebEncryption represents a JWE.
type JSONWebEncryption struct {
	B64ProtectedHeaders      string                 `json:"protected,omitempty"`
	UnprotectedHeaders       map[string]interface{} `json:"unprotected,omitempty"`
	Recipients               []Recipient            `json:"recipients,omitempty"`
	B64SingleRecipientEncKey string                 `json:"encrypted_key,omitempty"`
	SingleRecipientHeader    *RecipientHeaders      `json:"header,omitempty"`
	B64AAD                   string                 `json:"aad,omitempty"`
	B64IV                    string                 `json:"iv,omitempty"`
	B64Ciphertext            string                 `json:"ciphertext,omitempty"`
	B64Tag                   string                 `json:"tag,omitempty"`
}

// Recipient is a recipient of a JWE including the shared encryption key.
type Recipient struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EncryptedKey string            `json:"encrypted_key,omitempty"`
}

// RecipientHeaders are the recipient headers.
type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
	SPK json.RawMessage `json:"spk,omitempty"`
}
