package storageUtils

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// SecureStorage represents a secure storage in an Storage Provider.
//   - It's used for performing operations involving creation/instantiation of vaults (compartments).
//   - It wraps an Aries storage provider with additional functionality that's needed for EDV operations.
//
// (see github.com/hyperledger/aries-framework-go-ext/tree/main/component/storage/mongodb/store.go)
type SecureStorage interface {
	// CreateNewVault instantiates a new vault with the given dataVaultConfiguration
	CreateNewVault(vaultID string, dataVaultConfiguration *models.DataVaultConfiguration) error

	VaultExists(vaultID string) (bool, error)

	Put(vaultID string, documents ...EncryptedDocument) error

	// Get fetches a document from a vault.
	Get(vaultID, documentID string) ([]byte, error)

	// Delete deletes a document from a vault.
	Delete(vaultID, documentID string) error

	//  The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
	Query(vaultID string, query Query) ([]EncryptedDocument, error)
}
