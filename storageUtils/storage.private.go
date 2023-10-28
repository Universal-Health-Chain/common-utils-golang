package storageUtils

// ** Based on: https://github.com/trustbloc/edv/blob/main/pkg/edvprovider/edvprovider.go **
// Copyright SecureKey Technologies Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import (
	"encoding/json"
	"errors"
	"fmt"

	ariesStorageMongodb "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesStorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
	"go.mongodb.org/mongo-driver/bson"
	mongodriver "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

// PrivateStorage is used for performing operations involving creation/instantiation of vaults (compartments).
// It contains the stores for "documents" and "config" (vaults created).
type PrivateStorage struct {
	alternateName     string
	configStore       ariesStorage.Store
	documentsStore    ariesStorage.Store
	retrievalPageSize uint
}

// Get the alternate name for this private storage
func (p *PrivateStorage) GetAlternateName() string {
	return p.alternateName
}

// Set the alternate name for this private storage
func (p *PrivateStorage) SetAlternateName(alternateName string) bool {
	p.alternateName = alternateName
	return true
}

// CreateNewVault instantiates a new vault with the given dataVaultConfiguration
func (p *PrivateStorage) CreateNewVault(vaultID string, dataVaultConfiguration *models.DataVaultConfiguration) error {
	if p == nil || p.configStore == nil {
		return fmt.Errorf("error with config store")
	}

	// check if is mongodb
	mongoStorage, ok := p.configStore.(*ariesStorageMongodb.Store)
	if ok {
		err := mongoStorage.PutAsJSON(vaultID, dataVaultConfiguration)
		if err != nil {
			return fmt.Errorf("messages.StoreVaultConfigFailure")
		}

		return nil
	}

	// in case of mem or couchdb
	configBytes, err := json.Marshal(dataVaultConfiguration)
	if err != nil {
		return fmt.Errorf("messages.FailToMarshalConfig")
	}

	err = p.configStore.Put(vaultID, configBytes)
	if err != nil {
		return fmt.Errorf("messages.StoreVaultConfigFailure")
	}

	return nil

}

// VaultExists tells you whether the given vault already exists.
func (p *PrivateStorage) VaultExists(vaultID string) (bool, error) {
	_, err := p.configStore.Get(vaultID)
	if err != nil {
		if errors.Is(err, ariesStorage.ErrDataNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error while checking for vault configuration: %w", err)
	}

	return true, nil
}

// Put stores the given documents into a vault, creating or updating them as needed.
// TODO (#236): Support "unique" option on attribute pair.
func (p *PrivateStorage) Put(vaultID string, documents ...EncryptedDocument) error {
	mongoDBStore, ok := p.documentsStore.(*ariesStorageMongodb.Store)
	if ok {
		return StoreDocumentsForMongoDB(vaultID, documents, mongoDBStore)
	}

	operations := make([]ariesStorage.Operation, len(documents))

	for i := 0; i < len(documents); i++ {
		documentBytes, errMarshal := json.Marshal(documents[i])
		if errMarshal != nil {
			return fmt.Errorf("failed to marshal encrypted document %s: %w",
				documents[i].ID, errMarshal)
		}

		operations[i].Key = GenerateAriesDocumentEntryKey(vaultID, documents[i].ID)
		operations[i].Value = documentBytes
		operations[i].Tags = CreateTags(vaultID, documents[i])
	}

	err := p.documentsStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to store encrypted document(s): %w", err)
	}

	return nil
}

// Get fetches a document from a vault.
func (p *PrivateStorage) Get(vaultID, documentID string) ([]byte, error) {
	mongoDBStore, ok := p.documentsStore.(*ariesStorageMongodb.Store)
	if ok {
		return p.getFromMongoDB(mongoDBStore, vaultID, documentID)
	}

	return p.documentsStore.Get(GenerateAriesDocumentEntryKey(vaultID, documentID))
}

// Delete deletes a document from a vault.
func (p *PrivateStorage) Delete(vaultID, documentID string) error {
	mongoDBStore, ok := p.documentsStore.(*ariesStorageMongodb.Store)
	if ok {
		filter := bson.M{DocumentIDFieldName: documentID, VaultIDTagName: vaultID}

		writeModel := mongodriver.NewDeleteOneModel().SetFilter(filter)

		return mongoDBStore.BulkWrite([]mongodriver.WriteModel{writeModel})
	}

	return p.documentsStore.Delete(GenerateAriesDocumentEntryKey(vaultID, documentID))
}

// Query queries for data based on Encrypted Document attributes.
// TODO (#168): Add support for pagination (not currently in the spec).
//
//	The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
func (p *PrivateStorage) Query(vaultID string, query Query) ([]EncryptedDocument, error) {
	mongoDBStore, ok := p.documentsStore.(*ariesStorageMongodb.Store)
	if ok {
		return p.queryFromMongoDB(mongoDBStore, vaultID, query)
	}

	ariesQuery, err := ConvertEDVQueryToAriesQuery(query)
	if err != nil {
		return nil, err
	}

	return p.queryForEncryptedDocumentsFromAries(vaultID, ariesQuery)
}

func (p *PrivateStorage) queryForEncryptedDocumentsFromAries(vaultID, ariesQuery string) ([]EncryptedDocument, error) {
	iterator, err := p.documentsStore.Query(ariesQuery, ariesStorage.WithPageSize(int(p.retrievalPageSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	defer ariesStorage.Close(iterator, nil) // logger

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	var encryptedDocuments []EncryptedDocument

	for moreEntries {
		isForCorrectVault, err := VaultIDTagMatches(vaultID, iterator)
		if err != nil {
			return nil, err
		}

		if isForCorrectVault {
			encryptedDocumentBytes, valueErr := iterator.Value()
			if valueErr != nil {
				return nil, valueErr
			}

			var encryptedDocument EncryptedDocument

			err = json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal encrypted document bytes: %w", err)
			}

			encryptedDocuments = append(encryptedDocuments, encryptedDocument)
		}

		moreEntries, err = iterator.Next()
		if err != nil {
			return nil, err
		}
	}

	return encryptedDocuments, nil
}

func (p *PrivateStorage) queryFromMongoDB(store *ariesStorageMongodb.Store, vaultID string, query Query) ([]EncryptedDocument, error) {
	mongoDBQuery := ConvertEDVQueryToMongoDBQuery(vaultID, query)

	return p.queryForEncryptedDocumentsFromMongoDB(store, mongoDBQuery)
}

func (p *PrivateStorage) queryForEncryptedDocumentsFromMongoDB(store *ariesStorageMongodb.Store, filter interface{}) ([]EncryptedDocument, error) {
	iterator, err := store.QueryCustom(filter, mongooptions.Find().SetBatchSize(int32(p.retrievalPageSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	defer ariesStorage.Close(iterator, nil) // logger

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	var encryptedDocuments []EncryptedDocument

	for moreEntries {
		mongoDBDocument, valueErr := iterator.ValueAsRawMap()
		if valueErr != nil {
			return nil, valueErr
		}

		encryptedDocumentBytes, err := json.Marshal(mongoDBDocument)
		if err != nil {
			return nil, err
		}

		var encryptedDocument EncryptedDocument

		err = json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal encrypted document bytes: %w", err)
		}

		// This field is just for internal use - remove it before sending to client since it's not a proper field
		// in an Encrypted Document.
		// encryptedDocument.VaultID = ""

		encryptedDocuments = append(encryptedDocuments, encryptedDocument)

		moreEntries, err = iterator.Next()
		if err != nil {
			return nil, err
		}
	}

	return encryptedDocuments, nil
}

func (p *PrivateStorage) getFromMongoDB(store *ariesStorageMongodb.Store, vaultID, documentID string) ([]byte, error) {
	filter := bson.D{
		{Key: DocumentIDFieldName, Value: documentID},
		{Key: VaultIDTagName, Value: vaultID},
	}

	documents, err := p.queryForEncryptedDocumentsFromMongoDB(store, filter)
	if err != nil {
		return nil, err
	}

	if len(documents) == 0 {
		return nil, ariesStorage.ErrDataNotFound
	}

	documentBytes, err := json.Marshal(documents[0])
	if err != nil {
		return nil, err
	}

	return documentBytes, nil
}
