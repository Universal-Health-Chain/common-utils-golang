package storageUtils

// ** Based on: https://github.com/trustbloc/edv/blob/main/pkg/edvprovider/edvprovider.go **
// Copyright SecureKey Technologies Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import (
	"encoding/json"
	"fmt"

	// "github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"

	ariesStorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

// var logger = log.New("edv-rest")

// StorageService is used to contain several private storages and the self storage.
// It wraps an Aries storage provider with additional functionality.
// It contains the stores for "documents" and "config" (to set the vaults created).
type StorageService struct {
	storageProvider ariesStorage.Provider
	storageType     string
	selfStorage     PrivateStorage
	privateStorages []PrivateStorage
}

func NewStorageService(storageProvider ariesStorage.Provider) *StorageService {
	return &StorageService{
		storageProvider: storageProvider,
	}
}

// Get the alternate name for this storage service
func (s *StorageService) GetAlternateName() string {
	return s.selfStorage.GetAlternateName()
}

// Set the alternate name for this storage service
func (s *StorageService) SetAlternateName(alternateName string) bool {
	return s.selfStorage.SetAlternateName(alternateName)
}

// ** Methods for private storages **

func (s *StorageService) findPrivateStorageByAlternateName(alternateName string) (*PrivateStorage, error) {
	for _, privateStorage := range s.privateStorages {
		if privateStorage.GetAlternateName() == alternateName {
			return &privateStorage, nil
		}
	}
	return nil, fmt.Errorf("private storage with alternate name %s not found", alternateName)
}

func (s *StorageService) CreatePrivateStorage(
	alternateName string, configDatabaseName, documentDatabaseName string, retrievalPageSize uint,
) error {
	// No PrivateStorage exists before we create one
	// _, err := s.findPrivateStorageByAlternateName(alternateName)
	// if err != nil {
	// 	return err
	// }

	configStore, err := s.storageProvider.OpenStore(configDatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open configuration store: %w", err)
	}

	documentsStore, err := s.storageProvider.OpenStore(documentDatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open document store: %w", err)
	}

	privateStorage := PrivateStorage{
		configStore:       configStore,
		documentsStore:    documentsStore,
		retrievalPageSize: retrievalPageSize,
	}

	s.privateStorages = append(s.privateStorages, privateStorage)
	return nil
}

func (s *StorageService) CreateNewVaultInPrivateStorage(storageAlternateName string, vaultID string, dataVaultConfiguration *models.DataVaultConfiguration) error {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return err
	}

	return privateStorage.CreateNewVault(vaultID, dataVaultConfiguration)
}

func (s *StorageService) VaultExistsInPrivateStorage(storageAlternateName, vaultID string) (bool, error) {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return false, err
	}

	return privateStorage.VaultExists(vaultID)
}

func (s *StorageService) PutInPrivateStorage(storageAlternateName, vaultID string, documents ...EncryptedDocument) error {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return err
	}

	return privateStorage.Put(vaultID, documents...)
}

func (s *StorageService) GetFromPrivateStorage(storageAlternateName, vaultID, documentID string) ([]byte, error) {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return nil, err
	}

	return privateStorage.Get(vaultID, documentID)
}

func (s *StorageService) DeleteFromPrivateStorage(storageAlternateName, vaultID, documentID string) error {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return err
	}

	return privateStorage.Delete(vaultID, documentID)
}

func (s *StorageService) QueryPrivateStorage(storageAlternateName, vaultID string, query Query) ([]EncryptedDocument, error) {
	privateStorage, err := s.findPrivateStorageByAlternateName(storageAlternateName)
	if err != nil {
		return nil, err
	}

	return privateStorage.Query(vaultID, query)
}

// HostNewClient creates a Private Storage in the Storage Service and
// sets the client data in the "clients" vault of the Storage Service
func (s *StorageService) HostNewClient(protectedClientData []byte, alternateName string) (errMsg string) {
	vaultClients := "clients"
	configDatabaseName := alternateName + "_config"
	documentDatabaseName := alternateName + "_documents"
	retrievalPageSize := s.selfStorage.retrievalPageSize

	err := s.CreatePrivateStorage(alternateName, configDatabaseName, documentDatabaseName, retrievalPageSize)
	if err != nil {
		return fmt.Sprint(err.Error())
	}

	// Unmarshal the byte array into EncryptedDocument
	var encryptedDocument EncryptedDocument
	err = json.Unmarshal(protectedClientData, &encryptedDocument)
	if err != nil {
		return fmt.Sprintf("Failed to unmarshal the client data received: %s", err.Error())
	}

	// s.selfStorage is nil and this fails
	// return fmt.Sprint(s.selfStorage.Put(VaultClients, encryptedDocument))

	err = s.privateStorages[0].Put(vaultClients, encryptedDocument)
	if err != nil {
		return err.Error()
	}
	return ""
}

