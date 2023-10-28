package storageUtils

import (
	"fmt"
)

// CreatePrivateStorageInMemoryStorageService instantiates a new data storage in an Storage Provider.
// "retrievalPageSize" is used by ariesProvider for query paging,
// but it may be ignored if ariesProvider doesn't support paging.
func CreatePrivateStorageInMemoryStorageService(storageService StorageService,
	configDatabaseName, documentDatabaseName string, retrievalPageSize uint) (*PrivateStorage, error) {
	configStore, err := storageService.storageProvider.OpenStore(configDatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration store: %w", err)
	}

	documentsStore, err := storageService.storageProvider.OpenStore(documentDatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open document store: %w", err)
	}

	return &PrivateStorage{
		configStore:       configStore,
		documentsStore:    documentsStore,
		retrievalPageSize: retrievalPageSize,
	}, nil
}