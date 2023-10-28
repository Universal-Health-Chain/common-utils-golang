package storageUtils

import (
	"fmt"
)

type StorageServicesManager struct {
	storageServices []*StorageService
}

func NewStorageServicesManager(alternateName string, params StorageParameters, databaseTimeout uint64) (*StorageServicesManager, error) {
	manager := &StorageServicesManager{}

	err := manager.CreateStorageService(alternateName, params, databaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("error creating storage service: %v", err)
	}
	return manager, nil
}

// CreateStorageService checks if the alternateName already exists in some selfStorage or privateStorages
func (m *StorageServicesManager) CreateStorageService(alternateName string, parameters StorageParameters, databaseTimeout uint64) error {
	for _, service := range m.storageServices {
		// Check if the alternateName exists in selfStorage
		if service.selfStorage.GetAlternateName() == alternateName {
			return fmt.Errorf("cannot create new storage service: the storage service with name %s already exists", alternateName)
		}
		// Check if the alternateName exists in any of the privateStorages
		for _, privateStorage := range service.privateStorages {
			if privateStorage.GetAlternateName() == alternateName {
				return fmt.Errorf("cannot create new storage service: the name %s already exists as private storage in the storage service with name %s", alternateName, service.selfStorage.GetAlternateName())
			}
		}
	}

	provider, err := NewStorageProvider(parameters, databaseTimeout)
	if err != nil {
		return err
	}

	newService := NewStorageService(provider)
	newService.selfStorage.SetAlternateName(alternateName)
	m.storageServices = append(m.storageServices, newService)

	return nil
}

func (m *StorageServicesManager) GetStorageServiceByAlternateName(alternateName string) (*StorageService, error) {
	for _, service := range m.storageServices {
		if service.selfStorage.GetAlternateName() == alternateName {
			return service, nil
		}
	}

	return nil, fmt.Errorf("cannot found any storage service with name %s", alternateName)
}

func (m *StorageServicesManager) GetStorageServiceByPrivateStorage(alternateName string) (*StorageService, error) {
	for _, service := range m.storageServices {
		if service.selfStorage.GetAlternateName() == alternateName {
			return service, nil
		}

		for _, privateStorage := range service.privateStorages {
			if privateStorage.GetAlternateName() == alternateName {
				return service, nil
			}
		}
	}

	return nil, fmt.Errorf("cannot found any storage service containing a private storage with name %s", alternateName)
}
