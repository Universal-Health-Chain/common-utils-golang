package storageUtils

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"errors"
	"fmt"
	"time"

	"github.com/trustbloc/edge-core/pkg/log" // logger

	"github.com/cenkalti/backoff"
	ariesStorageCouchdb "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesStorageMongodb "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesStorageMem "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesStorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("edv-rest")

const (
	DatabaseTypeMemOption     = "mem"
	DatabaseTypeCouchDBOption = "couchdb"
	DatabaseTypeMongoDBOption = "mongodb"
	Sleep                     = time.Second
)

type StorageParameters struct {
	StorageType   string
	StorageURL    string
	StoragePrefix string
}

func NewStorageProvider(parameters StorageParameters, databaseTimeout uint64) (ariesStorage.Provider, error) {
	var prov ariesStorage.Provider

	providerFunc, supported := supportedAriesStorageProviders[parameters.StorageType]
	if !supported {
		return nil, errors.New("errInvalidDatabaseType")
	}

	err := retry(func() error {
		var openErr error
		prov, openErr = providerFunc(parameters.StorageURL, parameters.StoragePrefix)
		return openErr
	}, databaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", parameters.StorageType, err)
	}

	return prov, nil
}

func retry(fn func() error, numRetries uint64) error {
	return backoff.RetryNotify(fn,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(Sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf("failed to connect to database, will sleep for %s before trying again: %s",
				t, retryErr)
		})
}

var supportedAriesStorageProviders = map[string]func(string, string) (ariesStorage.Provider, error){
	DatabaseTypeCouchDBOption: func(databaseURL, prefix string) (ariesStorage.Provider, error) {
		return ariesStorageCouchdb.NewProvider(databaseURL, ariesStorageCouchdb.WithDBPrefix(prefix))
	},
	DatabaseTypeMemOption: func(_, _ string) (ariesStorage.Provider, error) { // nolint:unparam
		return ariesStorageMem.NewProvider(), nil
	},
	DatabaseTypeMongoDBOption: func(databaseURL, prefix string) (ariesStorage.Provider, error) {
		return ariesStorageMongodb.NewProvider(databaseURL, ariesStorageMongodb.WithDBPrefix(prefix))
	},
}
