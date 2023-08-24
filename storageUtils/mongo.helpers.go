package storageUtils

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"errors"
	"fmt"

	ariesStorageMongodb "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"

	"go.mongodb.org/mongo-driver/bson"
	mongodriver "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	LogModuleName       = "edv-provider"
	VaultIDTagName      = "vaultID"
	DocumentIDFieldName = "id"
)

func CreateMongoDBIndex(mongoDBProvider *ariesStorageMongodb.Provider, documentDatabaseName string) error {
	indexModels := GenerateMongoDBIndexModels()

	return mongoDBProvider.CreateCustomIndexes(documentDatabaseName, indexModels...)
}

func ConvertEDVQueryToAriesQuery(query Query) (string, error) {
	if query.Has != "" {
		return query.Has, nil
	}

	if len(query.Equals) > 1 || len(query.Equals[0]) > 1 {
		return "", errors.New("support for multiple attribute queries not implemented for " +
			"CouchDB or in-memory storage")
	}

	// Note: The case where query.Equals has no elements is handled in operations.go.
	for attributeName, attributeValue := range query.Equals[0] {
		return fmt.Sprintf("%s:%s", attributeName, attributeValue), nil
	}

	return "", nil
}

func GenerateMongoDBIndexModels() []mongodriver.IndexModel {
	model := []mongodriver.IndexModel{
		{
			Keys: bson.D{
				{Key: DocumentIDFieldName, Value: 1},
				{Key: VaultIDTagName, Value: 1},
			},
			Options: mongooptions.Index().SetName("DocumentIDAndVaultID").SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "indexed.attributes.name", Value: 1},
				{Key: "indexed.attributes.value", Value: 1},
				{Key: VaultIDTagName, Value: 1},
			},
			Options: mongooptions.Index().SetName("AttributesAndVaultID"),
		},
	}

	return model
}

func StoreDocumentsForMongoDB(vaultID string, documents []EncryptedDocument, mongoDBStore *ariesStorageMongodb.Store) error {
	writeModels := make([]mongodriver.WriteModel, len(documents))

	for i := 0; i < len(documents); i++ {
		documents[i].VaultID = vaultID

		mongoDBDocument, err := ariesStorageMongodb.PrepareDataForBSONStorage(documents[i])
		if err != nil {
			return err
		}

		filter := bson.M{DocumentIDFieldName: documents[i].ID, VaultIDTagName: vaultID}

		writeModels[i] = mongodriver.NewReplaceOneModel().SetFilter(filter).
			SetReplacement(mongoDBDocument).SetUpsert(true)
	}

	return mongoDBStore.BulkWrite(writeModels)
}

func ConvertEDVQueryToMongoDBQuery(vaultID string, edvQuery Query) bson.D {
	if edvQuery.Has != "" {
		return bson.D{
			{
				Key:   "indexed.attributes.name",
				Value: edvQuery.Has,
			},
			{
				Key:   VaultIDTagName,
				Value: vaultID,
			},
		}
	}

	mongoDBORQuery := make(bson.A, len(edvQuery.Equals))

	mongoDBQuery := bson.D{
		{
			Key:   "$or",
			Value: mongoDBORQuery,
		},
		{
			Key:   VaultIDTagName,
			Value: vaultID,
		},
	}

	for i, subfilter := range edvQuery.Equals {
		var mongoDBANDQuery bson.D

		for attributeName, attributeValue := range subfilter {
			mongoDBANDQuery = append(mongoDBANDQuery,
				bson.E{
					Key:   "indexed.attributes.name",
					Value: attributeName,
				})

			if attributeValue != "" {
				mongoDBANDQuery = append(mongoDBANDQuery,
					bson.E{
						Key:   "indexed.attributes.value",
						Value: attributeValue,
					})
			}
		}

		mongoDBORQuery[i] = mongoDBANDQuery
	}

	return mongoDBQuery
}
