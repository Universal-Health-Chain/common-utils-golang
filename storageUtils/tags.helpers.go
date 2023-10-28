package storageUtils

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func GenerateAriesDocumentEntryKey(vaultID, documentID string) string {
	return fmt.Sprintf("%s-%s", vaultID, documentID)
}

// Getting an array of tags (name and value) from the indexed attributes.
// Tags are both the "vaultID" attribute name and any other indexed attribute (name and value)
func CreateTags(vaultID string, document EncryptedDocument) []storage.Tag {
	tags := []storage.Tag{
		{Name: VaultIDTagName, Value: vaultID},
	}

	for _, indexedAttributeCollection := range document.IndexedAttributeCollections {
		for _, indexedAttribute := range indexedAttributeCollection.IndexedAttributes {
			tags = append(tags, storage.Tag{
				Name:  indexedAttribute.Name,
				Value: indexedAttribute.Value,
			})
		}
	}

	return tags
}

func VaultIDTagMatches(targetVaultID string, queryResultsIterator storage.Iterator) (bool, error) {
	tags, err := queryResultsIterator.Tags()
	if err != nil {
		return false, err
	}

	for _, tag := range tags {
		if tag.Name == VaultIDTagName && tag.Value == targetVaultID {
			return true, nil
		}
	}

	return false, nil
}
