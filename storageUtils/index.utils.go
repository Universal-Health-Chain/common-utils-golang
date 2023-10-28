
package storageUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"

	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

func CreateIndexedHmacData(unprotectedIndexes []models.IndexedAttribute, hmacKeyBytes []byte) (protectedIndexData models.IndexedAttributeCollection) {
	protectedIndexedData := models.IndexedAttributeCollection{
		Sequence:          0, // only one sequence in the examples
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{},
	}

	for _, unprotectedIndexAttribute := range unprotectedIndexes {
		protectedName, protectedValue := contentUtils.ComputeIndexedAttributeByHmacKey(hmacKeyBytes, unprotectedIndexAttribute.Name, unprotectedIndexAttribute.Value)
		protectedIndexAttribute := models.IndexedAttribute{
			Name:   protectedName,
			Value:  protectedValue,
			Unique: unprotectedIndexAttribute.Unique,
		}
		protectedIndexedData.IndexedAttributes = append(protectedIndexedData.IndexedAttributes, protectedIndexAttribute)
	}

	return protectedIndexedData
}