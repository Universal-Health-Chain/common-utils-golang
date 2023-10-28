package storageUtils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

var hmacKeyBytesForTest = []byte{}
var unprotectedIndexForTest = models.IndexedAttribute{Name: "name", Value: "value", Unique: true}
var unprotectedIndicesForTest = []models.IndexedAttribute{unprotectedIndexForTest}

func Test_CreateIndexedHmacData(t *testing.T) {

	protectedIndices := CreateIndexedHmacData(unprotectedIndicesForTest, hmacKeyBytesForTest)
	assert.NotNil(t, protectedIndices, "protectedIndices must not be empty")
}
