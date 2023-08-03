package didCommunicationUtils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponsePayloadDataToJSON(t *testing.T) {
	responsePayload := ResponseDocumentPayloadJARM{
		Audience:    "someClientApp",
		Expiration:  0,
		Issuer:      "",
		IssuedAt:    nil,
		JSONTokenID: nil,
		NotBefore:   nil,
		Scope:       nil,
		TokenType:   nil,
		Body: ResponseDocumentPayloadBodyJARM{
			Data: nil,
		},
		MediaType: nil,
	}

	result := responsePayload.ToJSON()
	assert.NotNil(t, result)
	assert.Equal(t, responsePayload.Audience, result["aud"])

	println("response payload JSON = ", result)

	// check other fields

}
