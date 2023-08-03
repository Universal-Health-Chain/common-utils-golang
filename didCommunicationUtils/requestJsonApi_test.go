package didCommunicationUtils

import (
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/joseUtils"
	"github.com/stretchr/testify/assert"
)

func Test_DecodeAndCheckRequestJsonApiDataJWT(t *testing.T) {
	/*
		incorrectDidDoc:=didDocumentUtils.DidDoc{}
		expectedAudience:="" */
	invalidJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZGF0YSI6InRlc3REYXRhIiwiaWF0IjoxNTE2MjM5MDIyfQ.Ao6MWo1fC0NU456mtXrhH-9kiWS-e0anXTrdi2KggFk"

	/* correctPayloadJWT := CreatePayloadForJsonApiJWT(999, "", "", nil, "", "") */

	/* 	correctDidDoc := didDocumentUtils.DidDoc{

	   	} */
	incorrectJWT := "testJWT"
	emptyStringArray := []string{}

	t.Run("Empty parameters - expected error", func(t *testing.T) {
		dataJWT, errorMsg := DecodeAndCheckRequestJsonApiDataJWT(nil, nil, "", emptyStringArray)
		assert.Nil(t, dataJWT, "DataJWT should be nil")
		assert.Equal(t, ErrCodeRequestInvalid, *errorMsg, "Error should be code request invalid")
	})

	t.Run("Empty parameters, only with wrong JWT - expected error", func(t *testing.T) {
		dataJWT, errorMsg := DecodeAndCheckRequestJsonApiDataJWT(&incorrectJWT, nil, "", emptyStringArray)
		assert.Nil(t, dataJWT, "DataJWT should be nil")
		assert.Equal(t, ErrCodeRequestInvalid, *errorMsg, "Error should be code request invalid")
	})

	t.Run("Empty parameters, only with invalid JWT - expected error", func(t *testing.T) {
		dataJWT, errorMsg := DecodeAndCheckRequestJsonApiDataJWT(&invalidJWT, nil, "", emptyStringArray)
		assert.Nil(t, dataJWT, "DataJWT should be nil")
		assert.Equal(t, joseUtils.ErrMsgInvalidRequest, *errorMsg, "Error should be request is empty or invalid")
	})

	t.Run("Correct parameters", func(t *testing.T) {
		/* dataJWT, errorMsg := DecodeAndCheckRequestJsonApiDataJWT(correctJWT, &correctDidDoc, "", emptyStringArray)
		assert.NotNil(t, dataJWT, "DataJWT should not be nil")
		assert.Nil(t, errorMsg, "Error should be nil") */
	})
}
func Test_DecodeAndCheckRequestJsonApiPayloadJAR(t *testing.T) {
	emptyPayload := PayloadJsonApiJWT{}
	emptyRecipientDidDocument := didDocumentUtils.DidDoc{}
	emptyRequiredScopes := []string{}

	t.Run("Empty parameters - expected false", func(t *testing.T) {
		isValid := checkRequestJsonApiPayloadProperties(&emptyPayload, &emptyRecipientDidDocument, emptyRequiredScopes)
		assert.False(t, isValid, "Should be invalid")
	})
	t.Run("", func(t *testing.T) {

	})
}
