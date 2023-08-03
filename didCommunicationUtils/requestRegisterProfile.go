package didCommunicationUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
)

type PayloadRegisterProfileRequestJWT struct {
	SoftwareID     string `json:"software_id,omitempty" bson:"software_id,omitempty"`
	AudienceSlice  string `json:"audience_slice,omitempty" bson:"audience_slice,omitempty"`
	NotValidBefore int64  `json:"nbf,omitempty" bson:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty" bson:"iat,omitempty"`
	JSONTokenID    string `json:"jti,omitempty" bson:"jti,omitempty"`
}

func CheckRegisterProfileRequestPayload(decodedRequestPayload *DecodedRequestPayloadJAR, recipientDidDoc didDocumentUtils.DidDoc, softwareIdList []string) string {
	//issued at mayor a fecha actual
	//expiration no menor a fecha actual
	if decodedRequestPayload.SoftwareID == nil {
		return "software id is empty"
	}

	if !(contentUtils.Contains(softwareIdList, *decodedRequestPayload.SoftwareID)) {
		return "software id not registered"
	}
	//TODO: check expiration and issued times

	return ""
}
