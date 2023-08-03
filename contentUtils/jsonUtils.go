package contentUtils

import "encoding/json"

func ConvertBytesToRawJson(bytes *[]byte) (result json.RawMessage, errMsg string) {
	if bytes == nil {
		return json.RawMessage{}, "no data to convert"
	}

	// It converts the bytes of any resource to json.RawMessage
	fhirResourceRaw := json.RawMessage{}
	err := fhirResourceRaw.UnmarshalJSON(*bytes)
	if err != nil {
		return json.RawMessage{}, "cannot convert raw data"
	}
	return fhirResourceRaw, ""
}