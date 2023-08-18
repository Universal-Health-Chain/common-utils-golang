package base64Utils

import "encoding/base64"

func EncodeStringifiedDataToRawBase64URL(stringifiedData string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(stringifiedData))
}

func DecodeRawBase64UrlToBytes(encodedData string) []byte {
	decodedDataBytes, err := base64.RawURLEncoding.DecodeString(encodedData)
	if err != nil {
		return nil
	}

	return decodedDataBytes
}
