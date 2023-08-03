package contentUtils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
)

func Base64UrlEncodedDataByJSON(jsonData map[string]interface{}) string {
	jsonBytes, _ := json.Marshal(jsonData)
	return base64.RawURLEncoding.EncodeToString(jsonBytes)
}

func InterfaceToMap(i interface{}) (map[string]interface{}, error) {
	if reflect.ValueOf(i).Kind() == reflect.Map {
		return i.(map[string]interface{}), nil
	}

	var (
		b   []byte
		err error
	)

	switch cv := i.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(i)
		if err != nil {
			return nil, fmt.Errorf("convert to bytes: ")
		}
	}

	var m map[string]interface{}

	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("convert to map: %w", err)
	}

	return m, nil
}
