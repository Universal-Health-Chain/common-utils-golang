package openidUtils

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Universal-Health-Chain/common-utils-golang/jwkUtils"
)

var GetSignKeyInHeaderJWT = func(inputHeaderB64URL string) *jwkUtils.JWK {
	headerBytes, _ := base64.RawURLEncoding.DecodeString(inputHeaderB64URL)
	var headerOpenid OpenidHeaders
	_ = json.Unmarshal(headerBytes, &headerOpenid) //"return nil, no alg"

	if headerOpenid.HeaderAlgorithm == nil {
		return nil
	}
	algorithm := *headerOpenid.HeaderAlgorithm

	if headerOpenid.HeaderJSONWebKey != nil {
		headerAlg := headerOpenid.HeaderJSONWebKey.Alg
		if headerAlg == algorithm {
			//assert.NotNil(t, headerOpenid.HeaderJSONWebKey) //
			return headerOpenid.HeaderJSONWebKey
		}
	}

	if headerOpenid.HeaderJSONWebKeySet != nil {
		jwkArray := headerOpenid.HeaderJSONWebKeySet.SearchJWKeyByAlg(algorithm)
		if len(*jwkArray) == 1 {
			//return jwkArray[0]
			jwk := *jwkArray
			jwk1 := jwk[0]
			return &jwk1
			//assert.NotNil(t, jwk[0], "there's one element")
		}
		if len(*jwkArray) > 1 {
			if headerOpenid.HeaderKeyID != nil {
				for _, jwk := range *jwkArray {
					if jwk.Kid == *headerOpenid.HeaderKeyID {
						return &jwk
						//assert.NotNil(t, jwk, "found jwk with same KId")
					}
				}
			}
		}
	}
	return nil
}
