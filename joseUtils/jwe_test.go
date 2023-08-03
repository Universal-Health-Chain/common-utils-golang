package joseUtils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// golang crypto NestedJWT: https://github.com/golang/crypto/blob/master/acme/jws.go

/* https://github.com/dvsekhvalnov/jose2go

HS256, HS384, HS512 signatures, A128KW, A192KW, A256KW,A128GCMKW, A192GCMKW, A256GCMKW
and DIR key management algorithm expecting []byte array key:

*/

const compactJWS = "eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"

/*
// Get the JWKS URL.
func Test_JWKeySet(jwksURL string, compactJWS string) {

	// Create the keyfunc options. Refresh the JWKS every hour and log errors.
	refreshInterval := time.Hour
	options := keyfunc.Options{
		RefreshInterval: &refreshInterval,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	// Parse the JWT.
	token, err := jwt.Parse(compactJWS, jwks.KeyFunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}

	log.Println("The token is valid.")
}
*/

func TestJSONWebEncryption_CompactSerialize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedHeader1": "protectedTestValue1",
			"protectedHeader2": "protectedTestValue2",
		}
		recipients := make([]*RecipientJWE, 1)

		recipients[0] = &RecipientJWE{ // RecipientJWE is a recipient of a JWE including the shared encryption key
			EncryptedKey: "TestKey",
		}

		jwe := JWEncryptionGo{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
			IV:               "TestIV",
			Ciphertext:       "TestCipherText",
			Tag:              "TestTag",
		}

		compactJWE, err := jwe.CompactSoleRecipientJWE(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedCompactJWE, compactJWE)
	})
}

func TestJSONWebEncryption_Serialize(t *testing.T) {
	t.Run("Success cases", func(t *testing.T) {
		t.Run("All fields filled, multiple recipients", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedHeader1": "protectedTestValue1",
				"protectedHeader2": "protectedTestValue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedHeader1": "unprotectedTestValue1",
				"unprotectedHeader2": "unprotectedTestValue2",
			}
			recipients := make([]*RecipientJWE, 2)

			recipients[0] = &RecipientJWE{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &RecipientJWE{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
				},
			}

			jwe := JWEncryptionGo{
				ProtectedHeaders:   protectedHeaders,
				UnprotectedHeaders: unprotectedHeaders,
				Recipients:         recipients,
				AAD:                "TestAAD",
				IV:                 "TestIV",
				Ciphertext:         "TestCipherText",
				Tag:                "TestTag",
			}
			serializedJWE, err := jwe.SerializeMultiRecipientStringified()
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAllFields, serializedJWE)
		})
		t.Run("All fields filled, one recipient - serialized JWE uses flattened syntax", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedHeader1": "protectedTestValue1",
				"protectedHeader2": "protectedTestValue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedHeader1": "unprotectedTestValue1",
				"unprotectedHeader2": "unprotectedTestValue2",
			}
			recipients := make([]*RecipientJWE, 1)

			recipients[0] = &RecipientJWE{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}

			jwe := JWEncryptionGo{
				ProtectedHeaders:   protectedHeaders,
				UnprotectedHeaders: unprotectedHeaders,
				Recipients:         recipients,
				AAD:                "TestAAD",
				IV:                 "TestIV",
				Ciphertext:         "TestCipherText",
				Tag:                "TestTag",
			}
			serializedJWE, err := jwe.SerializeMultiRecipientStringified()
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAllFieldsOneRecipient, serializedJWE)
		})
	})
}

const (
	exampleEPK = `{"kty":"EC","crv":"P-256","x":"0_Zip_vHBNI-P_in4S2OuPsxWy9cMWCem-ubr4hK1D0","y":"UTIlc5Vf0Ul` +
		`yrOgxFzZjt3JwKTA99cfkVNGu70_UZpA"}`

	exampleMockJWEAllFields = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedHeader1":"unp` +
		`rotectedTestValue1","unprotectedHeader2":"unprotectedTestValue2"},"recipients":[{"header":{"apu":"Tes` +
		`tAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdE` +
		`tleQ"},{"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` +
		exampleEPK + `},"encrypt` + `ed_key":"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"` +
		`VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEAllFieldsOneRecipient = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedHeader1":"unp` +
		`rotectedTestValue1","unprotectedHeader2":"unprotectedTestValue2"},"encrypted_key":"VGVzdEtleQ","heade` +
		`r":{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"aad":"VG` +
		`VzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`

	expectedCompactJWE = `eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZGhlYWRlcjIiOiJw` +
		`cm90ZWN0ZWR0ZXN0dmFsdWUyIn0.VGVzdEtleQ.VGVzdElW.VGVzdENpcGhlclRleHQ.VGVzdFRhZw`
)
