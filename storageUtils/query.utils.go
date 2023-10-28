package storageUtils

import "github.com/Universal-Health-Chain/common-utils-golang/contentUtils"

func ComposeGenericQuery(attKey, attValue string, privateHostHmacKeyBytes []byte) Query {
	// 1 - create the HMAC data with the Host HMAC Key to run the Query by searching in the indexed data
	secureAttributeName, secureAttributeValue := contentUtils.ComputeIndexedAttributeByHmacKey(privateHostHmacKeyBytes, attKey, attValue)

	// 2 - return the query to be executed
	return Query{
		Equals: []map[string]string{
			{
				secureAttributeName: secureAttributeValue,
			},
		},
	}
}