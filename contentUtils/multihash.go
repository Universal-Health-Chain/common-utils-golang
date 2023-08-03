package contentUtils

import "github.com/multiformats/go-multihash"

// Multihash is byte slice with the following form: <hash function code><digest size><hash function output>. See the spec for more information.
// B58String returns the B58-encoded representation of a multihash.
// Create a new multihash with the digest data.
func GetMultihashSHA256Base58(inputBytes *[]byte) string {
	var multihashDataBytes multihash.Multihash
	multihashDataBytes, _ = multihash.EncodeName(*inputBytes, "sha2-256")
	return multihashDataBytes.B58String()
}

// Multihash is byte slice with the following form: <hash function code><digest size><hash function output>. See the spec for more information.
// B58String returns the B58-encoded representation of a multihash.
// Create a new multihash with the digest data.
func GetMultihashBase58(inputBytes *[]byte, hashName string) string {
	var multihashDataBytes multihash.Multihash
	multihashDataBytes, _ = multihash.EncodeName(*inputBytes, hashName)
	return multihashDataBytes.B58String()
}
