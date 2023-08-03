package joseUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
)

// AudienceSingle represents one of the recipients that the JWT is intended for.
type AudienceSingle string

// AudienceSingleToString gets the string
func (audienceString *AudienceSingle) AudienceSingleToString() string {
	if audienceString == nil {
		return ""
	} else {
		return string(*audienceString)
	}
}

/*
// StringToAudienceSlice converts a space separated list of strings to a strings slice (array of strings)
func (audienceSlice *AudienceSlice) StringToAudienceSlice(v string) string {
	return contentUtils.StringToStringsArray(audienceSlice.AudienceSliceToStringsArray())
}
*/

// AudienceSlice represents the recipients that the JWT is intended for.
type AudienceSlice []string

// AudienceSliceToStringsArray splits the audience string around each instance of one or more consecutive white space characters
func (audienceSlice *AudienceSlice) AudienceSliceToStringsArray() []string {
	if audienceSlice == nil {
		return []string{}
	} else {
		return *audienceSlice
	}
}

//Contains checks whether a given string is included in the AudienceSlice
func (audienceSlice AudienceSlice) Contains(v string) bool {
	return contentUtils.StringsSliceHasStringMember(audienceSlice, v)
}

// AudienceSliceToString joins the array of strings with white space characters in a single string
func (audienceSlice AudienceSlice) AudienceSliceToString(v string) string {
	stringsArray := audienceSlice.AudienceSliceToStringsArray()
	return contentUtils.StringsArrayToString(&stringsArray)
}
