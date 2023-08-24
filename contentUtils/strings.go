package contentUtils

import (
	"strings"
)

// TODO: describe the function
func Contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

// StringsSliceContainsString checks if a string is contained in some member of the slice
func StringsSliceContainsString(slice []string, strValue string) bool {
	for _, entry := range slice {
		if strings.Contains(entry, strValue) {
			return true
		}
	}

	return false
}

// StringsSliceContains checks if a string is equal to some member in the slice
func StringsSliceHasStringMember(slice []string, strValue string) bool {
	for _, entry := range slice {
		if entry == strValue {
			return true
		}
	}

	return false
}

// StringsArrayToString converts a slice of strings to a string containing a space separated list of strings
func StringsArrayToString(stringsSlice *[]string) string {
	result := ""

	if stringsSlice == nil || len(*stringsSlice) < 1 {
		return result
	}

	for index, singleString := range *stringsSlice {
		if index == 0 {
			result = singleString // first value is not concatenated to anything
		} else {
			result = result + " " + singleString // concatenated to the previous values
		}
	}

	return result
}

// StringToStringsArray splits the string around each instance of one or more consecutive white space characters
func StringToStringsArray(spaceSeparatedString *string) []string {
	result := []string{}
	if spaceSeparatedString == nil {
		// empty array, do nothing
	} else {
		// splits the string around each instance of one or more consecutive white space characters
		result = strings.Fields(*spaceSeparatedString)
	}
	return result
}

// StringToStringsArray splits the string around each instance of one or more consecutive white space characters
func StringsArrayByConcatenatedString(concatenatedString *string, concatenationSymbol string) []string {
	result := []string{}
	if concatenatedString == nil {
		// empty array, do nothing
	} else {
		// splits the string around each instance of one or more consecutive white space characters
		result = strings.Split(*concatenatedString, concatenationSymbol)
	}
	return result
}
