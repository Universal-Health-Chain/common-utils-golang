package contentUtils

import "strings"

// CheckValidLocalizedText accepts "urn:ietf:bcp:47|<language>|<text>"
// but also "bcp:47|<language>|<text>" and "<language>|<text>" are allowed.
func CheckValidLocalizedText(localizedText string) bool {
	// check localized text is valid
	rule1 := false
	rule2 := false
	rule3 := false

	// when name has 3 slices (| separated) first has suffix "bcp:47"
	parts := strings.Split(localizedText, "|")
	n := len(parts)
	if n >= 2 {
		if n == 3 {
			rule1 = strings.HasSuffix(parts[0], "urn:ietf:bcp:47") || strings.HasSuffix(parts[0], "bcp:47")
			rule2 = CheckValidLanguage(parts[1]) // language part // mocked to true for now
			rule3 = parts[2] != ""               // check the value is not empty
		} else {
			rule1 = true                         // first part does not exist but it is allowed
			rule2 = CheckValidLanguage(parts[0]) // language part // mocked to true for now
			rule3 = parts[1] != ""               //check the value is not empty
		}
	}

	return rule1 && rule2 && rule3
}

// GetVerifiedLocalizedText returns empty string if wrong formatted instead of true or false
func GetVerifiedLocalizedText(localizedText string) string {
	ok := CheckValidLocalizedText(localizedText)
	if !ok {
		return ""
	} else {
		return localizedText
	}
}

func CheckValidMultipleLocalizedTexts(inputStr string) bool {
	//split input string by "," and call CheckValidName
	InputArray := strings.Split(inputStr, ",")
	for _, input := range InputArray {
		resp := CheckValidLocalizedText(input)
		if !resp {
			return false
		}
	}
	return true
}

func CheckValidLanguage(language interface{}) bool {
	return true
}
