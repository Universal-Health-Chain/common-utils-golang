package openidUtils

import (
	"github.com/Universal-Health-Chain/common-utils-golang/contentUtils"
)

// CheckScopeActionPermissionOverResource receives an action (create, read, update, delete, search)
// and verifies if some scope matches with the action over the entity's resource
// (e.g.: the scope "system/HealthcareService.cruds" matches with "create HealthcareService" action in the user's system)
// "?i" means case insensitive
// "\A" means at the beginning of the text

// CheckRequiredScopes generates an slice (array) with each of the matched scopes
// and returns true if the length of the resulting slice is equal to the length of the required scopes slice.
func CheckRequiredScopes(scopeClaim string, requiredScopes []string) bool {
	scopesArray := GetScopes(scopeClaim)
	result := []string{} // length is zero

	// for each required scope look if it exists in the scopes array.
	for index, requiredScope := range requiredScopes {

		// return false when looking for a scope in the position "n+1" but the previous scope was not set (found).
		if index != len(result) {
			return false
		}

		if contentUtils.StringsSliceContainsString(scopesArray, requiredScope) {
			result = append(result, requiredScope)
		}
	}

	// return true if all the required scopes are in the resulting array of matched scopes (same length)
	return len(requiredScopes) == len(result)
}
