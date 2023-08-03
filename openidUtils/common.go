package openidUtils

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Universal-Health-Chain/common-utils-golang/didDocumentUtils"
)

var (
	ErrEmptyData               = errors.New("the data is empty")
	ErrOpenidInvalidRequest    = "invalid_request"
	ErrOpenidInvalidToken      = "invalid_token"
	ErrOpenidInsufficientScope = "insufficient_scope"

	ErrServerError = "server encountered an unexpected condition"

	ErrUnauthorized_client     = "client is not authorized to request"
	ErrAccessDenied            = "resource owner or authorization server denied the request"
	ErrUnsupportedResponseType = "unsupported response type"
	ErrInvalidScope            = "request scope is invalid, unknown or malformed"
	ErrTemporarilyUnavailable  = "authorization server is currently unable to handle the request" //due to a temporary overloading or maintenance of the server
)

// const OpenidRequestDataBackendType = "didCommunicationUtils-plain+json" // "application/" prefix is omitted (RFC 7515)

var (
	audienceSeparation = "," // comma
	scopeSeparation    = " " // space

	// Multiple audiences are separated by comma or comma-space (but allowing space too).
	audienceDelimiterRegExp = regexp.MustCompile("[, ] *")

	// Multiple scopes are separated by space (but also allowing by comma or comma-space).
	scopeDelimiterRegExp = regexp.MustCompile("[, ] *")

	// OpenId scopes should not be prefixed with scopePrefix.
	// openIdScopes = regexp.MustCompile("^(openid|profile|email)$")
)

// ParseAudiences joins the slice into a whitespace-separated string.
func ParseAudiences(scopes []string) string {
	return strings.Join(scopes, audienceSeparation)
}

// GetAudiences converts audience claim to string slice, with compatibility not only for comma separated
// but for comma-space and space too.
func GetAudiences(audience string) []string {
	return audienceDelimiterRegExp.Split(audience, -1)
}

// ParseScopes joins the slice into a whitespace-separated string.
func ParseScopes(scopes []string) string {
	return strings.Join(scopes, scopeSeparation)
}

// GetScopesList converts scope claim to string slice, with compatibility not only for space separated
// but for comma and comma-space too.
func GetScopes(scope string) []string {
	return scopeDelimiterRegExp.Split(scope, -1)
}

// CheckAudience checks both the received audience(s) contains URLs
// ("http://" is allows only for localhost and "https" is required for other URLs)
// and the audience claim list contains the expected audience (but only it "expected" is not an empty string).
// The "aud" in UHC identifies at the same time:
// - the "software_id" (e.g.: professional-app-example), and
// - the Issuer's URL (e.g.: http://identity.professional-app-example.test-organization.localhost:8006/)
func CheckAudience(audience string, didDocument *didDocumentUtils.DidDoc) bool {
	// check if the audience (url) exist in the array of services within the didDocument
	if didDocument == nil || didDocument.Service == nil {
		return false
	}
	arrayServices := didDocument.Service
	expectedAudiences := []string{}
	for _, serviceUnit := range arrayServices {
		expectedAudiences = append(expectedAudiences, serviceUnit.ServiceEndpoint)
	}

	audiences := []string{}
	found := false
	if audience == "" {
		return false
	} else {
		audiences = GetAudiences(audience)
		for _, audienceString := range audiences {
			// allow "http://" only for localhost and require "https://" for other URLs
			if !(strings.HasPrefix(audienceString, "http://localhost:") ||
				strings.HasPrefix(audienceString, "https://")) { // TODO: change this one by regexp

				return false
			}
			// if an expected audience is provided then check if it matches

			//search for coincidences of audienceString among the expected audiences
			for _, expectedUnit := range expectedAudiences {
				if expectedUnit != "" && found == false {
					if strings.Contains(audienceString, expectedUnit) {
						found = true
					}
				}
			}
		}
	}

	// first check if all audiences are URLs and then check if it matches with the expected one

	return found
}

// CheckIssuerDidKidURI checks the "iss" URI is a DID with a keyID fragment (#).
// (private_key_jwt authentication method as specified in section 9 of OIDC).
func CheckIssuerDidKidURI(issuer string, expectedIssuerDidKid string) bool {
	// first lowercase, then check if it starts with "did:" and split by # to check if fragment part exist (length = 2)
	issuerParts := strings.Split(strings.ToLower(issuer), "#")
	return len(issuerParts) == 2 && (issuer == expectedIssuerDidKid)
}

// CheckTimeValidation cheks both:
// - the "nbf" field is no longer than 60 minutes in the past.
// - the "exp" field has a lifetime of no longer than 60 minutes after the "nbf" field.
func CheckTimeValidation(nbf, exp int64) bool {
	currentTime := time.Now().Unix()

	if exp > nbf && nbf <= currentTime && currentTime < exp && currentTime < nbf+int64(3600) {
		return true
	} else {
		return false
	}
}

// CheckCodeChallengeLength checks the "code_challenge" is between 43 and 128 characters as per the OpenID specification
// (it is the SHA-256 hash result of a random challenge generated by the client application, base64url encoded).
func CheckCodeChallengeLength(codeChallenge string) bool {
	if 43 <= len(codeChallenge) && len(codeChallenge) <= 128 {
		return true
	} else {
		return false
	}
}
