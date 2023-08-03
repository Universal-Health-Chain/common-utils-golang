package openidUtils

// CreateResponseRedirectUrlFragmentJARM returns a HTTP Redirect URL with an OpenID Response Object in compact JWT format (JWS/JWE)
// concatenated to the redirect URI as "<redirect_URI>#response=<the_compact_JWT>"
// where the JARM Response Object contains the data in the payload.
// Because the Response Document can be a DIDComm message (it adds "body" and "attachments" properties to the payload),
// a CRUDS operation API response will set the JSON data in the "body.data" as per both DIDComm and JSON:API specifications.
// and additional verifiable credentials or detached signatures can be set in the DIDComm "attachments".
// The JARM Response Object can be signed and optionally encrypted (nested JWT in a JWE)
// so a signed DIDComm message can be enveloped in a DIDComm encrypted message.
func CreateResponseRedirectUrlFragmentJARM(redirectUrl string, compactResponseJWT string) string {
	return redirectUrl + "#response=" + compactResponseJWT
}

// CreateResponseRedirectedUrlQueryJARM returns a HTTP Redirect URL with an OpenID Response Object in compact JWT format (JWS/JWE)
// concatenated to the redirect URI as "<redirect_URI>?response=<the_compact_JWT>"
// where the JARM Response Object contains the data in the payload.
// Because the Response Document can be a DIDComm message (it adds "body" and "attachments" properties to the payload),
// a CRUDS operation API response will set the JSON data in the "body.data" as per both DIDComm and JSON:API specifications.
// and additional verifiable credentials or detached signatures can be set in the DIDComm "attachments".
// The JARM Response Object can be signed and optionally encrypted (nested JWT in a JWE)
// so a signed DIDComm message can be enveloped in a DIDComm encrypted message.
func CreateResponseRedirectedUrlQueryJARM(redirectUrl string, compactResponseJWT string) string {
	return redirectUrl + "?response=" + compactResponseJWT
}

// ResponseDocumentByResponseType writes an HTTP JARM Response based on the ResponseType sent in the Request
// - code: it returns a Redirect URI concatenated with fragment ("#")
// - token: it returns a Redirect URI concatenated with a query ("?")
// - didcomm-uhc+json: returns a DIDComm v2 message signed and optionally encrypted based on the Registered Client App.
func ResponseDocumentByResponseType() {

}
