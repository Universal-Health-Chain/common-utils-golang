package openidUtils

// The audience identifies the intended "consumer" of the JWT.
// Normally it is the resource application (e.g., an API) that receives the token from a client app.
// The "aud" value is a string containing one or more space-separated case-sensitive strings or URIs.
// The interpretation of audience values is generally application specific, but if the access token has multiple audiences,
// then after using it in API X, the token can be used by API X for another audience.
// It is best practice to use "azp" (Authorized Presenter) to identify the client app
// (profile / wallet) who presents a JWT issued by other application (e.g: OpenID access token, VC, etc.).
// The "azp" is the Crystals Dilithium public key in DID URI format
// (e.g.: did:legal:health:ES::::Organization::<multibase58>:employee::<multibase58>#keyID

/*
	From a viewpoint of RFC 7519, ID Token defined in OpenID Connect Core 1.0 is one of application examples of JWT.
	In the context of ID Token, some of the standard claims defined in RFC 7519 are mandatory.
	To be concrete, iss, sub, aud, exp, and iat are mandatory.
*/
