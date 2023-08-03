![logo](https://avatars.githubusercontent.com/u/57396025?s=200&v=4)


# **UHC messages and DIDComm encapsulation**

UHC extends FAPI with DIDComm and Post-Quantum Computing algorithms. See [OpenID Utils](../openidUtils/README.md). UHC messages are protocol-agnostic to be used not only in HTTP but in other protocols such as Bluetooth. In UHC, the Request Object is the payload of a JWS/DIDComm signed message which can be encrypted in a JWE/DIDComm message as a [Nested JWT](https://www.rfc-editor.org/rfc/rfc7519.html#appendix-A.2), but using **Post-Quantum Computing (PQC)** algorithms for signature and encryption.

UHC extends the JWTs used in FAPI with DIDComm messages (for JAR and JARM):

- A DIDComm signed message is a signed JWM. When a message is both signed and encrypted, the JOSE recommendation is **sign the plaintext first, and then encrypt**. JWMs conceptually share parallels to JWTs. A JWM leverages JSON Web Signature (JWS) and or JSON Web Encryption (JWE) to achieve digital signing, integrity protection and or confidentiality via encryption for the JWM attribute set in similar ways to JWT for the JWT claim set.

- A DIDComm encrypted message is an encrypted JWM/JWE which contains nested a DIDComm signed message (signed JWM/JWT).


## **UHC disambiguation using DIDComm messages**

1. Similar to the Bundle ID in iOS applications, the OpenID "client_id" in both requests and responses refers to of the Client software ID, which is the reverse-DNS of the URL client application. For example: `com.example.region.organization-name.app-name`.

2. If the message is signed:

   - it contains the sender's public signature keyID ("kid") in the JOSE header of the JWS/DIDComm signed message.

3. If the message is encrypted it contains in the JOSE headers:

   - the sender's public encryption keyID ("skid") in the JOSE **protected header** of the JWE/DIDComm encrypted message.
   - the recipient's public encryption keyID ("skid") in the JOSE **protected header** of the JWE/DIDComm encrypted message.
   - the sender's public signature keyID ("kid") in the JOSE **header** of the JWS/DIDComm signed message.

4. The payload (unencrypted "plaintext" data) of the DIDComm message contains:

    - the "sub" property to identify the *DID of the Subject*, where the public encryption and / or signature keys exist for the current wallet (profile) sending/receiving data through the software application installed in an electronic device.
   
    - the *Issuer* ("iss" property) corresponds to the "issuer" entry in the *well-known* configuration files of the API service (both *openid-configuration* and *did-configuration.json* files). For example: `https://api-service-name.organization-name.region.example.com`.

    - the "from" property refers to the sender's DID where the sender's encryption "skid" and / or signature "kid" header properties refers to, similar to [OpenID SIOPv2](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html).

    - the "to" property refers to the recipient's DID. It can be an alias of a DID ("alsoKnownAs" property in a DID Document). If the recipient is an OpenID Provider the DID Document must have the "issuer" service URL matching with "iss" property (URL). More [information about the DID Method](https://github.com/Universal-Health-Chain/docs).

## **OpenID Connect Code Flow**

The OAuth 2.0/OpenID Connect Authorization Code grant is a two-step process:
1) **obtain an** [**authorization code**](requestCode.md), and
2) **exchange it for an** [**access token**](requestToken.md) (to be used in the APIs) **and optionally for an ID token** (to be used by the client application).


## **JWT-secured authorisation request (JAR), FAPI and DIDComm envelope**

When using the HTTP protocol and the HTTP POST method, the parameters of the HTTP request are serialized using Form Serialization (OICD Core - Section 13.2), the HTTP header `Content-type` is `application/x-www-form-urlencoded`.

Although different parameters are required as per OAuth 2.0, OpenID and JAR specifications, **FAPI and UHC ignore all except the** ***"request"*** **parameter**, which in FAPI it is a compact JWS containing the Request Object as payload.

UHC messages are protocol-agnostic to be used not only in HTTP but in other protocols such as Bluetooth, and extends the FAPI Security Profile. In UHC, the Request Object is the payload of a JWS/DIDComm signed message which can be encrypted in a JWE/DIDComm message as a [Nested JWT](https://www.rfc-editor.org/rfc/rfc7519.html#appendix-A.2), but using **Post-Quantum Computing (PQC)** algorithms for signature and encryption.

The parameters for the HTTP request are explained below:

- **"request"**: the JWT data container, named ***"Request Object"***, in compact JWT serialization.

- **"client_id"**: duplicated from the *Request Object's* payload (required by Section 5 of JAR, but **ignored by FAPI and UHC**).

Additionally, **if the client app is not using pushed authentication request (PAR)**, the client app can send duplicates of the **"response_type"** and **"scope"** parameters/values using the OAuth 2.0 request syntax as required by Section 6.1 of the OpenID Connect specification, but they are **ignored by FAPI and UHC specifications**.


## **Using a DIDComm message to envelope the Request Object in JAR**

JAR requires both Clients and Authorization Servers to verify the payload of signed JWT (Request Object) with keys from the other party.

For the Authentication Server (AS) it strongly recommends the use of JWKS URI endpoints to distribute public keys ("jwks_uri", [RFC8414](https://www.rfc-editor.org/rfc/rfc8414)).

For the Client applications it recommends either the use of JWKS URI endpoints ("jwks_uri", [RFC7591](https://www.rfc-editor.org/rfc/rfc7591)) or the use of the "jwks" JOSE header parameter in combination with RFC7591 and RFC7592.

An Authentication Request is an OAuth 2.0 Authorization Request that requests that the End-User be authenticated by the Authorization Server.


### **Signing and then encrypting a JWT/DIDComm**

As per the OpenID Connect specification ([OIDC Core - Section 16.14](https://openid.net/specs/openid-connect-core-1_0.html#SigningOrder)), a JWT can be first signed then encrypted, being the signed JWT (JWS) the plaintext data of the JWE ([Nested JWT](https://www.rfc-editor.org/rfc/rfc7519.html#appendix-A.2)).

UHC extends JWT with DIDComm messages. A DIDComm signed message is a signed JWM. When a message is both signed and encrypted, the JOSE recommendation is **sign the plaintext first, and then encrypt**.

JWMs conceptually share parallels to JWTs. A JWM leverages JSON Web Signature (JWS) and or JSON Web Encryption (JWE) to achieve digital signing, integrity protection and or confidentiality via encryption for the JWM attribute set in similar ways to JWT for the JWT claim set.

A DIDComm encrypted message is an encrypted JWM/JWE which contains nested a DIDComm signed message (signed JWM/JWT).


#### **Creating a compact JWT/DIDComm**

To maintain the compatibility with the JAR specification:

1) an encrypted JWE/jar-didcomm-encrypted+json message contains a Nested JWS/jar-didcomm-signed+json message, where:
    - the "typ" property of the JWE header is *"jwt"* as per the JAR specification;
    - the "cty" property of the JWE header is set to the media type *"didcomm-signed+json"* as defined in the DIDComm specification.
    - the "kid" property of the JWE header is recipient's public encryption keyID in *DID#kid* URI format.
2) a nested DIDComm-JAR signed message (JWT) contains a JAR object in the payload adding a "type" field to predict the structure inside of the message following the DIDComm specification, where:
    - the "typ" property of the JWT header is *"jwt"* as per the JAR specification;
    - the "cty" property of the JWT header is set to the media type *"didcomm-signed+json"* as defined in the DIDComm specification.
    - the "to" property of the JWT header is defined in the inner (signed) message, in order to avoid surreptitious forwarding or malicious usage of the signed message, as per the DIDComm specification.

Aligning with RFC 7515, IANA types for DIDComm messages MAY omit the `application/` prefix; the recipient MUST treat media types not containing `/` as having the `application/` prefix present.

#### **Message Layer Addressing Consistency**

As per the DIDComm specification ([Section 3.2](https://identity.foundation/didcomm-messaging/spec/#message-layer-addressing-consistency)), when messages are combined into layers as shown above in the Media Types table, various attributes must be checked for consistency by the message recipient.

- The *to* attribute in the plaintext message (Request Object payload) MUST contain the *kid* attribute of an encrypted message (*to* can be a `did#kid` URI)
- The *from* attribute in the plaintext message (Request Object payload) MUST match the signer’s *kid* in a signed message.
- The *from* attribute in the plaintext message (Request Object payload) MUST match the *skid* attribute in the encryption layer.


#### **Header of the encrypted DIDComm-JAR message envelope**

The JOSE header of the encrypted DIDComm message, following both JOSE ([RFC7516](https://www.rfc-editor.org/rfc/rfc7516.html#section-4)) and DIDComm specifications, requires the following fields:
- the **"skid"** (*required in UHC*) field value is the sender's public encryption keyID for authenticated encryption.
- the **"cty"** (*required in UHC*) field value is set to *"didcomm-signed+json"* when the plaintext is a Nested JWS/jar-didcomm-signed+json message.
- the **"typ"** (*required*) field value is *"jwt"*.
- the **"alg"** (*required*) field value identifies the **algorithm used to encrypt (encapsulate) the value of the CEK**.
- the **"enc"** (*required*) field value identifies the **algorithm used to encrypt the data using the CEK** (e.g.: *"A256GCM"* for AES data encryption).
- the **"kid"** (*conditional*) field value is the recipient's keyID (*kid*) to which the CEK was encrypted, calculated by the JWK Thumbprint of the recipient's public encryption key.
- the **"jku"** (*conditional*) field value is the recipient's JWK Set URL, to get the public key to which the JWE was encrypted by using the *"kid"* field as identifier.
- the **"jwk"** (*conditional*) field value is the recipient's public JWK to which the CEK was encrypted (rather than using both "kid" and "jku").


#### **Header of the signed DIDComm-JAR nested message**

The JOSE header of the signed DIDComm message, following both JAR and DIDComm specifications, requires the following fields:
- the **"to"** (*required in UHC*) field value is the DID Service Endpoint. It should be the same as the payload's "aud" field in case of the Authorization flow or the "htu" field when using a DPoP token bound to an access token.
- the **"cty"** (*required in UHC*) field value is set to *"didcomm-signed+json"*.
- the **"typ"** (*required*) field value is *"jwt"*.
- the **"alg"** (*required*) field value is the identifier of the digital signature algorithm. MUST NOT be "none".
- the **"kid"** (*required*) field value is the keyID (*kid*) calculated by the JWK Thumbprint of the public key used by the issuer.
- the **"jwks"** (*optional*) field value contains an array of public keys that corresponds in UHC to the sender's public signature JWK (first) and public encryption JWK (second, it can be already in the JWE "jwk" header).
- the **"zip"** (*optional*) field value can be "DEF" (deflated, compressed).

Note: *"x5u"* is not used in JAR because the certificate data can be included in the JWK (use the *"jwk"* or *"jku"* fields instead).


## **JWT-secured authorisation response (JARM)**

The JWT data container is named "Response Document".

- A Redirect URL with the Response Document in compact JWT as the "response" parameter.
- An HTML web page ([Form Post Response](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)) containing a form with the Response Document in compact JWT as the "response" parameter.


### **JWT-secured authorisation response (JARM) with DIDComm envelope**

TODO

#### **Error response**
As per the [OAuth 2.0 Authorization Framework - Section 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1) If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.

If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B:

- **"error"** (REQUIRED): A single ASCII error code from the following:
    - *"invalid_request"*: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
    - *"unauthorized_client"*: The client is not authorized to request an authorization code using this method.
    - *"access_denied"*: The resource owner or authorization server denied the request.
    - *"unsupported_response_type"*: The authorization server does not support obtaining an authorization code using this method.
    - *"invalid_scope"*: The requested scope is invalid, unknown, or malformed.
    - *"server_error"*: The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
      (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)
    - *"temporarily_unavailable"*: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
      (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect)

- **"state"** (CONDITIONAL): required if a "state" parameter was present in the client authorization request; it is the exact value received from the client.

- **"error_description"** (OPTIONAL): Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.

- **"error_uri"** (OPTIONAL). A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.
