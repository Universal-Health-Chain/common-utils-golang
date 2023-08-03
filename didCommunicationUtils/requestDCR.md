
![logo](https://avatars.githubusercontent.com/u/57396025?s=200&v=4)

# [**JWT-secured authorisation request (JAR) with DIDComm envelope**](./README.md)

## ** Dynamic Client Registration request (DCR) - DIDComm envelope**

The primary use case for Dynamic Client Registration is a confidential mobile application instance registering to get an installation-specific credential.

Being able to keep a credential secret is a requirement imposed by the OAuth standard to issue a refresh token.

Client registration is restricted to applications that have an initial access token obtained after a user has authenticated (the profile has been created by an administrator). In this case, the client is identified but only the end user is verified.

The user must login using the installation code provided by an administrator and the app identifies itself using the *software_id* and the self-generated cryptographic keys. After doing so, an ***initial*** *access token* is issued to the app. This first token is used *only for registering a specific instance of the application*. To limit this token's usage, it has a *special scope* called ***dcr***. This initial access token can then be used by the app to dynamically register itself (DCR).

With an initial access token in hand, the client can register itself. To do so, it will make an API call to the Dynamic Client Registration endpoint (/client). This endpoint is protected and requires an OAuth access token to be presented in the Authorization request header using the bearer authentication scheme (per RFC 6750): the initial access token.

Dynamic clients can be based on an existing client that is configured to be a template. Registration of a new client that is to be based on another is also very easy; there is only one request parameter: software_id. This ID (as defined in RFC 7591) is the client ID of the template client. No other settings need to be included in the request, and, if there are any, Curity will ignore them. The settings are always taken from the template.

The values in the response are taken from template identified by the software_id input parameter.
The client ID used for the software_id is only acceptable if that client is a template.

When using HTTP to send a JAR for DCR the HTTP header `Content-type` is `application/x-www-form-urlencoded` as defined in the OpenID specification.

The "request" parameter of the HTTP request (other are ignored as per the FAPI specification) is serialized using Form Serialization (OICD Core - Section 13.2).

Note: the Request Object specifies the type of data in this way:
- the **"typ"** in the JWS header is *"jwt"*.
- the **"cty"** in the JWS header of the Request is *"didcomm-signed+json"*.
- the **"type"** in the JWS payload of the Request is *"data-jar"*.
- the **"type"** in the Primary Document (within the *"body"* property in the payload) defines the Primary Document itself.

### **Creating a compact JWT/DIDComm for a DCR Request Form**

#### **Payload of the JWS/jar-didcomm-signed+json message**

The payload of the JWS/DIDComm signed message requires a *"body"* property to include specific attributes and data for the protocol as per the [DIDComm specification](https://identity.foundation/didcomm-messaging/spec/#plaintext-message-structure), which is a Primary Document as per the [JSON:API specification](https://jsonapi.org/format/#document-top-level).

In this way, the JAR receives from a client app a Primary Document contained in the *"body"* property, which in case of DCR has only one Resource Object in the "data" property ([JSON:API specification](https://jsonapi.org/format/#document-resource-objects)).

As per the Financial-grade API Security ([FAPI 1.0 Advanced - Section 5.2.2: Authorization Server](https://openid.net/specs/openid-financial-api-part-2-1_0-final.html#authorization-server) and [FAPI 2.0 Security Profile - Section 4.3.1.2: Authorization Code Flow](https://openid.bitbucket.io/fapi/fapi-2_0-security.html#section-4.3.1.2), the DIDComm specification and the OpenID specification, the JWT payload ([request object, RFC9101](https://www.rfc-editor.org/rfc/rfc9101.html#section-2.1)))
requires the following:

*Note: the "id" property (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID*
shall send the aud claim in the request object as the OP’s Issuer Identifier URL;
- the **"type"** (*required for DIDComm*) property is set in UHC as *"data+jar"* or *"profile-code+jar"* to predict the content of the message.
- the **"body"** (*required for DIDComm*) property has a JSON:API Primary Document, which can include one or more Resource Objects in its "data" property and one or more DIDComm "attachments" within each Resource Object.
- the **"aud"** (*required for FAPI*) property in the request object (it can be the same as the "aud" in an access token) is in UHC the URL of the issuer's service for the client app (a resolved DID fragment contains the full URL but not just the issuer URL). The URL of the issuer's service identifies at the same time the *"software_id"* URL and the OP's Issuer Identifier URL as the intended audience. The final endpoint MUST verify that it is an intended audience.

  *Examples:*

  `https://identity.professional.organization-name.hospital.app` for `did:legal:health:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94?service=identity-transaction`
  `https://connections.professional.organization-name.hospital.app` for `did:legal:health:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94?service=connection-transaction`

- the **"scope"** (*required*) property value contains *"openid"*. Additionally, when an admin is creating a new profile for an employee, more permissions can be included in the "scope" property by using the [SMART-On-FHIR v2 permissions format](https://www.hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html#scopes-for-requesting-clinical-data).
- the **"response_type"** (*required*) property value contains *"data"*.
- the **"response_mode"** (*required*) property value is *"jwt"* or *"form_post.jwt"* (both has the same effect).
- the **"nbf"** (*required*) property is no longer than *60 minutes* in the past (JSON numeric value representing the number of seconds from the UNIX epoch).
- the **"exp"** (*required*) property has a lifetime of no longer than *60 minutes* after the *"nbf"* property (JSON numeric value representing the number of seconds from the UNIX epoch).

  NOTE: Set the validity period of the authorization code (expiration) to one minute or a suitable short period of time if not replay is possible. The validity period may act as a cache control indicator of when to clear the authorization code cache if one is used ([FAPI 2.0 Baseline Profile - Section 2.2.1 - second note](https://openid.net/specs/fapi-2_0-baseline.html#section-2.2.1)).

  When an admin is creating an install-code for a practitioner profile, a custom expiration can be established (between 1-60 minutes).

- the **"client_id"** (*required*) is used in the federated network to identify the DID of the entity sending a JAR message (same as the DIDComm *"from"* property) to some endpoint service defined in an organization's DID Document (the wallet`s keyID is in the JWT header). In UHC, it can be an employee who performs a role in a department, a patient or patient's related person, a patient's medical device or a department's medical device).

  *Examples:*
  `did:legal:health:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94:Department:uuid:9fa1c633-a3df-4cc8-bbb7-6f1bb2775c89:Practitioner:uuid:ed8206a7-1623-4b07-863a-3a8bc049fe05:PractitionerRole:type:Supervisor`

  `did:legal:healthcare:ES:ES-CL:ES-SO:PractitionerRole:2.16.840.1.113883|0203|MD:<ProfessionalLicenseNumber>:Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94:Device:uuid:<uuid>:Software:dns:custom-app.organization-name.example.com`

  `did:legal:healthcare:ES:::Person:2.16.840.1.113883|0203|NN:<NationalIdentityNumber>:Device:apns:<pushToken>:Software:dns:custom-app.organization-name.example.com`

  *or*

  `did:legal:health:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94:HealthcareService:uuid:097c1d6c-4622-4511-a908-4417edda459c:Practitioner:uuid:77166e58-d08b-42b8-8370-480f82feded3:PractitionerRole:HL7|0203|MD:license-MD-ES-1`


- the **"subject"** (*required*) property refers in UHC to the target DID (e.g.: the organization's DID when sending CRUDS operations for departments and / or employees management).

  *Example:*

  `did:legal:health:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94`

- the **"jti"** (*required*) property is a unique identifier for the JWT (*JWT ID*), which can be used to prevent reuse of the request (replay attacks).
- the **"redirect_url"** (*optional*):

*Notes*:
1) *the "id" property (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID.*
2) *the "iss" property is not used in a JAR.*
