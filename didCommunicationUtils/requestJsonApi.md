![logo](https://avatars.githubusercontent.com/u/57396025?s=200&v=4)

  # [**JWT-secured authorisation request (JAR) with DIDComm envelope**](./README.md)

## **JSON:API request - DIDComm envelope**

When using HTTP to send a JAR JSON:API the HTTP header `Content-type` is `application/x-www-form-urlencoded` as defined in the OpenID specification, instead of "application/*vendor*.api+json" as defined in the [JSON:API specification](https://jsonapi.org/format/#jsonapi-media-type).

The "request" parameter of the HTTP request (other are ignored as per the FAPI specification) is serialized using Form Serialization (OICD Core - Section 13.2).

Note: the Request Object specifies the type of data in this way:
 - the **"typ"** in the JWS header is *"jwt"*.
 - the **"cty"** in the JWS header of the Request is *"didcomm-signed+json"*.
 - the **"type"** in the JWS payload of the Request is *"data-jar"*.
 - the **"type"** in the Primary Document (within the *"body"* property in the payload) defines the Primary Document itself (e.g.: it can be *"transaction"* or other types).

### **Creating a compact JWT/DIDComm for a JSON:API Request Form**

#### **Payload of the JWS/jar-didcomm-signed+json message**

The payload of the JWS/DIDComm signed message requires a *"body"* property to include specific attributes and data for the protocol as per the [DIDComm specification](https://identity.foundation/didcomm-messaging/spec/#plaintext-message-structure), which is a Primary Document as per the [JSON:API specification](https://jsonapi.org/format/#document-top-level).

In this way, the JAR receives from a client app a Primary Document contained in the *"body"* property, which has a one or more Resource Objects in the "data" property as per the [JSON:API specification](https://jsonapi.org/format/#document-resource-objects).

As an extension to the JSON:API Resource Object properties, UHC utilizes the DIDComm "attributes" property within each Resource Object instead of being used the JSON:API "included" property.

As per the Financial-grade API Security ([FAPI 1.0 Advanced - Section 5.2.2: Authorization Server](https://openid.net/specs/openid-financial-api-part-2-1_0-final.html#authorization-server) and [FAPI 2.0 Security Profile - Section 4.3.1.2: Authorization Code Flow](https://openid.bitbucket.io/fapi/fapi-2_0-security.html#section-4.3.1.2), the DIDComm specification and the JSON:API specification, the JWT payload ([request object, RFC9101](https://www.rfc-editor.org/rfc/rfc9101.html#section-2.1)))
requires the following:

*Note: the "id" property (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID*
shall send the aud claim in the request object as the OP’s Issuer Identifier URL;

- the **"type"** (*required for DIDComm*) property is set in UHC as *"data+jar"* to predict the content of the message.
  
- the **"body"** (*required for DIDComm*) property has a JSON:API Primary Document, which can include one or more Resource Objects in its "data" property and one or more DIDComm "attachments" within each Resource Object.
  
- the **"aud"** (*required for FAPI*) is the URL or the endpoint as appears in the DID Document of the OpenID service provider.

  *Examples:*

  `http://localhost:8006/cds-es/v1/resources/transaction` 

- the **"scope"** (*required*) property value contains *"openid"*.
  
- the **"response_type"** (*required*) property value contains *"data"*.
  
- the **"response_mode"** (*required*) property value is *"jwt"* or *"form_post.jwt"* (both has the same effect).
  
- the **"nbf"** (*required*) property is no longer than *60 minutes* in the past (JSON numeric value representing the number of seconds from the UNIX epoch).
  
- the **"exp"** (*required*) property has a lifetime of no longer than *60 minutes* after the *"nbf"* property (JSON numeric value representing the number of seconds from the UNIX epoch).

  NOTE: Set the validity period to one minute or a suitable short period of time if not replay is possible. ([FAPI 2.0 Baseline Profile - Section 2.2.1 - second note](https://openid.net/specs/fapi-2_0-baseline.html#section-2.2.1)).

- the **"client_id"** (*required*) is used in the federated network to identify the DID of the entity sending a JAR message (same as the DIDComm *"from"* property) to some endpoint service defined in an organization's DID Document (the wallet`s keyID is in the JWT header). In UHC, it can be an employee who performs a role in a department, a patient or patient's related person, a patient's medical device or a department's medical device).

  *Examples:*
  `did:legal:healthcare:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94:Department:uuid:9fa1c633-a3df-4cc8-bbb7-6f1bb2775c89:Practitioner:uuid:ed8206a7-1623-4b07-863a-3a8bc049fe05:PractitionerRole:type:Supervisor`

  *or*

  `did:legal:healthcare:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94:HealthcareService:uuid:097c1d6c-4622-4511-a908-4417edda459c:Practitioner:uuid:77166e58-d08b-42b8-8370-480f82feded3:PractitionerRole:oid:2.16.840.1.113883.18.108|MD`


- the **"subject"** (*required*) property refers in UHC to the target DID (e.g.: the organization's DID when sending CRUDS operations for departments and / or employees management).

  *Example:*

  `did:legal:healthcare:ES::::Organization:uuid:e7f01da5-7cd4-4e7c-993f-f83659684a94`

- the **"jti"** (*required*) property is a unique identifier for the JWT (*JWT ID*), which can be used to prevent reuse of the request (replay attacks).
  
- the **"redirect_url"** (*optional*).

*Notes*:
1) *the "id" property (required in DIDComm) is ignored in UHC because "jti" is used for back-guard compatibility with OpenID.*
2) *the "iss" property is not used in a JAR.*