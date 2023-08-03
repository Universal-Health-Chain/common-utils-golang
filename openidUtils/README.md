![UHC-Logo](https://avatars.githubusercontent.com/u/57396025?s=200&v=4)

[Go to main](../README.md)

# OpenID Utils

This package contains funtions, structs and methods to implement OIDC and FAPI.

## **[OIDC (OpenID Connect)](https://openid.net/connect/)**

OpenID is an open standard and decentralized authentication protocol promoted by the non-profit OpenID Foundation. It allows users to be authenticated by co-operating sites (known as relying parties, or RP) using a third-party OpenID provider service (OP).

OIDC is an identity layer on top of the [OAuth 2.0 protocol](https://oauth.net/2/). It enables Clients to verify the identity of the End-User. Specifically, a system entity called an OpenID Provider (OP) can issue JSON-formatted identity tokens and verified claims to OIDC relying parties (RP) via a RESTful HTTP API (the OP is the an identity service). The OP establishes trust with other applications and services while using a single digital identity (it can be a DID with a universal health identifier for training and health).

Federated identity is a way to use an account from one identity service (OP) to create an account and log in to a different site. There are two main players in a federated identity system: an OpenID Provider (OP) and a Service Provider (SP), which is a relaying party (RP, e.g.: an API service distinct to the OP).

### **[OIDC Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)**

OIDC Issuer discovery is the process of determining the location of the OpenID Provider. It is optional in case of a Relying Party (e.g.: a client app) can know the OP's Issuer location through an out-of-band mechanism. For example, a DIDComm OOB message encoded in a QR code can be scanned by a client app to get the configuration information of an OIDC Issuer.

When a client app have to retrieve online the configuration information of an OIDC Issuer, it is required to be accesible in the Issuer's *well-known* location, e.g.: `https://identity.organization-name.example.com/.well-known/openid-configuration`. This *discovery* document has the ***"issuer"*** endpoint, which is the OICD Issuer URL (*https* URL scheme with no query or fragment component, e.g.: `https://identity.organization-name.example.com/`). Both access tokens and responses issued will contain the Issuer URL in the "iss" payload's field, and all the requests and access tokens accepted by the Issuer ([FAPI Security Profile 1.0 - Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server)) will contain at least this Issuer URL in the audience field ("aud").


## **[Financial-grade API (FAPI)](https://fapi.openid.net/)**

Financial-grade API (FAPI) is an industry-led specification developed by the OpenID Foundation.

While the [FAPI 2.0 Security Profile](https://oauth.net/fapi/) was initially developed with a focus on financial applications, it is designed to be universally applicable for protecting APIs exposing high-value and sensitive (personal and other) data, for example, in e-health and e-government applications.

FAPI utilizes both JWT-secured authorisation request (JAR) and JWT-secured authorisation response (JARM).


## **[JWT-secured authorisation request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)**

When using the HTTP protocol and the HTTP POST method, the parameters of the HTTP request are serialized using Form Serialization (OICD Core - Section 13.2).

The HTTP header  `Content-type` is `application/x-www-form-urlencoded`.

Although different parameters are required as per OAuth 2.0, OpenID and JAR specifications, **FAPI ignore all except the** ***"request"*** **parameter**, which in FAPI it is a compact JWS containing the Request Object as payload.

The parameters for the HTTP request are explained below:

- **"request"**: the JWT data container, named ***"Request Object"***, in compact JWT serialization.

- **"client_id"**: duplicated from the *Request Object's* payload (required by Section 5 of JAR, but **ignored by FAPI and UHC**).

Additionally, **if the client app is not using pushed authentication request (PAR)**, the client app can send duplicates of the **"response_type"** and **"scope"** parameters/values using the OAuth 2.0 request syntax as required by Section 6.1 of the OpenID Connect specification, but they are **ignored by FAPI and UHC specifications**.


## **[JWT-secured authorisation response (JARM)](https://openid.net/specs/oauth-v2-jarm.html)**

The JWT data container is named "Response Document". The Response Document can be sent in an HTTP response in two different ways, depending on the *"response_type"* property specified in the JAR: 

- As a Redirect URL, with the Response Document in compact JWT as the "response" parameter.

- As a [Form Post Response](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html), where the OP returns an HTML web page containing an HTML form with the Response Document in compact JWT as the "response" parameter in the HTML form. The HTML web page contains a script to cause the auto-submission of the form the Client software application, so the Client will be able to process the message without regard for the mechanism by which the form submission was initiated.


## **UHC messaging encapsulation**

UHC extends OIDC and FAPI with both DIDComm and JSON:API specificactions and uses Post-Quantum Computing (PQC) algorithms instead of the traditional non-PQC resistant ones. See [DIDComm Utils](../didcommUtils/README.md).