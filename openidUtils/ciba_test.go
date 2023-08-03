package openidUtils

// The Client Initiated Backchannel Authentication (CIBA) defines a protocol to support initiating authentication
// without user interaction from a Consumer Device.
// Authentication is performed via an Authentication Device by the user who also consents (if required) to the request.
// CIBA is also referred to as a decoupled flow.
// see https://curity.io/resources/learn/ciba-flow/

/*
FAPI 2.0 CHANGES:
https://darutk.medium.com/implementers-note-about-open-banking-brasil-78d3d612dfaf
- Clients must use PKCE in all cases now (except when adopting 'Advanced' and not using PAR - for backwards compatibility with existing ecosystems).
- Clarify servers must reject requests where nonce is missing when using scope=openid.
- A "x-fapi-customer-ip-address" containing a valid IPv4 or IPv6 address must be accepted
FAPI 2.0 ADVANCED CHANGES:
- Must reject request objects where the "exp" gives a lifetime of longer than 60 minutes.
- Must reject request objects where the "nbf" claim in request object is missing or is more than 60 minutes in the past.
- Requests that use PAR (if supported) must be rejected if they do not use PKCE (the requirement is not applied to non-PAR requests purely for backwards compatibility)
- JARM is now an alternative to OIDC (previously it was allowed to be offered in addition to OIDC).
- When using JARM, only the response type code is permitted.
- The 'aud' claim sent in the request object must be the OP's issuer (in UHC this is the business app reverse DNS such as app.hospital.es.reinasofiadecordoba)
- Clients must support sign+encrypted id tokens.

The CIBA grant type is an extension grant type as defined by Section 4.5 of OAuth 2.0 with the value: "urn:openid:params:grant-type:ciba"
OpenID Provider Metadata
    The following authorization server metadata parameters are introduced by this specification for OPs publishing their support of the CIBA flow and details thereof.

        backchannel_token_delivery_modes_supported: REQUIRED. JSON array containing one or more of the following values: poll, ping, and push.
        backchannel_authentication_endpoint: REQUIRED. URL of the OP's Backchannel Authentication Endpoint as defined in Section 7.
        backchannel_authentication_request_signing_alg_values_supported: OPTIONAL. JSON array containing a list of the NestedJWT signing algorithms (alg values) supported by the OP for signed authentication requests, which are described in Section 7.1.1. If omitted, signed authentication requests are not supported by the OP.
        backchannel_user_code_parameter_supported: OPTIONAL. Boolean value specifying whether the OP supports the use of the user_code parameter, with true indicating support. If omitted, the default value is false.

    The CIBA grant type is used in the grant_types_supported field of discovery metadata for OPs that support the ping or poll delivery modes.
    The supported client authentication methods and, when applicable, the associated NestedJWT signing algorithms of the OP's Backchannel Authentication Endpoint are the same as those indicated by the token_endpoint_auth_methods_supported and token_endpoint_auth_signing_alg_values_supported metadata parameters respectively.
Client Metadata
    Clients registering to use CIBA MUST indicate a token delivery mode. When using the ping or poll mode, the Client MUST include the CIBA grant type in the "grant_types" field. When using the ping or push mode, the Client MUST register a client notification endpoint. Clients intending to send signed authentication requests MUST register the signature algorithm that will be used. The following parameters are introduced by this specification:

        backchannel_token_delivery_mode: REQUIRED. One of the following values: poll, ping, or push.
        backchannel_client_notification_endpoint: REQUIRED if the token delivery mode is set to ping or push. This is the endpoint to which the OP will post a notification after a successful or failed end-user authentication. It MUST be an HTTPS URL.
        backchannel_authentication_request_signing_alg: OPTIONAL. The NestedJWT algorithm alg value that the Client will use for signing authentication requests, as described in Section 7.1.1. When omitted, the Client will not send signed authentication requests.
        backchannel_user_code_parameter: OPTIONAL. Boolean value specifying whether the Client supports the user_code parameter. If omitted, the default value is false. This parameter only applies when OP parameter backchannel_user_code_parameter_supported is true.

    The token_endpoint_auth_method indicates the registered authentication method for the client to use when making direct requests to the OP, including requests to both the token endpoint and the backchannel authentication endpoint.
Poll and Ping Modes with Pairwise Identifiers
    To use the Poll or Ping mode with Pairwise Pseudonymous Identifiers (PPIDs), the Client needs to register a URI that is of its ownership and use it during the authentication process in a way that demonstrates that the URI belongs to it, which allows the OP to consider the host component of that URI as the Sector Identifier for the pairwise identifier calculation per Section 8.1 of OpenID Connect Core.
    In OpenID Connect Core the sector_identifier_uri contains a document with a list of redirect_uris and the Sector Identifier is defined as either the host component of the sector_identifier_uri or if this is not provided then the host component of the redirect_uri.
    In CIBA Poll and Ping modes the jwks_uri is used in place of the redirect_uri. In CIBA Push mode the backchannel_client_notification_endpoint is used in place of the redirect_uri. In situations where the PPID must be shared among multiple RPs, then a sector_identifier_uri can be registered. This specification extends the purpose of the sector_identifier_uri such that it can contain jwks_uris and backchannel_client_notification_endpoints as well as redirect_uri.
    To support Pairwise Pseudonymous Identifiers in Ping and Poll modes, the RP must provide either a sector_identifier_uri or a jwks_uri at the registration phase when the urn:openid:params:grant-type:ciba grant type is registered. In that way, the OpenID Provider can use the host component of the sector_identifier_uri or jwks_uri as the Sector Identifier to generate the PPIDs for the Client.
    When an OpenID Provider that supports PPIDs receives a dynamic registration request for a Client that indicates that it wishes to use the Poll or Ping CIBA modes, it MUST check if a valid jwks_uri is set when the subject_type is pairwise. If a sector_identifier_uri is explicitly provided, then the jwks_uri must be included in the list of URIs pointed to by the sector_identifier_uri.
    But having registered a "jwks_uri" is not enough to use PPIDs, Client needs somehow to demonstrate that such "jwks_uri" belongs to it, which can be accomplished by proving possession of a private key corresponding to one of the public keys published at the "jwks_uri". Such proof can be demonstrated with signed authentication requests using the asymmetric keys provided by the "jwks_uri" or by authenticating to the OP using one of the following two mechanisms in conjunction with a key from its "jwks_uri":

        Using the Self-Signed Certificate Mutual TLS OAuth Client Authentication Method as defined in section 2.2 of [RFC8705].
        Using the private_key_jwt method as per section 9 Client Authentication of [OpenID.Core].

Push Mode with Pairwise Identifiers
When using the Push mode, the PPIDs will use the host component of the "backchannel_client_notification_endpoint" as the Sector Identifier.
In case a "sector_identifier_uri" is explicitly provided, then the
"backchannel_client_notification_endpoint" must be included in the list of URIs pointed to by the "sector_identifier_uri".

The following is a non-normative example from a dynamic registration request that contains
the CIBA grant type as required and a "jwks_uri" (with line wraps within values for display purposes only).
    POST /connect/register HttpHeaders/1.1
    Content-Type: application/json
    Accept: application/json
    Host: server.example.com
    Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...

    {
        "application_type": "web",
        "client_name": "My Example",
        "logo_uri": "https://client.example.org/logo.png",
        "subject_type": "pairwise",
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["urn:openid:params:grant-type:ciba"],
        "backchannel_token_delivery_mode": "poll",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks",
        "contacts": ["ve7jtb@example.org", "mary@example.org"]
    }


*/

/*
OAuth 2.0 Rich Authorization Requests
Request parameter "authorization_details": contains, in JSON notation, an array of objects.
Each JSON object contains the data to specify the authorization requirements for a certain type of resource.

Common data fields: This specification defines a set of common data fields:

   locations:  An array of strings representing the location of the
      resource or resource server.  These strings are typically URIs
      identifying the location of the RS.  This field can allow a client
      to specify a particular RS, as discussed in Section 12.
   actions:  An array of strings representing the kinds of actions to be
      taken at the resource.
   datatypes:  An array of strings representing the kinds of data being
      requested from the resource.
   identifier:  A string identifier indicating a specific resource
      available at the API.
   privileges:  An array of strings representing the types or levels of
      privilege being requested at the resource.

*/
