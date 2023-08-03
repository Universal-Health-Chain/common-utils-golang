
![logo](https://avatars.githubusercontent.com/u/57396025?s=200&v=4)

# [**JWT-secured authorisation request (JAR) with DIDComm envelope**](./README.md)

## ** Dynamic Client Registration request (DCR) - DIDComm envelope**

Based on the [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html), to register a new native Client application (software ID) at the Authorization Server (AS):
- an administrator sends a JAR with any Client Metadata parameters that the administrator specify during the registration.
- the *AS* assigns to the new Client app a unique Client Identifier (*"client_id"*) which is the reverse DNS provided by the administrator as *"software_id"* in the request, and associates the Metadata given in the request with this Client Identifier. 

