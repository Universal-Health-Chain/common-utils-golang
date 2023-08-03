package openidUtils

// Federated OpenID device-local mode: https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-07.html
// For every authentication request, the native user experience first checks whether this request can be fulfilled
// using the locally stored credentials. If so, it generates a presentation signed with the user's keys
// in order to prevent replay of the credential.This approach dramatically reduces latency
// and reduces load on the OP's servers. Moreover, the user identification, authentication, and authorization
// can be done even in situations with unstable or no internet connectivity.

// Presentation Definition: https://identity.foundation/presentation-exchange/#presentation-definition

// PresentationDefinition properties are for use at the top-level of a Presentation Definition.
// Any properties that are not defined below MUST be ignored, unless otherwise specified by a Feature.
//
// - id - The Presentation Definition MUST contain an id string property. The string SHOULD provide a unique ID for the desired context.
// 	 For example, a UUID such as 32f54163-7166-48f1-93d8-f f217bdb0653 could provide an ID that is unique in a global context, while a simple string such as my_presentation_definition_1 could be suitably unique in a local context.
//
// - name - The Presentation Definition MAY contain a name property.
//   If present, its value SHOULD be a human-friendly string intended to constitute a distinctive designation of the Presentation Definition.
//
// - purpose - The Presentation Definition MAY contain a purpose property.
//    If present, its value MUST be a string that describes the purpose for which the Presentation Definition's inputs are being used for.
//
// - format - Some envelope transport protocols may include the value of this property in other locations and use different property names
//   (See the Format Embed Locations section for details), but regardless of whether it resides at the default location (the format property of the presentation_definition object),
//   the value MUST be an object with one or more properties matching the registered Claim Format Designations
//   (e.g., jwt, jwt_vc, jwt_vp, etc.).
//   The properties inform the Holder of the Claim format configurations the Verifier can process.
//   The value for each claim format property MUST be an object and the object MUST include a format-specific property
//   (i.e., alg or proof_type)
//
// - 'input_descriptors': The Presentation Definition MUST contain an 'input_descriptors' property.
//	 Its value MUST be an array of Input Descriptor Objects, the composition of which are described in the Input Descriptors section below.
type PresentationDefinition struct {
	ID               string                        `json:"id,omitempty" bson:"id,omitempty"`
	Name             string                        `json:"name,omitempty" bson:"name,omitempty"`
	Purpose          string                        `json:"purpose,omitempty" bson:"purpose,omitempty"`
	Format           []PresentationInputFormat     `json:"format,omitempty" bson:"format,omitempty"`
	InputDescriptors []PresentationInputDescriptor `json:"input_descriptors,omitempty" bson:"input_descriptors,omitempty"`
}

type PresentationInputFormat struct {
	Jwt   *PresentationInputFormatAlg   `json:"jwt,omitempty" bson:"jwt,omitempty"`
	JwtVC *PresentationInputFormatAlg   `json:"jwt_vc,omitempty" bson:"jwt_vc,omitempty"`
	JwtVP *PresentationInputFormatAlg   `json:"jwt_vp,omitempty" bson:"jwt_vp,omitempty"`
	Ldp   *PresentationInputFormatProof `json:"ldp,omitempty" bson:"ldp,omitempty"`
	LdpVC *PresentationInputFormatProof `json:"ldp_vc,omitempty" bson:"ldp_vc,omitempty"`
	LdpVP *PresentationInputFormatProof `json:"ldp_vp,omitempty" bson:"ldp_vp,omitempty"`
}

type PresentationInputFormatAlg struct {
	Alg []string `json:"alg,omitempty" bson:"alg,omitempty"`
}

type PresentationInputFormatProof struct {
	Proof []string `json:"proof,omitempty" bson:"proof,omitempty"`
}

// PresentationInputDescriptor fields are required for submission, unless otherwise specified by a Feature.
// - MUST contain an 'id' property. The value of the id property MUST be a string that does not conflict with the id of another Input Descriptor Object in the same Presentation Definition.
// - MAY contain a 'name' property. If present, its value SHOULD be a human-friendly name that describes what the target schema represents.
// - MAY contain a 'purpose' property. If present, its value MUST be a string that describes the purpose for which the Claim's data is being requested.
// - MAY contain a 'format' property. If present, its value MUST be an object with one or more properties matching the registered Claim Format Designations (e.g., jwt, jwt_vc, jwt_vp, etc.).
//   This format property is identical in value signature to the top-level format object, but can be used to specifically constrain submission of a single input to a subset of formats or algorithms.
// - MAY contain a 'limit_disclosure' property. If present, its value MUST be 'required' or 'preferred'
// 	 Omission of the limit_disclosure property indicates the Conformant Consumer MAY submit a response that contains more than the data described in the fields array.
//	 - required: This indicates that the Conformant Consumer MUST limit submitted fields to those listed in the fields array (if present).
//		Conformant Consumers are not required to implement support for this value, but they MUST understand this value sufficiently to return nothing (or cease the interaction with the Verifier) if they do not implement it.
// 	 - preferred: This indicates that the Conformant Consumer SHOULD limit submitted fields to those listed in the fields array (if present).
// - MAY contain a constraints property. If present, its value MUST be an object composed by , unless otherwise specified by a Feature.
type PresentationInputDescriptor struct {
	ID          string                       `json:"id,omitempty" bson:"id,omitempty"`
	Name        string                       `json:"name,omitempty" bson:"name,omitempty"`
	Purpose     string                       `json:"purpose,omitempty" bson:"purpose,omitempty"`
	Format      []PresentationInputFormat    `json:"format,omitempty" bson:"format,omitempty"`
	Constraints PresentationInputConstraints `json:"constraints,omitempty" bson:"constraints,omitempty"`
}

// The PresentationInputConstraints object MAY contain
// - fields property: SHALL be processed forward from 0-index, so if a Verifier desires to reduce processing by checking the most defining characteristics of a credential (e.g the type or schema of a credential) implementers SHOULD order these field checks before all others to ensure earliest termination of evaluation.
//   If the fields property is present, its value MUST be an array of objects composed by path, id, purpose, filter properties
type PresentationInputConstraints struct {
	Fields []PresentationInputConstraintFields `json:"fields,omitempty" bson:"fields,omitempty"`
}

// The PresentationInputConstraintsFields object MAY contain
// -  MUST contain a path property. The value of this property MUST be an array of one or more JSONPath string expressions
//	  (as defined in the JSONPath Syntax Definition section) that select a target value from the input.
//	  The array MUST be evaluated from 0-index forward, breaking as soon as a Field Query Result is found (as described in Input Evaluation),
//	  which will be used for the rest of the entry’s evaluation. The ability to declare multiple expressions in this way allows the Verifier to account for format differences,
//	  for example: normalizing the differences in structure between JSON-LD/JWT-based Verifiable Credentials and vanilla JSON Web Tokens (JWTs) [RFC7519].
// -  MAY contain an id property. If present, its value MUST be a string that is unique from every other field object’s id property, including those contained in other Input Descriptor Objects.
// -  MAY contain a purpose property. If present, its value MUST be a string that describes the purpose for which the field is being requested.
// -  MAY contain a filter property, and if present its value MUST be a JSON Schema descriptor used to filter against the values returned from evaluation of the JSONPath string expressions in the path array.
type PresentationInputConstraintFields struct {
	ID      string `json:"id,omitempty" bson:"id,omitempty"`
	Path    string `json:"path,omitempty" bson:"path,omitempty"`
	Purpose string `json:"purpose,omitempty" bson:"purpose,omitempty"`
	Filter  string `json:"filter,omitempty" bson:"filter,omitempty"`
}

// RP can request selective disclosure or certain claims from a credential of a particular type
// and can also ask for alternative credentials being presented
//{
//    "id_token": {
//        "email": null
//    },
//    "vp_token": {
//        "presentation_definition": {
//            "id": "vp token example",
//            "submission_requirements": [
//                {
//                    "name": "Citizenship Information",
//                    "rule": "pick",
//                    "count": 1,
//                    "from": "A"
//                }
//            ],
//            "input_descriptors": [
//                {
//                    "id": "id card credential with constraints",
//                    "group": [
//                        "A"
//                    ],
//                    "format": {
//                        "ldp_vc": {
//                            "proof_type": [
//                                "Ed25519Signature2018"
//                            ]
//                        }
//                    },
//                    "constraints": {
//                        "limit_disclosure": "required",
//                        "fields": [
//                            {
//                                "path": [
//                                    "$.type"
//                                ],
//                                "filter": {
//                                    "type": "string",
//                                    "pattern": "IDCardCredential"
//                                }
//                            },
//                            {
//                                "path": [
//                                    "$.credentialSubject.given_name"
//                                ]
//                            },
//                            {
//                                "path": [
//                                    "$.credentialSubject.family_name"
//                                ]
//                            },
//                            {
//                                "path": [
//                                    "$.credentialSubject.birthdate"
//                                ]
//                            }
//                        ]
//                    }
//                },
//                {
//                    "id": "passport credential",
//                    "format": {
//                        "jwt_vc": {
//                            "alg": [
//                                "RS256"
//                            ]
//                        }
//                    },
//                    "group": [
//                        "A"
//                    ],
//                    "constraints": {
//                        "fields": [
//                            {
//                                "path": [
//                                    "$.vc.type"
//                                ],
//                                "filter": {
//                                    "type": "string",
//                                    "pattern": "PassportCredential"
//                                }
//                            }
//                        ]
//                    }
//                }
//            ]
//        }
//    }
//}

// Response: In case the OP returns verifiable presentation(s) in the vp_token with a matching _vp_token in the corresponding id_token.
//{
//    "iss": "https://self-issued.me/v2",
//    "aud": "https://book.itsourweb.org:3000/client_api/authresp/uhn",
//    "iat": 1615910538,
//    "exp": 1615911138,
//    "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
//    "sub_jwk": {
//        "kty": "RSA",
//        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...DKgw",
//        "e": "AQAB"
//    },
//    "auth_time": 1615910535,
//    "nonce": "960848874",
//    "_vp_token": {
//        "presentation_submission": {
//            "id": "Selective disclosure example presentation",
//            "definition_id": "Selective disclosure example",
//            "descriptor_map": [
//                {
//                    "id": "ID Card with constraints",
//                    "format": "ldp_vp",
//                    "path": "$[0]", // "$" if the vp_token has only a single presentation instead of an array
//                    "path_nested": {
//                        "format": "ldp_vc",
//                        "path": "$[0].verifiableCredential[0]"
//                    }
//                },
//                {
//                    "id": "Ontario Health Insurance Plan",
//                    "format": "jwt_vp",
//                    "path": "$[1].presentation",
//                    "path_nested": {
//                        "format": "jwt_vc",
//                        "path": "$[1].presentation.vp.verifiableCredential[0]"
//                    }
//                }
//            ]
//        }
//    }
//}
//
// and an example of the corresponding vp_token containing multiple verifiable presentations:
//[
//    {
//        "@context": [
//            "https://www.w3.org/2018/credentials/v1"
//        ],
//        "type": [
//            "VerifiablePresentation"
//        ],
//        "verifiableCredential": [
//            {
//                "@context": [
//                    "https://www.w3.org/2018/credentials/v1",
//                    "https://www.w3.org/2018/credentials/examples/v1"
//                ],
//                "id": "https://example.com/credentials/1872",
//                "type": [
//                    "VerifiableCredential",
//                    "IDCardCredential"
//                ],
//                "issuer": {
//                    "id": "did:example:issuer"
//                },
//                "issuanceDate": "2010-01-01T19:23:24Z",
//                "credentialSubject": {
//                    "given_name": "Fredrik",
//                    "family_name": "Str&#246;mberg",
//                    "birthdate": "1949-01-22"
//                },
//                "proof": {
//                    "type": "Ed25519Signature2018",
//                    "created": "2021-03-19T15:30:15Z",
//                    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
//                    "proofPurpose": "assertionMethod",
//                    "verificationMethod": "did:example:issuer#keys-1"
//                }
//            }
//        ],
//        "id": "ebc6f1c2",
//        "holder": "did:example:holder",
//        "proof": {
//            "type": "Ed25519Signature2018",
//            "created": "2021-03-19T15:30:15Z",
//            "challenge": "n-0S6_WzA2Mj",
//            "domain": "https://client.example.org/cb",
//            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
//            "proofPurpose": "authentication",
//            "verificationMethod": "did:example:holder#key-1"
//        }
//    },
//    {
//        "presentation":
//        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0
//        MzFjMjc2ZTEyZWNhYiNrZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxY
//        zI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzc
//        yI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxNTQxNDkzNzI0LCJpYXQiO
//        jE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY
//        29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd
//        3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZ
//        UNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjd
//        CI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IjxzcGFuIGxhbmc9J2ZyL
//        UNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAy
//        BND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp
//        8PHbF2HaWodQIoOBxxT-4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB
//        1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSioc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6R
//        txJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6V3tPgHeKXE94fz_QpYfg
//        --7kLsyBAfQGbg"
//    }
//]
