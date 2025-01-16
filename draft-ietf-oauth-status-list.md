---
title: "Token Status List"
category: info

docname: draft-ietf-oauth-status-list-latest
submissiontype: IETF  # also: "IETF", "IAB", or "IRTF"
number:
date:
v: 3
venue:
  github: "oauth-wg/draft-ietf-oauth-status-list"
  latest: "https://oauth-wg.github.io/draft-ietf-oauth-status-list/draft-ietf-oauth-status-list.html"

author:
 -
    fullname: Tobias Looker
    organization: MATTR
    email: tobias.looker@mattr.global
 -
    fullname: Paul Bastian
    email: paul.bastian@posteo.de
 -
    fullname: Christian Bormann
    organization: SPRIND
    email: chris.bormann@gmx.de

normative:
  RFC1950: RFC1950
  RFC1951: RFC1951
  RFC2046: RFC2046
  RFC3986: RFC3986
  RFC6125: RFC6125
  RFC6838: RFC6838
  RFC7515: RFC7515
  RFC7519: RFC7519
  RFC8259: RFC8259
  RFC8392: RFC8392
  RFC8725: RFC8725
  RFC8949: RFC8949
  RFC9052: RFC9052
  RFC9110: RFC9110
  RFC9596: RFC9596
  IANA.MediaTypes:
    author:
      org: "IANA"
    title: "Media Types"
    target: "https://www.iana.org/assignments/media-types/media-types.xhtml"
  IANA.JOSE:
    author:
      org: "IANA"
    title: "JSON Object Signing and Encryption (JOSE)"
    target: "https://www.iana.org/assignments/jose/jose.xhtml"
  IANA.JWT:
    author:
      org: "IANA"
    title: "JSON Web Token Claims"
    target: "https://www.iana.org/assignments/jwt/jwt.xhtml"
  IANA.CWT:
    author:
      org: "IANA"
    title: "CBOR Web Token (CWT) Claims"
    target: "https://www.iana.org/assignments/cwt/cwt.xhtml"
  IANA.OAuth.Params:
    author:
      org: "IANA"
    title: "OAuth Authorization Server Metadata"
    target: "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata"
  CORS:
    author:
      org: "WHATWG"
    title: "Fetch Living Standard"
    target: "https://fetch.spec.whatwg.org/#http-cors-protocol"

informative:
  RFC6749: RFC6749
  RFC7662: RFC7662
  RFC7800: RFC7800
  RFC8414: RFC8414
  RFC9458: RFC9458
  SD-JWT.VC: I-D.ietf-oauth-sd-jwt-vc
  ISO.mdoc:
    author:
      org: "ISO/IEC JTC 1/SC 17"
    title: "ISO/IEC 18013-5:2021 ISO-compliant driving licence"


--- abstract

This specification defines a mechanism, data structures and processing rules for representing the status of tokens secured by JSON Object Signing and Encryption (JOSE) or CBOR Object Signing and Encryption (COSE), such as JWT, SD-JWT VC, CBOR Web Token and ISO mdoc. It also defines an extension point and a registry for future status mechanisms.

--- middle

# Introduction

Token formats secured by JOSE {{IANA.JOSE}} or COSE {{RFC9052}}, such as JWTs {{RFC7519}}, SD-JWT VCs {{SD-JWT.VC}}, CWTs {{RFC8392}} and ISO mdoc {{ISO.mdoc}}, have vast possible applications. Some of these applications can involve issuing a token whereby certain semantics about the token or its validity may change over time. Communicating these changes to relying parties in an interoperable manner, such as whether the token is considered invalidated or suspended by its issuer, is important for many of these applications.

This document defines a Status List data structure that describes the individual statuses of multiple Referenced Tokens. A Referenced Token may be of any format, but is most commonly a data structures secured by JOSE or COSE. The Referenced Token is referenced by the Status List, which described the status of the Referenced Token. The statuses of all Referenced Tokens are conveyed via a bit array in the Status List. Each Referenced Token is allocated an index during issuance that represents its position within this bit array. The value of the bit(s) at this index correspond to the Referenced Token's status. A Status List is provided within a Status List Token protected by cryptographic signature or MAC and this document defines its representations in JWT and CWT format.

The following diagram depicts the relationship between the artifacts:

~~~ ascii-art

┌────────────────┐  describes status ┌──────────────────┐
│  Status List   ├──────────────────►│ Referenced Token │
│ (JSON or CBOR) │◄──────────────────┤  (JOSE or COSE)  │
└─────┬──────────┘    references     └──────────────────┘
      │
      │ embedded in
      ▼
┌───────────────────┐
│ Status List Token │
│  (JWT or CWT)     │
└───────────────────┘

~~~

An Issuer issues Referenced Tokens to a Holder, the Holder uses and presents those Referenced Tokens to a Relying Party. The Issuer gives updated status information to the Status Issuer, who creates a Status List Token. The Status Issuer provides the Status List Token to the Status Provider, who serves the Status List Token on a public, resolvable endpoint. The roles of the Issuer (of the Referenced Token), the Status Issuer and the Status Provider may be fulfilled by the same entity. If not further specified, the term Issuer may refer to an entity acting for all three roles. This document describes how an Issuer references a Status List Token and how a Relying Party fetches and validates Status Lists.

The following diagram depicts the relationship between the involved roles (Relying Party is equivalent to Verifier of {{SD-JWT.VC}}):

~~~ ascii-art

           issue                 present
           Referenced            Referenced
┌────────┐ Token      ┌────────┐ Token      ┌───────────────┐
│ Issuer ├───────────►│ Holder ├───────────►│ Relying Party │
└─┬──────┘            └────────┘            └──┬────────────┘
  ▼ update status                              │
┌───────────────┐                              │
│ Status Issuer │                              │
└─┬─────────────┘                              │
  ▼ provide Status List                        │
┌─────────────────┐         fetch Status List  │
│ Status Provider │◄───────────────────────────┘
└─────────────────┘

~~~

Status Lists may be composed for expressing a range of Status Types. This document defines basic Status Types for the most common use cases as well as an extensibility mechanism for custom Status Types.

Furthermore, the document defines an extension point that enables other specifications to describe additional status mechanisms and creates an IANA registry.

## Example Use Cases

An example for the usage of a Status List is to manage the status of issued access tokens as defined in section 1.4 of {{RFC6749}}. Token Introspection {{RFC7662}} defines another way to determine the status of an issued access token, but it requires the party trying to validate an access tokens status to directly contact the token issuer, whereas the mechanism defined in this specification does not have this limitation.

Another possible use case for the Status List is to express the status of verifiable credentials (Referenced Tokens) issued by an Issuer in the Issuer-Holder-Verifier model {{SD-JWT.VC}}.

## Rationale

Revocation mechanisms are an essential part for most identity ecosystems. In the past, revocation of X.509 TLS certificates has been proven difficult. Traditional certificate revocation lists (CRLs) have limited scalability; Online Certificate Status Protocol (OCSP) has additional privacy risks, since the client is leaking the requested website to a third party. OCSP stapling is addressing some of these problems at the cost of less up-to-date data. Modern approaches use accumulator-based revocation registries and Zero-Knowledge-Proofs to accommodate for this privacy gap, but face scalability issues again.

This specification seeks to find a balance between scalability, security, and privacy by minimizing the status information to mere bits (often a single bit) and compressing the resulting binary data. Thereby, a Status List may contain statuses of many thousands or millions Referenced Tokens while remaining as small as possible. Placing large amounts of Referenced Tokens into the same list also enables herd privacy relative to the Status Provider.

## Design Considerations

The decisions taken in this specification aim to achieve the following design goals:

* the specification shall favor a simple and easy to understand concept
* the specification shall be easy, fast and secure to implement in all major programming languages
* the specification shall be optimized to support the most common use cases and avoid unnecessary complexity of corner cases
* the Status List shall scale up to millions of tokens to support large scale government or enterprise use cases
* the Status List shall enable caching policies and offline support
* the specification shall support JSON and CBOR based tokens
* the specification shall not specify key resolution or trust frameworks
* the specification shall design an extension point to convey information about the status of a token that can be re-used by other mechanisms

## Status Mechanism Registry

This specification establishes the IANA "Status Mechanisms" registry for status mechanism and registers the members defined by this specification. Other specifications can register other members used for status retrieval. Other status mechanisms may have different tradeoffs regarding security, privacy, scalability adn complexity. The privacy and security considerations in this document only represent the properties of the Status List mechanism.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Issuer:
: An entity that issues the Referenced Token.

Status Issuer:
: An entity that issues the Status List Token about the status information of the Referenced Token. This role may be fulfilled by the Issuer.

Status Provider:
: An entity that provides the Status List Token on a public endpoint. This role may be fulfilled by the Status Issuer.

Holder:
: An entity that receives Referenced Tokens form the Issuer and presents them to Relying Parties.

Relying Party:
: An entity that relies on the Status List Token to validate the status of the Referenced Token. Also known as Verifier.

Status List:
: An object in JSON or CBOR representation containing a bit array that lists the statuses of many Referenced Tokens.

Status List Token:
: A token in JWT or CWT representation that contains a cryptographically secured Status List.

Referenced Token:
: A cryptographically secured data structure which contains a reference to a Status List Token. It is RECOMMENDED to use JSON {{RFC8259}} with JOSE as defined in {{RFC7515}} or CBOR {{RFC8949}} with COSE as defined in {{RFC9052}}. The information from the contained Status List gives the Relying Party additional information about the current status of the Referenced Token. Examples for Referenced Tokens are SD-JWT VC and ISO mdoc.

base64url:
: Denotes the URL-safe base64 encoding without padding as defined in Section 2 of {{RFC7515}} as "Base64url Encoding".

# Status List {#status-list}

A Status List is a byte array that contains the statuses of many Referenced Tokens represented by one or multiple bits. A common representation of a Status List is composed by the following algorithm:

1. Each status of a Referenced Token MUST be represented with a bit-size of 1,2,4, or 8. Therefore up to 2,4,16, or 256 statuses for a Referenced Token are possible, depending on the bit-size. This limitation is intended to limit bit manipulation necessary to a single byte for every operation and thus keeping implementations simpler and less error prone.

2. The overall Status List is encoded as a byte array. Depending on the bit-size, each byte corresponds to 8/(#bit-size) statuses (8,4,2, or 1). The status of each Referenced Token is identified using the index that maps to one or more specific bits within the byte array. The index starts counting at 0 and ends with "size" - 1 (being the last valid entry). The bits within an array are counted from least significant bit "0" to the most significant bit ("7"). All bits of the byte array at a particular index are set to a status value.

3. The byte array is compressed using DEFLATE {{RFC1951}} with the ZLIB {{RFC1950}} data format. Implementations are RECOMMENDED to use the highest compression level available.

The following example illustrates a Status List that represents the statuses of 16 Referenced Tokens, requiring 16 bits (2 bytes) for the uncompressed byte array:

~~~ ascii-art

status[0] = 1
status[1] = 0
status[2] = 0
status[3] = 1
status[4] = 1
status[5] = 1
status[6] = 0
status[7] = 1
status[8] = 1
status[9] = 1
status[10] = 0
status[11] = 0
status[12] = 0
status[13] = 1
status[14] = 0
status[15] = 1
~~~

These bits are concatenated:

~~~ ascii-art

byte             0                  1               2
bit       7 6 5 4 3 2 1 0    7 6 5 4 3 2 1 0    7
         +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+  +-+...
values   |1|0|1|1|1|0|0|1|  |1|0|1|0|0|0|1|1|  |0|...
         +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+  +-+...
index     7 6 5 4 3 2 1 0   15   ...  10 9 8   23
         \_______________/  \_______________/
                0xB9               0xA3

~~~

## Status List in JSON Format {#status-list-json}

This section defines the data structure for a JSON-encoded Status List:

* `status_list`: REQUIRED. JSON Object that contains a Status List. It MUST contain at least the following claims:
   * `bits`: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the Status List (`lst`). The allowed values for `bits` are 1,2,4 and 8.
   * `lst`: REQUIRED. JSON String that contains the status values for all the Referenced Tokens it conveys statuses for. The value MUST be the base64url-encoded Status List as specified in [](#status-list).
   * `aggregation_uri`: OPTIONAL. JSON String that contains a URI to retrieve the Status List Aggregation for this type of Referenced Token. See section [](#aggregation) for further detail.

The following example illustrates the JSON representation of the Status List:

~~~~~~~~~~
{::include ./examples/status_list_encoding_json}
~~~~~~~~~~

## Status List in CBOR Format {#status-list-cbor}

This section defines the data structure for a CBOR-encoded Status List:

* The `StatusList` structure is a map (Major Type 5) and defines the following entries:
  * `bits`: REQUIRED. Unsigned integer (Major Type 0) that contains the number of bits per Referenced Token in the Status List. The allowed values for `bits` are 1, 2, 4 and 8.
  * `lst`: REQUIRED. Byte string (Major Type 2) that contains the Status List as specified in [](#status-list).
  * `aggregation_uri`: OPTIONAL. Text string (Major Type 3) that contains a URI to retrieve the Status List Aggregation for this type of Referenced Token. See section [](#aggregation) for further detail.

The following example illustrates the CBOR representation of the Status List in Hex:

~~~~~~~~~~
{::include ./examples/status_list_encoding_cbor}
~~~~~~~~~~

The following is the CBOR Annotated Hex output of the example above:

~~~~~~~~~~
{::include ./examples/status_list_encoding_cbor_diag}
~~~~~~~~~~

# Status List Token {#status-list-token}

A Status List Token embeds the Status List into a token that is cryptographically signed and protects the integrity of the Status List. This allows for the Status List Token to be hosted by third parties or be transferred for offline use cases.

This section specifies Status List Tokens in JSON Web Token (JWT) and CBOR Web Token (CWT) format.

## Status List Token in JWT Format {#status-list-token-jwt}

The Status List Token MUST be encoded as a "JSON Web Token (JWT)" according to {{RFC7519}}.

The following content applies to the JWT Header:

* `typ`: REQUIRED. The JWT type MUST be `statuslist+jwt`.

The following content applies to the JWT Claims Set:

* `sub`: REQUIRED. As generally defined in {{RFC7519}}. The `sub` (subject) claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the `uri` claim contained in the `status_list` claim of the Referenced Token.
* `iat`: REQUIRED. As generally defined in {{RFC7519}}. The `iat` (issued at) claim MUST specify the time at which the Status List Token was issued.
* `exp`: OPTIONAL. As generally defined in {{RFC7519}}. The `exp` (expiration time) claim, if present, MUST specify the time at which the Status List Token is considered expired by the Status Issuer.
* `ttl`: OPTIONAL. The `ttl` (time to live) claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number encoded in JSON as a number.
* `status_list`: REQUIRED. The `status_list` (status list) claim MUST specify the Status List conforming to the rules outlined in [](#status-list-json).

The following additional rules apply:

1. The JWT MAY contain other claims.

2. The JWT MUST be secured using a cryptographic signature or MAC algorithm. Relying Parties MUST reject JWTs with an invalid signature.

3. Relying Parties MUST reject JWTs that are not valid in all other respects per "JSON Web Token (JWT)" {{RFC7519}}.

4. Application of additional restrictions and policy are at the discretion of the Relying Party.

The following is a non-normative example for a Status List Token in JWT format:

~~~~~~~~~~
{::include ./examples/status_list_jwt}
~~~~~~~~~~

## Status List Token in CWT Format {#status-list-token-cwt}

The Status List Token MUST be encoded as a "CBOR Web Token (CWT)" according to {{RFC8392}}.

The following content applies to the CWT protected header:

* `16` (type): REQUIRED. The type of the CWT MUST be `statuslist+cwt` as defined in {{RFC9596}}.

The following content applies to the CWT Claims Set:

* `2` (subject): REQUIRED. As generally defined in {{RFC8392}}. The subject claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the `uri` claim contained in the `status_list` claim of the Referenced Token.
* `6` (issued at): REQUIRED. As generally defined in {{RFC8392}}. The issued at claim MUST specify the time at which the Status List Token was issued.
* `4` (expiration time): OPTIONAL. As generally defined in {{RFC8392}}. The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer.
* `65534` (time to live): OPTIONAL. Unsigned integer (Major Type 0). The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number.
* `65533` (status list): REQUIRED. The status list claim MUST specify the Status List conforming to the rules outlined in [](#status-list-cbor).

The following additional rules apply:

1. The CWT MAY contain other claims.

2. The CWT MUST be secured using a cryptographic signature or MAC algorithm. Relying Parties MUST reject CWTs with an invalid signature.

3. Relying Parties MUST reject CWTs that are not valid in all other respects per "CBOR Web Token (CWT)" {{RFC8392}}.

4. Application of additional restrictions and policy are at the discretion of the Relying Party.

The following is a non-normative example for a Status List Token in CWT format in Hex:

~~~~~~~~~~
{::include ./examples/status_list_cwt}
~~~~~~~~~~

The following is the CBOR Annotated Hex output of the example above:

~~~~~~~~~~
{::include ./examples/status_list_cwt_diag}
~~~~~~~~~~

# Referenced Token {#referenced-token}

## Status Claim {#status-claim}

By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism to retrieve status information about this Referenced Token. The claim contains members used to reference to a Status List Token as defined in this specification. Other members of the "status" object may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1 of {{RFC7800}} in which different authenticity confirmation methods can be included.

## Referenced Token in JOSE {#referenced-token-jose}

The Referenced Token MAY be encoded as a "JSON Web Token (JWT)" according to {{RFC7519}} or other formats based on JOSE.

The following content applies to the JWT Claims Set:

* `status`: REQUIRED. The `status` (status) claim MUST specify a JSON Object that contains at least one reference to a status mechanism.
  * `status_list`: REQUIRED when the status mechanism defined in this specification is used. It contains a reference to a Status List Token. It MUST at least contain the following claims:
    * `idx`: REQUIRED. The `idx` (index) claim MUST specify an Integer that represents the index to check for status information in the Status List for the current Referenced Token. The value of `idx` MUST be a non-negative number, containing a value of zero or greater.
    * `uri`: REQUIRED. The `uri` (URI) claim MUST specify a String value that identifies the Status List Token containing the status information for the Referenced Token. The value of `uri` MUST be a URI conforming to {{RFC3986}}.

Application of additional restrictions and policy are at the discretion of the Relying Party.

The following is a non-normative example for a decoded header and payload of a Referenced Token:

~~~ ascii-art

{
  "alg": "ES256",
  "kid": "11"
}
.
{
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  }
}
~~~

SD-JWT-based Verifiable Credentials {{SD-JWT.VC}} introduce the usage of status mechanism in Section 3.2.2.2. The "status" object uses the same encoding as a JWT as defined in {{referenced-token-jose}}.

The following is a non-normative example for a Referenced Token in SD-JWT-VC serialized form as received from an Issuer:

~~~ ascii-art

eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb
Ikh2cktYNmZQVjB2OUtfeUNWRkJpTEZIc01heGNEXzExNEVtNlZUOHgxbGciXSwgImlz
cyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAw
LCAiZXhwIjogMTg4MzAwMDAwMCwgInN1YiI6ICI2YzVjMGE0OS1iNTg5LTQzMWQtYmFl
Ny0yMTkxMjJhOWVjMmMiLCAic3RhdHVzIjogeyJzdGF0dXNfbGlzdCI6IHsiaWR4Ijog
MCwgInVyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3N0YXR1c2xpc3RzLzEifX0sICJf
c2RfYWxnIjogInNoYS0yNTYifQ.-kgS-R-Z4DEDlqb8kb6381_gHHNatsoF1fcVKZk3M
06CrnV8F8k9d2w2V_YAOvgcb0f11FqDFezXBXH30d4vcw~WyIyR0xDNDJzS1F2ZUNmR2
ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJlbHVWN
U9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyI2S
Wo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~
WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ~WyJRZ19PN
jR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTN
EdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnU
nJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotR
GYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4V
GpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0~
~~~

Resulting payload of the example above:

~~~ ascii-art

{
  "_sd": [
    "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg"
  ],
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  },
  "_sd_alg": "sha-256"
}
~~~

## Referenced Token in COSE {#referenced-token-cose}

The Referenced Token MAY be encoded as a "COSE Web Token (CWT)" object according to {{RFC8392}} or other formats based on COSE.

The following content applies to the CWT Claims Set:

* `65535` (status): REQUIRED. The status claim is encoded as a `Status` CBOR structure and MUST include at least one data item that refers to a status mechanism. Each data item in the `Status` CBOR structure comprises a key-value pair, where the key must be a CBOR text string (Major Type 3) specifying the identifier of the status mechanism, and the corresponding value defines its contents. This specification defines the following data items:
  * `status_list` (status list): REQUIRED when the status mechanism defined in this specification is used. It has the same definition as the `status_list` claim in [](#referenced-token-jose) but MUST be encoded as a `StatusListInfo` CBOR structure with the following fields:
    * `idx`: REQUIRED. Unsigned integer (Major Type 0) The `idx` (index) claim MUST specify an Integer that represents the index to check for status information in the Status List for the current Referenced Token. The value of `idx` MUST be a non-negative number, containing a value of zero or greater.
    * `uri`: REQUIRED. Text string (Major Type 3). The `uri` (URI) claim MUST specify a String value that identifies the Status List Token containing the status information for the Referenced Token. The value of `uri` MUST be a URI conforming to {{RFC3986}}.

Application of additional restrictions and policy are at the discretion of the Relying Party.

The following is a non-normative example of a Referenced Token in CWT format in Hex:

~~~~~~~~~~
{::include ./examples/referenced_token_cwt}
~~~~~~~~~~

The following is the CBOR Annotated Hex output of the example above:

~~~~~~~~~~
{::include ./examples/referenced_token_cwt_diag}
~~~~~~~~~~

ISO mdoc {{ISO.mdoc}} may utilize the Status List mechanism by introducing the `status` parameter in the Mobile Security Object (MSO) as specified in Section 9.1.2. The `status` parameter uses the same encoding as a CWT as defined in {{referenced-token-cose}}.

It is RECOMMENDED to use `status` for the label of the field that contains the `Status` CBOR structure.

Application of additional restrictions and policy are at the discretion of the Relying Party.

The following is a non-normative example for an IssuerAuth as specified in ISO mDL (also referred to as signed MSO) in Hex:

~~~ ascii-art

8443a10126a118215901f3308201ef30820195a00302010202140bfec7da97e048e
15ac3dacb9eafe82e64fd07f5300a06082a8648ce3d040302302331143012060355
04030c0b75746f7069612069616361310b3009060355040613025553301e170d323
4313030313030303030305a170d3235313030313030303030305a30213112301006
035504030c0975746f706961206473310b300906035504061302555330593013060
72a8648ce3d020106082a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9
a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8983e1b37d3a539f4d5883
65e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301c0603551d1f0415
30133011a00fa00d820b6578616d706c652e636f6d301e0603551d1204173015811
36578616d706c65406578616d706c652e636f6d301d0603551d0e0416041414e290
17a6c35621ffc7a686b7b72db06cd12351301f0603551d2304183016801454fa238
3a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff04040302078030
150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d04030
20348003045022100b7103fd4b90529f50bd6f70c5ae5ce7f4f3d4d15a4e082812f
9fa1f5c2e5aa0a0220070b2822ec7ce6c56804923a85b2cfbffd054cf9a915f070c
fef7179a4bc6569590320d81859031ba766737461747573a16b7374617475735f6c
697374a26369647819019c63757269782168747470733a2f2f6578616d706c652e6
36f6d2f7374617475736c697374732f3167646f6354797065756f72672e69736f2e
31383031332e352e312e6d444c6776657273696f6e63312e306c76616c696469747
9496e666fa3667369676e6564c074323032342d31302d30315431333a33303a3032
5a6976616c696446726f6dc074323032342d31302d30315431333a33303a30325a6
a76616c6964556e74696cc074323032352d31302d30315431333a33303a30325a6c
76616c756544696765737473a1716f72672e69736f2e31383031332e352e31ac005
820a81d65ed5075fbd7ee19fa66e2bb3047ed826e2769873e7ef07c923da7a6f243
01582048701a9546492284d266ed81d439230a582d0e1f17a08ab1859a3efe98069
0a4025820d11fe48c8835b30bfb3895c3905436ddfb63f59ab9eee181b110985329
2a8f62035820a741bf05e20a8bc359e32426106ed0899b2c60262cc3acc637ddc99
41095fb7a045820ab67cb9a8f20a8572f77f02727367d08dc8e57fb89deb46b9c62
6e94457b7d8b055820bacddb4142b3842bd555206eb5acb27ded063294995c7e7fe
fbf93ece522604d065820bfd02b3aebdc05b53b5539226c38088d6d784b0ea0fab6
9eb9311650a48d325307582027dab70fe71da63e5e5d199e8ae5b79cbe8904bc30c
5b7544fb809e02ccb3e6a0858200dbd7ccc9c7727d3d17295f1b6f1914071670ee2
3d4d33530c31f1f406b8e3b7095820a5beb5efadf37f21637209abc519830681cc5
1f334818a823fec13b29552f5ba0a5820d8047c95f9272d7d07b2c13a9f5ac2ee02
380ab272a165e569391d89a2152c3c0b582004939930ffb4911ef03487a153605a3
0368b69f2437d6d21b4c90f92bc144c3e6d6465766963654b6579496e666fa16964
65766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c89
7dcd68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92
fa484caa722c228288f01d0c03a2c3d66f646967657374416c676f726974686d675
348412d3235365840b7c2d4abe85aa5ba814ef95de0385c71c802be8ac33a4a971a
85ed800ba7acb59cb21035f4a68fc0caa450cbefd3b255aec72f83595f0ae7b7d50
fe8a1c4cafe
~~~

The following is the CBOR Diagnostic Notation of the example above:

~~~~~~~~~~
[
  << {
    1: -7
  } >>,
  {
    33: h'308201ef30820195a00302010202140bfec7da97e048e15ac3dacb9ea
    fe82e64fd07f5300a06082a8648ce3d04030230233114301206035504030c0b
    75746f7069612069616361310b3009060355040613025553301e170d3234313
    030313030303030305a170d3235313030313030303030305a30213112301006
    035504030c0975746f706961206473310b30090603550406130255533059301
    306072a8648ce3d020106082a8648ce3d03010703420004ace7ab7340e5d964
    8c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8983e1b37d
    3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a530
    1c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301e0
    603551d120417301581136578616d706c65406578616d706c652e636f6d301d
    0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0
    603551d2304183016801454fa2383a04c28e0d930792261c80c4881d2c00b30
    0e0603551d0f0101ff04040302078030150603551d250101ff040b300906072
    8818c5d050102300a06082a8648ce3d0403020348003045022100b7103fd4b9
    0529f50bd6f70c5ae5ce7f4f3d4d15a4e082812f9fa1f5c2e5aa0a0220070b2
    822ec7ce6c56804923a85b2cfbffd054cf9a915f070cfef7179a4bc6569'
  },
  << 24( << {
    "status": {
      "status_list": {
        "idx": 412,
        "uri": "https://example.com/statuslists/1"
      }
    },
    "docType": "org.iso.18013.5.1.mDL",
    "version": "1.0",
    "validityInfo": {
      "signed": 2024-10-01 13:30:02+00:00,
      "validFrom": 2024-10-01 13:30:02+00:00,
      "validUntil": 2025-10-01 13:30:02+00:00
    },
    "valueDigests": {
      "org.iso.18013.5.1": {
        0: h'a81d65ed5075fbd7ee19fa66e2bb3047ed826e2769873e7ef07c92
        3da7a6f243',
        1: h'48701a9546492284d266ed81d439230a582d0e1f17a08ab1859a3e
        fe980690a4',
        2: h'd11fe48c8835b30bfb3895c3905436ddfb63f59ab9eee181b11098
        53292a8f62',
        3: h'a741bf05e20a8bc359e32426106ed0899b2c60262cc3acc637ddc9
        941095fb7a',
        4: h'ab67cb9a8f20a8572f77f02727367d08dc8e57fb89deb46b9c626e
        94457b7d8b',
        5: h'bacddb4142b3842bd555206eb5acb27ded063294995c7e7fefbf93
        ece522604d',
        6: h'bfd02b3aebdc05b53b5539226c38088d6d784b0ea0fab69eb93116
        50a48d3253',
        7: h'27dab70fe71da63e5e5d199e8ae5b79cbe8904bc30c5b7544fb809
        e02ccb3e6a',
        8: h'0dbd7ccc9c7727d3d17295f1b6f1914071670ee23d4d33530c31f1
        f406b8e3b7',
        9: h'a5beb5efadf37f21637209abc519830681cc51f334818a823fec13
        b29552f5ba',
        10: h'd8047c95f9272d7d07b2c13a9f5ac2ee02380ab272a165e569391
        d89a2152c3c',
        11: h'04939930ffb4911ef03487a153605a30368b69f2437d6d21b4c90
        f92bc144c3e'
      }
    },
    "deviceKeyInfo": {
      "deviceKey": {
        1: 2,
        -1: 1,
        -2: h'96313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd
        48dca6b7f9a',
        -3: h'1fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01
        d0c03a2c3d6'
      }
    },
    "digestAlgorithm": "SHA-256"
  } >> ) >>,
  h'b7c2d4abe85aa5ba814ef95de0385c71c802be8ac33a4a971a85ed800ba7acb
  59cb21035f4a68fc0caa450cbefd3b255aec72f83595f0ae7b7d50fe8a1c4cafe'
]
~~~~~~~~~~

# Status Types {#status-types}

This document defines statuses of Referenced Tokens as Status Type values. A status describes the state, mode, condition or stage of an entity that is represented by the Referenced Token.

A Status List can not represent multiple statuses per Referenced Token. If the Status List contains more than one bit per token (as defined by `bits` in the Status List), then the whole value of bits MUST describe one value. Status Types MUST have a numeric value between 0 and 255 for their representation in the Status List. The issuer of the Status List MUST choose an adequate `bits` (bit size) to be able to describe the required Status Types for its application.

## Status Types Values

This document creates a registry in [](#iana-status-types) that includes the most common Status Type values. Additional values may defined for particular use cases. Status Types described by this document comprise:

 - 0x00 - "VALID" - The status of the Referenced Token is valid, correct or legal.
 - 0x01 - "INVALID" - The status of the Referenced Token is revoked, annulled, taken back, recalled or cancelled.
 - 0x02 - "SUSPENDED" - The status of the Referenced Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.
 - 0x03 - "APPLICATION_SPECIFIC_3" - The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.
 - 0x0E - "APPLICATION_SPECIFIC_14" - The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.
 - 0x0F - "APPLICATION_SPECIFIC_15" - The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.

The Status Issuer MUST choose an adequate `bits` (bit size) to be able to describe the required Status Types for the application.

The processing rules for JWT or CWT precede any evaluation of a Referenced Token's status. For example, if a token is evaluated as being expired through the "exp" (Expiration Time) but also has a status of 0x00 ("VALID"), the token is considered expired.

# Verification and Processing

## Status List Request {#status-list-request}

To obtain the Status List Token, the Relying Party MUST send an HTTP GET request to the URI provided in the Referenced Token.

The HTTP endpoint SHOULD support the use of Cross-Origin Resource Sharing (CORS) {{CORS}} and/or other methods as appropriate to enable Browser-Based clients to access it.

The Relying Party SHOULD send the following Accept-Header to indicate the requested response type:

- "application/statuslist+jwt" for Status List Token in JWT format
- "application/statuslist+cwt" for Status List Token in CWT format

If the Relying Party does not send an Accept Header, the response type is assumed to be known implicit or out-of-band.

A successful response that contains a Status List Token MUST use an HTTP status code in the 2xx range.

A response MAY also choose to redirect the client to another URI using a HTTP status code in the 3xx range, which clients SHOULD follow. A client SHOULD detect and intervene in cyclical redirections (i.e., "infinite" redirection loops).

The following are non-normative examples for a request and response for a Status List Token with type `application/statuslist+jwt`:

~~~ ascii-art

GET /statuslists/1 HTTP/1.1
Host: example.com
Accept: application/statuslist+jwt
~~~


~~~ ascii-art

HTTP/1.1 200 OK
Content-Type: application/statuslist+jwt

{::include ./examples/status_list_jwt_raw}
~~~

## Status List Response {#status-list-response}

In the successful response, the Status Provider MUST use the following content-type:

- "application/statuslist+jwt" for Status List Token in JWT format
- "application/statuslist+cwt" for Status List Token in CWT format

In the case of "application/statuslist+jwt", the response MUST be of type JWT and follow the rules of [](#status-list-token-jwt).
In the case of "application/statuslist+cwt", the response MUST be of type CWT and follow the rules of [](#status-list-token-cwt).

The HTTP response SHOULD use gzip Content-Encoding as defined in {{RFC9110}}.

If caching-related HTTP headers are present in the HTTP response, Relying Parties SHOULD prioritize the exp and ttl claims within the Status List Token over the HTTP headers for determining caching behavior.

## Validation Rules

Upon receiving a Referenced Token, a Relying Party MUST first perform the validation of the Referenced Token - e.g., checking for expected attributes, valid signature, expiration time. The processing rules for JWT or CWT precede any evaluation of a Referenced Token's status. For example, if a token is evaluated as being expired through the "exp" (Expiration Time) but also has a status of 0x00 ("VALID"), the token is considered expired. As this is out of scope of this document, this validation is not be described here, but is expected to be done according to the format of the Referenced Token.

If this validation was not successful, the Referenced Token MUST be rejected. If the validation was successful, the Relying Party MUST perform the following validation steps to evaluate the status of the reference token:

1. Check for the existence of a `status` claim, check for the existence of a `status_list` claim within the `status` claim and validate that the content of `status_list` adheres to the rules defined in [](#referenced-token-jose) for JWTs and [](#referenced-token-cose) for CWTs. This step can be overruled if defined within the Referenced Token Format natively
2. Resolve the Status List Token from the provided URI
3. Validate the Status List Token:
    1. Validate the Status List Token by following the rules defined in section 7.2 of {{RFC7519}} for JWTs and section 7.2 of {{RFC8392}} for CWTs
    2. Check for the existence of the required claims as defined in [](#status-list-token-jwt) and [](#status-list-token-cwt) depending on token type
4. All existing claims in the Status List Token MUST be checked according to the rules in [](#status-list-token-jwt) and [](#status-list-token-cwt)
    1. The subject claim (`sub` or `2`) of the Status List Token MUST be equal to the `uri` claim in the `status_list` object of the Referenced Token
    2. If the Relying Party has custom policies regarding the freshness of the Status List Token, it SHOULD check the issued at claim (`iat` or `6`)
    3. If expiration time is defined (`exp` or `4`), it MUST be checked if the Status List Token is expired
    4. If the Relying Party is using a system for caching the Status List Token, it SHOULD check the `ttl` claim of the Status List Token and retrieve a fresh copy if (time status was resolved + ttl < current time)
5. Decompress the Status List with a decompressor that is compatible with DEFLATE {{RFC1951}} and ZLIB {{RFC1950}}
6. Retrieve the status value of the index specified in the Referenced Token as described in [](#status-list). Fail if the provided index is out of bound of the Status List
7. Check the status value as described in [](#status-types)

If any of these checks fails, no statement about the status of the Referenced Token can be made and the Referenced Token SHOULD be rejected.

## Historical resolution {#historical-resolution}

By default, the status mechanism defined in this specification only conveys information about the state of Reference Tokens at the time the Status List Token was issued. The validity period for this information, as defined by the issuer, is explicitly stated by the `iat` (issued at) and `exp` (expiration time) claims for JWT, and their corresponding ones for the CWT representation. If support for historical status information is required, this can be achieved by extending the request for the Status List Token as defined in [](#status-list-request) with a timestamp. This feature has additional privacy implications as described in [](#privacy-historical).

To obtain the Status List Token, the Relying Party MUST send an HTTP GET request to the URI provided in the Referenced Token with the additional query parameter `time` and its value being a unix timestamp. The response for a valid request SHOULD contain a Status List Token that was valid for that specified time or an error.

If the Server does not support the additional query parameter, it SHOULD return a status code of 501 (Not Implemented), or if the requested time is not supported it SHOULD return a status code of 406 (Not Acceptable). A Status List Token might be served via static file hosting (e.g., leveraging a Content Delivery Network), which would result in the client not being able to retrieve those status codes. Thus, the client MUST verify support for this feature by verifying that the requested timestamp is within the valid time of the returned token signaled via `iat` (`6` for CWT) and `exp` (`4` for CWT).

The following is a non-normative example for a GET request using the `time` query parameter:

~~~ ascii-art

GET /statuslists/1?time=1686925000 HTTP/1.1
Host: example.com
Accept: application/statuslist+jwt
~~~

The following is a non-normative example for a response for the above Request:

~~~ ascii-art

HTTP/1.1 200 OK
Content-Type: application/statuslist+jwt

{::include ./examples/status_list_jwt_raw}
~~~

# Status List Aggregation {#aggregation}

Status List Aggregation is an optional mechanism to retrieve a list of URIs to all Status List Tokens, allowing a Relying Party to fetch all relevant Status Lists for a specific type of Referenced Token or Issuer. This mechanism is intended to support fetching and caching mechanisms and allow offline validation of the status of a reference token for a period of time.

If a Relying Party encounters an invalid Status List referenced in the response from the Status List Aggregation endpoint, it SHOULD continue processing the other valid Status Lists referenced in the response.

There are two options for a Relying Party to retrieve the Status List Aggregation.
An Issuer MAY support any of these mechanisms:

- Issuer metadata: The Issuer of the Referenced Token publishes an URI which links to Status List Aggregation, e.g. in publicly available metadata of an issuance protocol
- Status List Parameter: The Status Issuer includes an additional claim in the Status List Token that contains the Status List Aggregation URI.

## Issuer Metadata

The Issuer MAY link to the Status List Aggregation URI in metadata that can be provided by different means like .well-known metadata as is used commonly in OAuth and OpenID, or via a VICAL extension for ISO mDoc / mDL. If the Issuer is an OAuth Authorization Server according to {{RFC6749}}, it is RECOMMENDED to use `status_list_aggregation_endpoint` for its metadata defined by {{RFC8414}}.

The concrete specification on how this is implemented depends on the specific ecosystem and is out of scope of this specification.

## Status List Parameter

The URI to the Status List Aggregation MAY be provided as the optional parameter `aggregation_uri` in the Status List itself as explained in[](#status-list-cbor) and [](#status-list-json) respectively. A Relying Party may use this URI to retrieve an up-to-date list of relevant Status Lists.

## Status List Aggregation in JSON Format

This section defines the structure for a JSON-encoded Status List Aggregation:

* `status_lists`: REQUIRED. JSON array of strings that contains URIs linking to Status List Tokens.

The Status List Aggregation URI provides a list of Status List URIs. This aggregation in JSON and the media type return SHOULD be `application/json`. A Relying Party can iterate through this list and fetch all Status List Tokens before encountering the specific URI in a Referenced Token.

The following is a non-normative example for media type `application/json`:

~~~ json

{
   "status_lists" : [
      "https://example.com/statuslists/1",
      "https://example.com/statuslists/2",
      "https://example.com/statuslists/3"
   ]
}
~~~

# Further Examples

## Status List with 2-Bit Status Values in JSON format

In this example, the Status List additionally includes the Status Type "SUSPENDED". As the Status Type value for "SUSPENDED" is 0x02 and does not fit into 1 bit, the "bits" is required to be 2.

This example Status List represents the status of 12 Referenced Tokens, requiring 24 bits (3 bytes) of status.

~~~ ascii-art

status[0] = 1
status[1] = 2
status[2] = 0
status[3] = 3
status[4] = 0
status[5] = 1
status[6] = 0
status[7] = 1
status[8] = 1
status[9] = 2
status[10] = 3
status[11] = 3
~~~

These bits are concatenated:

~~~ ascii-art

byte             0                  1                  2
bit       7 6 5 4 3 2 1 0    7 6 5 4 3 2 1 0    7 6 5 4 3 2 1 0
         +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+
values   |1|1|0|0|1|0|0|1|  |0|1|0|0|0|1|0|0|  |1|1|1|1|1|0|0|1|
         +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+
          \ / \ / \ / \ /    \ / \ / \ / \ /    \ / \ / \ / \ /
status     3   0   2   1      1   0   1   0      3   3   2   1
index      3   2   1   0      7   6   5   4      11  10  9   8
           \___________/      \___________/      \___________/
                0xC9               0x44               0xF9

~~~

Resulting in the byte array and compressed/base64url-encoded Status List:

~~~~~~~~~~
{::include ./examples/status_list_encoding2_json}
~~~~~~~~~~

# Security Considerations {#Security}

The Status List as defined in [](#status-list) only exists in cryptographically secured containers which allows checking the integrity and origin without relying on other aspects like transport security (e.g., the web PKI).

## Correct decoding and parsing of the encoded Status List

Implementers should be particularly careful for the correct parsing and decoding of the Status List. Incorrect implementations might check the index on the wrong data or miscalculate the bit and byte index leading to an erroneous status of the Referenced Token. Beware, that bits are indexed (bit order) from least significant bit to most significant bit (also called "right to left") while bytes are indexed (byte order) in their natural incrementing byte order (usually written for display purpose from left to right). Endianness does not apply here because each status value fits within a single byte.

Implementations are RECOMMENDED to verify correctness using the test vectors given by this specification.

## Security Guidance for JWT and CWT

A Status List Token in the JWT format should follow the security considerations of {{RFC7519}} and the best current practices of {{RFC8725}}.

A Status List Token in the CWT format should follow the security considerations of {{RFC8392}}.

## Status List Caching

When fetching a Status List Token, Relying Parties must carefully evaluate how long a Status List is cached for. Collectively the `iat`, `exp` and `ttl` claims when present in a Status List Token communicate how long a Status List should be cached and should be considered valid for. The following diagram illustrates the relationship between these claims and how they are designed to influence caching.

~~~ ascii-art
Time of fetching

         │
         │            Check for        Check for        Check for
         │             updates          updates          updates
         │
 iat     │                │                │                │    exp
         │                │                │                │
  │      │                │                │                │     │
  │      │                │                │                │     │
  │      │                │                │                │     │
  │      │                │                │                │     │
  │      │      ttl       │      ttl       │      ttl       │     │
  │      │ ─────────────► │ ─────────────► │ ─────────────► │ ──► │
  │      │                │                │                │     │
  │      │                │                │                │     │
  │                                                               │
──┼───────────────────────────────────────────────────────────────┼─►
  │                                                               │
~~~

It is essential to understand the distinct purposes of the `ttl` and `exp` claims. The `ttl` claim represents a duration to be interpreted relative to the time the Status List is fetched, indicating when a new version of the Status List may be available. In contrast, the `exp` claim specifies an absolute timestamp, marking the point in time when the Status List expires and MUST NOT be relied upon any longer. Together, these claims provide guidance on when to check for updates (`ttl` claim) and when the Status List must be refreshed or replaced (`exp` claim).

# Privacy Considerations

## Observability of Issuers {#privacy-issuer}

The main privacy consideration for a Status List, especially in the context of the Issuer-Holder-Verifier model {{SD-JWT.VC}}, is to prevent the Issuer from tracking the usage of the Referenced Token when the status is being checked. If an Issuer offers status information by referencing a specific token, this would enable him to create a profile for the issued token by correlating the date and identity of Relying Parties, that are requesting the status.

The Status List approaches these privacy implications by integrating the status information of many Referenced Tokens into the same list. Therefore, the Issuer does not learn for which Referenced Token the Relying Party is requesting the Status List. The privacy of the Holder is protected by the anonymity within the set of Referenced Tokens in the Status List, also called herd privacy. This limits the possibilities of tracking by the Issuer.

The herd privacy is depending on the number of entities within the Status List called its size. A larger size results in better privacy but also impacts the performance as more data has to be transferred to read the Status List.

Additionally, the Issuer may analyse data from the HTTP request to identify the Relying Party, e.g. through the sender's IP address.

This behaviour may be mitigated by:

- private relay protocols or other mechanism hiding the original sender like {{RFC9458}}.
- using trusted Third Party Hosting, see [](#third-party-hosting).

## Malicious Issuers

A malicious Issuer could bypass the privacy benefits of the herd privacy by generating a unique Status List for every Referenced Token. By these means, he could maintain a mapping between Referenced Tokens and Status Lists and thus track the usage of Referenced Tokens by utilizing this mapping for the incoming requests. This malicious behaviour could be detected by Relying Parties that request large amounts of Referenced Tokens by comparing the number of different Status Lists and their sizes.

## Observability of Relying Parties {#privacy-relying-party}

Once the Relying Party receives the Referenced Token, this enables him to request the Status List to validate its status through the provided `uri` parameter and look up the corresponding `index`. However, the Relying Party may persistently store the `uri` and `index` of the Referenced Token to request the Status List again at a later time. By doing so regularly, the Relying Party may create a profile of the Referenced Token's validity status. This behaviour may be intended as a feature, e.g. for a KYC process that requires regular validity checks, but might also be abused in cases where this is not intended and unknown to the Holder, e.g. profiling the suspension of a driving license or checking the employment status of an employee credential.

This behaviour could be mitigated by:

- regular re-issuance of the Referenced Token, see [](#implementation-lifecycle).

## Observability of Outsiders {#privacy-outsider}

Outside actors may analyse the publicly available Status Lists to get information on the internal processes of the Issuer and his related business. This data may allow inferences on the total number of issued Reference Tokens and the revocation rate. Additionally, actors may regularly fetch this data or use the historic data functionality to learn how these numbers change over time.

This behaviour could be mitigated by:

- disable the historical data feature [](#historical-resolution)
- disable the Status List Aggregation [](#aggregation)
- choose non-sequential, pseudo-random or random indices
- use decoy entries to obfuscate the real number of Referenced Tokens within a Status List
- choose to deploy and utilize multiple Status Lists simultaneously

## Unlinkability

The tuple of uri and index inside the Referenced Token are unique and therefore is traceable data.

### Colluding Relying Parties

Two or more colluding Relying Parties may link two transactions involving the same Referenced Token by comparing the status claims of received Referenced Tokens, and therefore determine that they have interacted with the same Holder.

To avoid privacy risks for colluding Relying Parties, it is RECOMMENDED that Issuers use batch issuance to issue multiple Referenced Tokens, see [](#implementation-lifecycle). To avoid further correlatable information by the values of `uri` and `index`, Status Issuers are RECOMMENDED to:

- choose non-sequential, pseudo-random or random indices
- use decoy entries to obfuscate the real number of Referenced Tokens within a Status List
- choose to deploy and utilize multiple Status Lists simultaneously

### Colluding Status Issuer and Relying Party

A Status Issuer and a Relying Party Issuer may link two transaction involving the same Referenced Tokens by comparing the status claims of the Referenced Token, and therefore determine that they have interacted with the same Holder. It is therefore recommended to use Status Lists for Referenced Token formats that have similar unlinkability properties.

## Third Party Hosting {#third-party-hosting}

If the roles of the Issuer and the Status Provider are performed by two different entities, this may give additional privacy assurances as the Issuer has no means to identify the Relying Party or its request.

Third Party hosting may also allow for greater scalability, as the Status List Tokens may be served by operators with greater resources, like CDNs.

## Historical Resolution {#privacy-historical}

By default, this specification only supports providing Status List information for the most recent status information and does not allow the lookup of historical information like a validity state at a specific point in time. There exists optional support for a query parameter that allows these kind of historic lookups as described in [](#historical-resolution). There are scenarios where such a functionality is necessary, but this feature should only be implemented when the scenario and the consequences of enabling historical resolution are fully understood.

There are strong privacy concerns that have to be carefully taken into considerations when providing a mechanism that allows historic requests for status information - see [](#privacy-relying-party) for more details. Support for this functionality is optional and Implementers are RECOMMENDED to not support historic requests unless there are strong reasons to do so and after carefully considering the privacy implications.

# Implementation Considerations {#implementation}

## Token Lifecycle {#implementation-lifecycle}

The lifetime of a Status List Token depends on the lifetime of its Referenced Tokens. Once all Referenced Tokens are expired, the Issuer may stop serving the Status List Token.

Referenced Tokens may be regularly re-issued to mitigate linkability of presentations to Relying Parties. In this case, every re-issued Referenced Token MUST have a fresh Status List entry in order to prevent this becoming possible source of correlation.

Referenced Tokens may also be issued in batches, such that Holders can use individual tokens for every transaction. In this case, every Referenced Token MUST have a dedicated Status List entry. Revoking batch issued Referenced Tokens might reveal this correlation later on.

## Default Values and Double Allocation

Implementations producing Status Lists are RECOMMENDED to initialize the Status List byte array with a default value and provide this as an initialization parameter to the Issuer. The Issuer is RECOMMENDED to use a default value that represents the most common value for its Referenced Tokens to avoid an update during issuance.

Implementations producing Status Lists are RECOMMENDED to prevent double allocation, i.e. re-using the same `uri` and `index` for multiple Referenced Tokens. The Issuer MUST prevent any unintended double allocation by using the Status List.

## Status List Size

The Status List Issuer may increase the size of a Status List if it requires indices for additional Referenced Tokens. It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder, i.e. `size-in-bits` % 8 = 0.

The Status List Issuer may chunk its Referenced Tokens into multiple Status Lists to reduce the transmission size of an individual Status List Token. This may be useful for setups where some entities operate in constrained environments, e.g. for mobile internet or embedded devices.

## Status List Formats

 This specification defines 2 different token formats of the Status List:

 - JWT
 - CWT

This specification states no requirements to not mix different formats like a CBOR based Referenced Token using a JWT for the Status List, but the expectation is that within an ecosystem, a choice for specific formats is made.
Within such an ecosystem, only support for those selected variants is required and implementations should know what to expect via a profile.

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry {{IANA.JWT}} established by {{RFC7519}}.

### Registry Contents

* Claim Name: `status`
* Claim Description: Reference to a status or validity mechanism containing up-to-date status information on the JWT.
* Change Controller: IETF
* Specification Document(s): [](#status-claim) of this specification

<br/>

* Claim Name: `status_list`
* Claim Description: A status list containing up-to-date status information on multiple tokens.
* Change Controller: IETF
* Specification Document(s): [](#status-list-token-jwt) of this specification

<br/>

* Claim Name: `ttl`
* Claim Description: Time to Live
* Change Controller: IETF
* Specification Document(s): [](#status-list-token-jwt) of this specification

## JWT Status Mechanisms Registry {#iana-registry}

This specification establishes the IANA "JWT Status Mechanisms" registry for JWT "status" member values and adds it to the "JSON Web Token (JWT)" registry group at https://www.iana.org/assignments/jwt. The registry records the status mechanism member and a reference to the specification that defines it.

JWT Status Mechanisms are registered by Specification Required [RFC5226] after a three-week
review period on the jwt-reg-review@ietf.org mailing list, on the advice of one or more Designated Experts.
However, to allow for the allocation of names prior to publication, the Designated Expert(s) may approve
registration once they are satisfied that such a specification will be published.

Registration requests sent to the mailing list for review should use an appropriate subject (e.g., "Request to register JWT Status Mechanism: example").

Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision
to the review list and IANA.  Denials should include an explanation and, if applicable, suggestions as to how to make the request
successful.

IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.

### Registration Template

Status Mechanism Value:

  > The name requested (e.g., "status_list"). The name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts state that there is a compelling reason to allow an exception.

Status Mechanism Description:

  > Brief description of the status mechanism.

Change Controller:

  > For IETF Stream RFCs, list the IETF.  For others, give the name of the responsible party.  Other details (e.g., postal address, email address, home page URI) may also be included.

Specification Document(s):

  > Reference to the document or documents that specify the parameter, preferably including URIs that can be used to retrieve copies of the documents.  An indication of the relevant sections may also be included but is not required.

### Initial Registry Contents

* Status Mechanism Value: `status_list`
* Status Mechanism Description: A status list containing up-to-date status information on multiple tokens.
* Change Controller: IETF
* Specification Document(s): [](#referenced-token-jose) of this specification

## CBOR Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "CBOR Web Token (CWT) Claims" registry {{IANA.CWT}} established by {{RFC8392}}.

### Registry Contents

<br/>

* Claim Name: `status`
* Claim Description: Reference to a status or validity mechanism containing up-to-date status information on the CWT.
* JWT Claim Name: `status`
* Claim Key: TBD (requested assignment 65535)
* Claim Value Type: map
* Change Controller: IETF
* Reference: [](#status-claim) of this specification

<br/>

* Claim Name: `status_list`
* Claim Description: A status list containing up-to-date status information on multiple tokens.
* JWT Claim Name: `status_list`
* Claim Key: TBD (requested assignment 65533)
* Claim Value Type: map
* Change Controller: IETF
* Specification Document(s): [](#status-list-token-cwt) of this specification

<br/>

* Claim Name: `ttl`
* Claim Description: Time to Live
* JWT Claim Name: `ttl`
* Claim Key: TBD (requested assignment 65534)
* Claim Value Type: unsigned integer
* Change Controller: IETF
* Specification Document(s): [](#status-list-token-cwt) of this specification

## CWT Status Mechanisms Registry {#cwt-iana-registry}

This specification establishes the IANA "CWT Status Mechanisms" registry for CWT "status" member values and adds it to the "CBOR Web Token (CWT) Claims" registry group at https://www.iana.org/assignments/cwt. The registry records the status mechanism member and a reference to the specification that defines it.

CWT Status Mechanisms are registered by Specification Required [RFC5226] after a three-week
review period on the cwt-reg-review@ietf.org mailing list, on the advice of one or more Designated Experts. However, to allow for the allocation of names prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a
specification will be published.

Registration requests sent to the mailing list for review should use an appropriate subject (e.g., "Request to register CWT Status Mechanism: example").

Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision
to the review list and IANA.  Denials should include an explanation and, if applicable, suggestions as to how to make the request
successful.

IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.

### Registration Template

Status Mechanism Value:

  > The name requested (e.g., "status_list"). The name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts state that there is a compelling reason to allow an exception.

Status Mechanism Description:

  > Brief description of the status mechanism.

Change Controller:

  > For IETF Stream RFCs, list the IETF.  For others, give the name of the responsible party.  Other details (e.g., postal address, email address, home page URI) may also be included.

Specification Document(s):

  > Reference to the document or documents that specify the parameter, preferably including URIs that can be used to retrieve copies of the documents.  An indication of the relevant sections may also be included but is not required.

### Initial Registry Contents

* Status Mechanism Value: `status_list`
* Status Mechanism Description: A status list containing up-to-date status information on multiple tokens.
* Change Controller: IETF
* Specification Document(s): [](#referenced-token-cose) of this specification

## OAuth Status Types Registry {#iana-status-types}

This specification establishes the IANA "OAuth Status Types" registry for Status List values and adds it to the "OAuth Parameters" registry group at https://www.iana.org/assignments/oauth-parameters. The registry records the a human readable label, the bit representation and a common description for it.

Status Types are registered by Specification Required [RFC5226] after a two-week
review period on the oauth-ext-review@ietf.org mailing list, on the advice of one or more Designated Experts. However, to allow for the allocation of names prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a
specification will be published.

Registration requests sent to the mailing list for review should use an appropriate subject (e.g., "Request to register Status Type name: example").

Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision
to the review list and IANA.  Denials should include an explanation and, if applicable, suggestions as to how to make the request
successful.

IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.

### Registration Template

Status Type Name:

  > The name is a human-readable case insensitive label for the Status Type that helps to talk about a Status of Referenced Token in common language.

Status Type Description:

  > Brief description of the Status Type and optional examples.

Status Type value:

  > The bit representation of the Status Type in a byte hex representation. Valid Status Type values range from 0x00-0xFF. Values are filled up with zeros if they have less than 8 bits.

Change Controller:

  > For IETF Stream RFCs, list the IETF.  For others, give the name of the responsible party.  Other details (e.g., postal address, email address, home page URI) may also be included.

Specification Document(s):

  > Reference to the document or documents that specify the parameter, preferably including URIs that can be used to retrieve copies of the documents.  An indication of the relevant sections may also be included but is not required.

### Initial Registry Contents

* Status Type Name: VALID
* Status Type Description: The status of the Referenced Token is valid, correct or legal.
* Status Type value: `0x00`
* Change Controller: IETF
* Specification Document(s): [](#status-types) of this specification

<br/>

* Status Type Name: INVALID
* Status Type Description: The status of the Referenced Token is revoked, annulled, taken back, recalled or cancelled.
* Status Type value: `0x01`
* Change Controller: IETF
* Specification Document(s): [](#status-types) of this specification

<br/>

* Status Type Name: SUSPENDED
* Status Type Description: The status of the Referenced Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.
* Status Type value: `0x02`
* Change Controller: IETF
* Specification Document(s): [](#status-types) of this specification

<br/>

* Status Type Name: APPLICATION_SPECIFIC_3
* Status Type Description: The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.
* Status Type value: `0x03`
* Change Controller: IETF
* Specification Document(s): [](#status-types) of this specification

<br/>

* Status Type Name: APPLICATION_SPECIFIC_14
* Status Type Description: The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.
* Status Type value: `0x0E`
* Change Controller: IETF
* Specification Document(s): [](#status-types) of this specification

<br/>

* Status Type Name: APPLICATION_SPECIFIC_15
* Status Type Description: The status of the Referenced Token is implicitly given by the particular use case and the meaning of this value is known out-of-band.
* Status Type value: `0x0F`
* Change Controller: IETF
* Specification Document(s): [](#referenced-token-jose) of this specification

<br/>

## OAuth Parameters Registration

This specification requests registration of the following value in the IANA "OAuth Authorization Server Metadata" registry {{IANA.OAuth.Params}} established by {{RFC8414}}.

* Metadata Name: status_list_aggregation_endpoint
* Metadata Description: URL of the Authorization Server aggregating OAuth Token Status List URLs for token status management.
* Change Controller: IETF
* Reference: [](#aggregation) of this specification

## Media Type Registration

This section requests registration of the following media types {{RFC2046}} in
the "Media Types" registry {{IANA.MediaTypes}} in the manner described
in {{RFC6838}}.

To indicate that the content is an JWT-based Status List:

  * Type name: application
  * Subtype name: statuslist+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: See [](#status-list-token-jwt) of this specification
  * Security considerations: See [](#Security) of this specification
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information: n/a
  * Person &amp; email address to contact for further information: Paul Bastian, paul.bastian@posteo.de
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Paul Bastian, paul.bastian@posteo.de
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is an CWT-based Status List:

  * Type name: application
  * Subtype name: statuslist+cwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: See [](#status-list-token-cwt) of this specification
  * Security considerations: See [](#Security) of this specification
  * Interoperability considerations: n/a
  * Published specification: this specification
  * Applications that use this media type: Applications using this specification for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information: n/a
  * Person &amp; email address to contact for further information: Paul Bastian, paul.bastian@posteo.de
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Paul Bastian, paul.bastian@posteo.de
  * Change controller: IETF
  * Provisional registration? No

--- back

# Acknowledgments
{:numbered="false"}

We would like to thank
Brian Campbell,
Filip Skokan,
Francesco Marino,
Guiseppe De Marco,
Kristina Yasuda,
Markus Kreusch,
Martijn Haring,
Michael B. Jones,
Michael Schwartz,
Mike Prorock,
Oliver Terbu,
Orie Steele,
Timo Glastra
and
Torsten Lodderstedt

for their valuable contributions, discussions and feedback to this specification.

# Document History
{:numbered="false"}

-07

* rename Status Mechanism Methods registry to Status Mechanisms registry
* changes as requested by IANA review
* emphasize that security and privacy considerations only apply to Status List and no other status mechanisms
* differentiate unlinkability between Issuer-RP and RP-RP

-06

* iana registration text updated with update procedures
* explicitly mention that status list is expected to be contained in cryptographically secured containers
* reworked and simplified introduction and abstract
* specify http status codes and allow redirects
* add status_list_aggregation_endpoint OAuth metadata
* remove unsigned options (json/cbor) of status list
* add section about mixing status list formats and media type
* fixes from IETF review
* update guidance around ttl
* add guidance around aggregation endpoint

-05

* add optional support for historical requests
* update CBOR claim definitions
* improve section on Status Types and introduce IANA registry for it
* add Status Issuer and Status Provider role description to the introduction/terminology
* add information on third party hosting to security consideration
* remove constraint that Status List Token must not use a MAC

-04

* add mDL example as Referenced Token and consolidate CWT and CBOR sections
* add implementation consideration for Default Values, Double Allocation and Status List Size
* add privacy consideration on using private relay protocols
* add privacy consideration on observability of outsiders
* add security considerations on correct parsing and decoding
* remove requirement for matching iss claim in Referenced Token and Status List Token
* add sd-jwt-vc example
* fix CWT status_list map encoding
* editorial fixes
* add CORS considerations to the http endpoint
* fix reference of Status List in CBOR format
* added status_list CWT claim key assigned
* move base64url definition to terminology

-03

* remove unused reference to RFC9111
* add validation rules for status list token
* introduce the status list aggregation mechanism
* relax requirements for status_list claims to contain other parameters
* change cwt referenced token example to hex and annotated hex
* require TLS only for fetching Status List, not for Status List Token
* remove the undefined phrase Status List endpoint
* remove http caching in favor of the new ttl claim
* clarify the sub claim of Status List Token
* relax status_list iss requirements for CWT
* Fixes missing parts & iana ttl registration in CWT examples

-02

* add ttl claim to Status List Token to convey caching
* relax requirements on referenced token
* clarify Deflate / zlib compression
* make a reference to the Issuer-Holder-Verifier model of SD-JWT VC
* add COSE/CWT/CBOR encoding

-01

* Rename title of the draft
* add design consideration to the introduction
* Change status claim to in referenced token to allow re-use for other mechanisms
* Add IANA Registry for status mechanisms
* restructure the sections of this document
* add option to return an unsigned Status List
* Changing compression from gzip to zlib
* Change typo in Status List Token sub claim description
* Add access token as an example use-case

-00

* Initial draft after working group adoption
* update acknowledgments
* renamed Verifier to Relying Party
* added IANA consideration

\[ draft-ietf-oauth-status-list \]

-01

* Applied editorial improvements suggested by Michael Jones.

-00

* Initial draft
