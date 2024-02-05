---
title: "Token Status List"
category: info

docname: draft-ietf-oauth-status-list-latest
submissiontype: IETF  # also: "IETF", "IAB", or "IRTF"
number:
date:
v: 3
venue:
  github: "vcstuff/draft-ietf-oauth-status-list"
  latest: "https://vcstuff.github.io/draft-ietf-oauth-status-list/draft-ietf-oauth-status-list.html"

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
    email: chris.bormann@gmx.de

normative:
  RFC7519: RFC7519
  RFC8392: RFC8392
  RFC3986: RFC3986
  RFC1950: RFC1950
  RFC1951: RFC1951
  RFC7515: RFC7515
  RFC6125: RFC6125
  RFC9110: RFC9110
  RFC9111: RFC9111
informative:
  RFC6749: RFC6749
  RFC7662: RFC7662
  RFC7800: RFC7800

--- abstract

This specification defines status list data structures for representing the status of JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}}.
The status list data structures themselves are also represented as JWTs or CWTs.

--- middle

# Introduction

JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}} as secure token formats, have vast possible applications. Some of these applications can involve issuing a token whereby certain semantics about the token can change over time, which are important to be able to communicate to relying parties in an interoperable manner, such as whether the token is considered invalidated or suspended by its issuer.

This document defines a Status List and its representations in JSON and CBOR formats that describe the individual statuses of multiple Referenced Tokens, which themselves are JWTs or CWTs. The statuses of all Referenced Tokens are conveyed via a bit array in the Status List. Each Referenced Token is allocated an index during issuance that represents its position within this bit array. The value of the bit(s) at this index correspond to the Referenced Token's status. A Status List may either be provided by an endpoint or be signed and embedded into a Status List Token, whereas this document defines its representations in JWT and CWT. Status Lists may be composed for expressing a range of Status Types. This document defines basic Status Types for the most common use cases as well as an extensibility mechanism for custom Status Types. The document also defines how an issuer of a Referenced Token references a Status List (Token).

An example for the usage of a Status List is to manage the status of issued access tokens as defined in section 1.4 of {{RFC6749}}. Token Introspection {{RFC7662}} defines another way to determine the status of an issued access token, but it requires the party trying to validate an access tokens status to directly contact the token issuer, whereas the mechanism defined in this specification does not have this limitation.

Another possible use case for the Status List is to express the status of verifiable credentials (Referenced Tokens) issued by an issuer in the Issuer-Holder-Verifier model.
The following diagram depicts the basic conceptual relationship.

~~~ ascii-art

+-------------------+                  +------------------------+
|                   | describes status |                        |
|    Status List    +----------------->|    Referenced Token    |
|   (JSON or CBOR)  <------------------+     (JWT or CWT)       |
|                   |   references     |                        |
+-------+-----------+                  +--------+---------------+
        |
        |embedded in
        v
+-------------------+
|                   |
| Status List Token |
|  (JWT or CWT)     |
|                   |
+-------------------+

~~~

## Rationale

Revocation mechanisms are an essential part for most identity ecosystems. In the past, revocation of X.509 TLS certificates has been proven difficult. Traditional certificate revocation lists (CRLs) have limited scalability; Online Certificate Status Protocol (OCSP) has additional privacy risks, since the client is leaking the requested website to a third party. OCSP stapling is addressing some of these problems at the cost of less up-to-date data. Modern approaches use accumulator-based revocation registries and Zero-Knowledge-Proofs to accommodate for this privacy gap, but face scalability issues again.

This specification seeks to find a balance between scalability, security, and privacy by minimizing the status information to mere bits (often a single bit) and compressing the resulting binary data. Thereby, a Status List may contain statuses of many thousands or millions Referenced Tokens while remaining as small as possible. Placing large amounts of Referenced Tokens into the same list also enables herd privacy relative to the Issuer.

This specification establishes the IANA "Status Mechanism Methods" registry for status mechanism and registers the members defined by this specification. Other specifications can register other members used for status retrieval.

## Design Considerations

The decisions taken in this specification aim to achieve the following design goals:

* the specification shall favor a simple and easy to understand concept
* the specification shall be easy, fast and secure to implement in all major programming languages
* the specification shall be optimized to support the most common use cases and avoid unneccessary complexity of corner cases
* the Status List shall scale up to millions of tokens to support large scale government or enterprise use cases
* the Status List shall enable caching policies and offline support
* the specification shall support JSON and CBOR based tokens
* the specification shall not specify key resolution or trust frameworks
* the specification shall design an extension point to convey information about the status of a token that can be re-used by other mechanisms

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Issuer:
: An entity that issues the Referenced Token and provides the status information of the Referenced Token by serving a Status List Token on a public endpoint.

Relying Party:
: An entity that relies on the Status List to validate the status of the Referenced Token. Also known as Verifier.

Status List:
: An object in JSON or CBOR representation containing a bit array that lists the statuses of many Referenced Tokens.

Status List Token:
: A token in JWT or CWT representation that contains a cryptographically secured Status List.

Referenced Token:
: A token in JWT or CWT representation which contains a reference to a Status List or Status List Token. The information from the contained Status List may give a Relying Party additional information about up-to-date status of the Referenced Token.

# Status List {#status-list}

A Status List is a byte array that contains the statuses of many Referenced Tokens represented by one or multiple bits. A common representation of a Status List is composed by the following algorithm:

1. Each status of a Referenced Token MUST be represented with a bit-size of 1,2,4, or 8. Therefore up to 2,4,16, or 256 statuses for a Referenced Token are possible, depending on the bit-size. This limitation is intended to limit bit manipulation necessary to a single byte for every operation and thus keeping implementations simpler and less error prone.

2. The overall Status List is encoded as a byte array. Depending on the bit-size, each byte corresponds to 8/(#bit-size) statuses (8,4,2, or 1). The status of each Referenced Token is identified using the index that maps to one or more specific bits within the byte array. The index starts counting at 0 and ends with "size" - 1 (being the last valid entry). The bits within an array are counted from least significant bit "0" to the most significant bit ("7"). All bits of the byte array at a particular index are set to a status value.

3. The complete byte array is compressed using the "DEFLATE" {{RFC1951}} compression method and stored using the "ZLIB" {{RFC1950}} data format. Implementations are RECOMMENDED to use the highest compression level available.

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

This section defines the structure for a JSON-encoded Status List:

* `status_list`: REQUIRED. JSON Object that contains a Status List. The object contains exactly two claims:
   * `bits`: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the Status List (`lst`). The allowed values for `bits` are 1,2,4 and 8.
   * `lst`: REQUIRED. JSON String that contains the status values for all the Referenced Tokens it conveys statuses for. The value MUST be the base64url-encoded (as defined in Section 2 of {{RFC7515}}) Status List as specified in [](#status-list).

The following example illustrates the JSON representation of the Status List:

~~~~~~~~~~
{::include ./examples/status_list_encoding}
~~~~~~~~~~

## Status List in CBOR Format {#status-list-cbor}

TBD

# Status List Token {#status-list-token}

A Status List Token embeds the Status List into a token that is cryptographically signed and protects the integrity of the Status List. This allows for the Status List Token to be hosted by third parties or be transferred for offline use cases.

This section specifies Status List Tokens in Json Web Token (JWT) and Cbor Web Token (CWT) format.

## Status List Token in JWT Format {#status-list-token-jwt}

The Status List Token MUST be encoded as a "JSON Web Token (JWT)" according to {{RFC7519}}.

The following content applies to the JWT Header:

* `typ`: REQUIRED. The JWT type MUST be `statuslist+jwt`.

The following content applies to the JWT Claims Set:

* `iss`: REQUIRED. The `iss` (issuer) claim MUST specify a unique string identifier for the entity that issued the Status List Token. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the `iss` claim contained within the Referenced Token.
* `sub`: REQUIRED. The `sub` (subject) claim MUST specify a unique string identifier for that Status List Token. The value MUST be equal to that of the `uri` claim contained in the `status_list` claim of the Referenced Token.
* `iat`: REQUIRED. The `iat` (issued at) claim MUST specify the time at which the Status List Token was issued.
* `exp`: OPTIONAL. The `exp` (expiration time) claim MAY convey the time at which it is considered expired by its issuer.
* `status_list`: REQUIRED. The `status_list` (status list) claim MUST specify the Status List conforming to the rules outlined in [](#status-list-json).

The following additional rules apply:

1. The JWT MAY contain other claims.

2. The JWT MUST be digitally signed using an asymmetric cryptographic algorithm. Relying parties MUST reject the JWT if it is using a Message Authentication Code (MAC) algorithm. Relying parties MUST reject JWTs with an invalid signature.

3. Relying parties MUST reject JWTs that are not valid in all other respects per "JSON Web Token (JWT)" {{RFC7519}}.

4. Application of additional restrictions and policy are at the discretion of the verifying party.

The following is a non-normative example for a Status List Token in JWT format:

~~~~~~~~~~
{::include ./examples/status_list_jwt}
~~~~~~~~~~

## Status List Token in CWT Format {#status-list-token-cwt}

TBD

# Referenced Token {#referenced-token}

## Status Claim {#status-claim}

By including a "status" claim in a Referenced Token, the issuer is referencing a mechanism to retrieve status information about this Referenced Token. The claim contains members used to reference to a status list as defined in this specification. Other members of the "status" object may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1 of {{RFC7800}} in which different authenticity confirmation methods can be included.

## Referenced Token in JWT Format {#referenced-token-jwt}

The Referenced Token MUST be encoded as a "JSON Web Token (JWT)" according to {{RFC7519}}.

The following content applies to the JWT Claims Set:

* `iss`: REQUIRED. The `iss` (issuer) claim MUST specify a unique string identifier for the entity that issued the Referenced Token. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the `iss` claim contained within the referenced Status List Token.
* `status`: REQUIRED. The `status` (status) claim MUST specify a JSON Object that contains at least one reference to a status mechanism.
  * `status_list`: REQUIRED when the status list mechanism defined in this specification is used. It contains a reference to a Status List or Status List Token. The object contains exactly two claims:
    * `idx`: REQUIRED. The `idx` (index) claim MUST specify an Integer that represents the index to check for status information in the Status List for the current Referenced Token. The value of `idx` MUST be a non-negative number, containing a value of zero or greater.
    * `uri`: REQUIRED. The `uri` (URI) claim MUST specify a String value that identifies the Status List or Status List Token containing the status information for the Referenced Token. The value of `uri` MUST be a URI conforming to {{RFC3986}}.

Application of additional restrictions and policy are at the discretion of the verifying party.

The following is a non-normative example for a decoded header and payload of a Referenced Token:

~~~ ascii-art

{
  "alg": "ES256",
  "kid": "11"
}
.
{
  "iss": "https://example.com",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  }
}
~~~

# Status Types {#status-types}

This document defines potential statuses of Referenced Tokens as Status Type values. If the Status List contains more than one bit per token (as defined by "bits" in the Status List), then the whole value of bits MUST describe one value. A Status List can not represent multiple statuses per Referenced Token.

The registry in this document describes the basic Status Type values required for the most common use cases.
Additional values may defined for particular use cases.

## Status Types Values

A status describes the state, mode, condition or stage of an entity that is described by the Status List. Status Types MUST be numeric values between 0 and 255.
Status types described by this specification comprise:

 - 0x00 - "VALID" - The status of the Token is valid, correct or legal.
 - 0x01 - "INVALID" - The status of the Token is revoked, annulled, taken back, recalled or cancelled. This state is irreversible.
 - 0x02 - "SUSPENDED" - The status of the Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.

The issuer of the Status List MUST choose an adequate `bits` (bit size) to be able to describe the required Status Types for the application.

The processing rules for JWT or CWT precede any evaluation of a Referenced Token's status. For example, if a token is evaluated as being expired through the "exp" (Expiration Time) but also has a status of 0x00 ("VALID"), the token is considered expired.

# Verification and Processing

## Status List Request

To obtain the Status List or Status List Token, the Relying Party MUST send a HTTP GET request to the Status List Endpoint. Communication with the Status List Endpoint MUST utilize TLS. Which version(s) should be implemented will vary over time. A TLS server certificate check MUST be performed as defined in Section 5 and 6 of {{RFC6125}}.

The Relying Party SHOULD send the following Accept-Header to indicate the requested response type:

- "application/statuslist+json" for Status List in JSON format
- "application/statuslist+jwt" for Status List in JWT format
- "application/statuslist+cbor" for Status List in CBOR format
- "application/statuslist+cwt" for Status List in CWT format

If the Relying Party does not send an Accept Header, the response type is assumed to be known implicit or out-of-band.

## Status List Response

In the successful response, the Status List Provider MUST use the following content-type:

- "application/statuslist+json" for Status List in JSON format
- "application/statuslist+jwt" for Status List in JWT format
- "application/statuslist+cbor" for Status List in CBOR format
- "application/statuslist+cwt" for Status List in CWT format

In the case of "application/statuslist+json", the response MUST be of type JSON and follow the rules of [](#status-list-json).
In the case of "application/statuslist+jwt", the response MUST be of type JWT and follow the rules of [](#status-list-token-jwt).
In the case of "application/statuslist+cbor", the response MUST be of type CBOR and follow the rules of [](#status-list-cbor).
In the case of "application/statuslist+cwt", the response MUST be of type CWT and follow the rules of [](#status-list-token-cwt).

The HTTP response SHOULD use gzip Content-Encoding as defined in {{RFC9110}}.

## Caching

If caching is required (e.g., to enable the use of alternative mechanisms for hosting, like Content Delivery Networks), the control of the caching mechanism SHOULD be implemented using the standard HTTP Cache-Control as defined in {{RFC9111}}.

## Validation Rules

# Further Examples

## Status List Token with 2-Bit Status Values in JWT format

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

Resulting in the byte array and compressed/base64url encoded status list:

~~~~~~~~~~
{::include ./examples/status_list_encoding2}
~~~~~~~~~~

# Security Considerations {#Security}

## Correct decoding and parsing of the encoded status list
TODO elaborate on risks of incorrect parsing/decoding leading to erroneous status data

## Cached and Stale status lists
TODO consumers/Relying Party of the status list should be aware if they fetch the up-to-date data

## Authorized access to the Status List {#security-authorization}
TODO elaborate on authorization mechanisms preventing misuse and profiling as described in privacy section

## History
TODO elaborate on status list only providing the up-to date/latest status, no historical data, may be provided by the underlying hosting architecture

# Privacy Considerations

## Issuer tracking and Herd Privacy {#privacy-issuer}

The main privacy consideration for a Status List, especially in the context of the Issuer-Holder-Verifier model, is to prevent the Issuer from tracking the usage of the Referenced Token when the status is being checked. If an Issuer offers status information by referencing a specific token, this would enable him to create a profile for the issued token by correlating the date and identity of Relying Parties, that are requesting the status.

The Status List approaches these privacy implications by integrating the status information of many Referenced Tokens into the same list. Therefore, the Issuer does not learn for which Referenced Token the Relying Party is requesting the Status List. The privacy of the Holder is protected by the anonymity within the set of Referenced Tokens in the Status List, also called herd privacy. This limits the possibilities of tracking by the Issuer.

The herd privacy is depending on the number of entities within the Status List called its size. A larger size results in better privacy but also impacts the performance as more data has to be transferred to read the Status List.

## Malicious Issuers

A malicious Issuer could bypass the privacy benefits of the herd privacy by generating a unique Status List for every Referenced Token. By these means, he could maintain a mapping between Referenced Tokens and Status Lists and thus track the usage of Referenced Tokens by utilizing this mapping for the incoming requests. This malicious behaviour could be detected by Relying Parties that request large amounts of Referenced Tokens by comparing the number of different Status Lists and their sizes.

## Relying Party tracking {#privacy-relying-party}

Once the Relying Party gets the Referenced Token, this enables him to request the Status List to validate the status of the Token through the provided "uri" property and look up the corresponding "index". However, the Relying Party may persistently store the "uri" and "index" of the Referenced Token to request the Status List again at a later time. By doing so regularly, the Relying Party may create a profile of the Referenced Token's validity status. This behaviour may be inteded as a feature, e.g. for a KYC process that requires regular validity checks, but might also be abused in cases where this is not intended and unknown to the Holder, e.g. profiling the suspension of a driving license or checking the employment status of an employee credential. This behaviour could be constrained by adding authorization rules to the Status List, see [](#security-authorization).

## Correlation Risks and Tracking

Colluding Issuers and Relying Parties have the possibility to identify the usage of credentials of a particular Holder, as the Referenced Token contains unique, trackable data.

To avoid privacy risks for colluding Relying Parties, it is recommended that Issuers use batch issuance to issue multiple tokens, such that Holders can use individual tokens for specific Relying Parties. In this case, every Referenced Token MUST have a dedicated Status List entry. Revoking batch issued Referenced Tokens might reveal this correlation lateron.

To avoid information leakage by the values of "uri" and "index", Issuers are RECOMMENDED to:

- choose non-sequential, pseudo-random or random indices
- use decoy or dead entries to obfuscate the real number of Referenced Tokens within a Status List
- choose to deploy and utilize multiple Status Lists simulantaniously

## Third Party Hosting

TODO elaborate on increased privacy if the status list is hosted by a third party instead of the issuer reducing tracking possiblities
TODO evaluate deifnition of Status List Provider?
 An entity that hosts the Status List as a resource for potential Relying Parties. The Status List Provider may be the issuer of the Status List but may also be outsourced to a trusted third party.

# Implementation Considerations {#implementation}

TBD Declare whether JWT and CWT representations can be used interchangeably by the same issuer.  For instance, declare whether a status list can reference both JWT and CWT tokens.

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by [@!RFC7519].

### Registry Contents

*  Claim Name: `status`
*  Claim Description: Reference to a status or validity mechanism containing up-to-date status information on the JWT.
*  Change Controller: IETF
*  Specification Document(s):  [](#status-claim) of this specification

## JWT Status Mechanism Methods Registry {#iana-registry}

This specification establishes the IANA "Status Mechanism Methods" registry for JWT "status" member values. The registry records the status mechanism method member and a reference to the specification that defines it.

### Registration Template

Status Method Value:

  > The name requested (e.g., "status_list"). The name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts state that there is a compelling reason to allow an exception.

Status Method Description:

  > Brief description of the status mechanism method.

Change Controller:

  > For Standards Track RFCs, list the "IESG".  For others, give the name of the responsible party.  Other details (e.g., postal address, email address, home page URI) may also be included.

Specification Document(s):

  > Reference to the document or documents that specify the parameter, preferably including URIs that can be used to retrieve copies of the documents.  An indication of the relevant sections may also be included but is not required.

### Initial Registry Contents

*  Status Method Value: `status_list`
*  Status Method Description: A status list containing up-to-date status information on multiple other JWTs encoded as a bitarray.
*  Change Controller: IETF
*  Specification Document(s):  [](#referenced-token-jwt) of this specification

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

To indicate that the content is an JSON-based Status List:

  * Type name: application
  * Subtype name: statuslist+json
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A JSON-based Status List is a JSON Object.
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Paul Bastian, paul.bastian@posteo.de
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Paul Bastian, paul.bastian@posteo.de
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is an JWT-based Status List:

  * Type name: application
  * Subtype name: statuslist+jwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A JWT-based Status List is a JWT; JWT values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') characters.
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
  * Person &amp; email address to contact for further information: Paul Bastian, paul.bastian@posteo.de
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Paul Bastian, paul.bastian@posteo.de
  * Change controller: IETF
  * Provisional registration? No

To indicate that the content is an CBOR-based Status List:

  * Type name: application
  * Subtype name: statuslist+cbor
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary; A CBOR-based Status List is a CBOR Object.
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
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
  * Encoding considerations: binary;
  * Security considerations: See (#Security) of [[ this specification ]]
  * Interoperability considerations: n/a
  * Published specification: [[ this specification ]]
  * Applications that use this media type: Applications using [[ this specification ]] for updated status information of tokens
  * Fragment identifier considerations: n/a
  * Additional information:
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
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
Michael B. Jones,
Mike Prorock,
Orie Steele,
Timo Glastra
and
Torsten Lodderstedt

for their valuable contributions, discussions and feedback to this specification.

# Document History
{:numbered="false"}

-01
* add design consideration to the introduction
* Change status claim to in referenced token to allow re-use for other mechanisms
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

[draft-ietf-oauth-status-list ]

-01

* Applied editorial improvements suggested by Michael Jones.

-00

* Initial draft
