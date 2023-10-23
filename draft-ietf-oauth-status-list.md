---
title: "OAuth Status List"
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
  RFC1952: RFC1952
  RFC7515: RFC7515
  RFC6125: RFC6125
  RFC9110: RFC9110
  RFC9111: RFC9111
informative:

--- abstract

This specification defines status list data structures for representing the status of JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}}.
The status list data structures themselves are also represented as JWTs or CWTs.

--- middle

# Introduction

JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}} as secure token formats, have vast possible applications. Some of these applications can involve issuing a token whereby certain semantics about the token can change over time, which are important to be able to communicate to relying parties in an interoperable manner, such as whether the token is considered invalidated or suspended by its issuer.

This document defines Status List representations in JWT and CWT formats that describe the individual statuses of multiple Referenced Tokens, which themselves are also JWTs or CWTs. The statuses of all Referenced Tokens are conveyed via a bit array in the Status List. Each Referenced Token is allocated an index during issuance that represents its position within this bit array. The value of the bit(s) at this position correspond to the Referenced Token's status. The document also defines how an issuer of a Referenced Token references a Status List Token. Status Lists may be composed for expressing a range of Status Types. This document defines basic Status Types for the most common use cases as well as an extensibility mechanism for custom Status Types. The Status List Token may be used by an issuer in the Issuer-Holder-Verifier model to express the status of verifiable credentials (Referenced Tokens) issued by an issuer.

The following diagram depicts the basic conceptual relationship.

~~~ ascii-art

+------------------+                    +-------------------+
|                  |     References     |                   |
|                  |------------------->|                   |
| Referenced Token |                    | Status List Token |
|   (JWT or CWT)   |                    |    (JWT or CWT)   |
|                  |  Describes Status  |                   |
|                  |<-------------------|                   |
+------------------+                    +-------------------+
~~~

## Rationale

Revocation mechanisms are an essential part for most identity ecosystems. In the past, revocation of X.509 TLS certificates has been proven difficult. Traditional certificate revocation lists (CRLs) have limited scalability; Online Certificate Status Protocol (OCSP) has additional privacy risks, since the client is leaking the requested website to a third party. OCSP stapling is addressing some of these problems at the cost of less up-to-date data. Modern approaches use accumulator-based revocation registries and Zero-Knowledge-Proofs to accommodate for this privacy gap, but face scalability issues again.

This specification seeks to find a balance between scalability, security, and privacy by minimizing the status information to mere bits (often a single bit) and compressing the resulting binary data. Thereby, a Status List may contain statuses of 100,000 or more Referenced Tokens, but still remain relatively small. Placing large amounts of Referenced Tokens into the same list also enables herd privacy relative to the Issuer.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Issuer:
: An entity that issues the Referenced Token and provides the status information of the Referenced Token by serving a Status List Token on a public endpoint.

Relying Party:
: An entity that relies on the Status List to validate the status of the Referenced Token. Also known as Verifier.

Status List:
: A bit array that lists the statuses of many Referenced Tokens.

Status List Token:
: A token in JWT or CWT representation that contains a cryptographically secured Status List.

Referenced Token:
: A token in JWT or CWT representation which contains a reference to a Status List Token. The information from the contained Status List may give a Relying Party additional information about up-to-date status of the Referenced Token.

# JSON Web Token Representation

## Status List JWT Format and Processing Requirements {#jwt-status-list-format-and-processing}

The following rules apply to validating a JWT-based Status List Token. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the Referenced Token.

2. The JWT MUST contain a "sub" (subject) claim that contains an unique string identifier for that Referenced Token. The value MUST be equal to that of the "uri" claim contained in the "status" claim of the Referenced Token.

3. The JWT MUST contain an "iat" (issued at) claim that identifies the time at which it was issued.

4. The JWT MUST contain an "status_list" (status list) claim conforming to the rules outlined in [](#jwt-status-list-claim-format).

5. The JWT MAY contain an "exp" (expiration time) claim that conveys when it is considered expired by its issuer.

6. The JWT MAY contain other claims.

7. The JWT MUST be digitally signed using an asymmetric cryptographic algorithm. Relying parties MUST reject the JWT if it is using a Message Authentication Code (MAC) algorithm. Relying parties MUST reject JWTs with an invalid signature.

8. Relying parties MUST reject JWTs that are not valid in all other respects per "JSON Web Token (JWT)" {{RFC7519}}.

~~~~~~~~~~
{::include ./examples/status_list_jwt}
~~~~~~~~~~

### Status List Claim Format {#jwt-status-list-claim-format}

The following rules apply to validating the "status_list" (status list) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "bits" (bit size) member with an numeric value that represents the number of bits per Referenced Token in the Status List ("lst") of the Status List JWT. The allowed values for "bits" are 1,2,4 and 8.

3. The claim value object MUST contain a "lst" (list) member with a string value that represents the status values for all the tokens it conveys statuses for. The value MUST be computed using the algorithm described in [](#jwt-status-list-claim-encoding).

### Status List Encoding {#jwt-status-list-claim-encoding}

Each status of a Referenced Token MUST be represented with a bit size of 1,2,4, or 8. Therefore up to 2,4,16, or 256 statuses for a Referenced Token are possible, depending on the bit size. This limitation is intended to limit bit manipulation necessary to a single byte for every operation and thus keeping implementations simpler and less error prone.

1. The overall Status List is encoded as a byte array. Depending on the bitsize, each byte corresponds to 8/(#bit-size) statuses (8,4,2, or 1). The status of each Referenced Token is identified using the index that maps to one or more specific bits within the byte array. The index starts counting at 0 and ends with "size" - 1 (being the last valid entry). The bits within an array are counted from least significant bit "0" to the most significant bit ("7"). All bits of the byte array at a particular index are set to a status value.

2. The complete byte array is compressed using gZIP {{RFC1952}}.

3. The result of the gZIP compression is then base64url-encoded, as defined in Section 2 of {{RFC7515}}.

## Referenced Token Format and Processing Requirements {#jwt-referenced-token}

The following rules apply to validating a Referenced Token in JWT representation, which references a Status List Token. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the referenced Status List Token.

2. The JWT MUST contain an "status" (status) claim conforming to the rules outlined in [](#jwt-referenced-token-status)

The following example is the decoded header and payload of a JWT meeting the processing rules as defined above.

~~~ ascii-art

{
  "alg": "ES256",
  "kid": "11"
}
.
{
  "iss": "https://example.com",
  "status": {
    "idx": 0,
    "uri": "https://example.com/statuslists/1"
  }
}
~~~

### Status Claim Format {#jwt-referenced-token-status}

The following rules apply to validating the "status" (status) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain an "idx" (index) member with a numeric value that represents the index to check for status information in the Status List for the current JWT. The value of this member MUST be a non-negative number, containing a value of zero or greater.

3. The claim value object MUST contain a "uri" member with a string value that identifies the Status List containing the status information for the JWT. The value of this member MUST be a uri conforming to {{RFC3986}}.

# Status Types {#status-types}

This document defines potential statuses of Referenced Tokens as Status Type values. If the Status List contains more than one bit per token (as defined by "bits" in the Status List), then the whole value of bits MUST describe one value. A Status List can not represent multiple statuses per Referenced Token.

The registry in this document describes the basic Status Type values required for the most common use cases.
Additional values may defined for particular use cases.

## Status Types Values

A status describes the state, mode, condition or stage of an entity that is described by the status list. Status Types MUST be numeric values between 0 and 255.
Status types described by this specification comprise:
 - 0x00 - "VALID" - The status of the Token is valid, correct or legal.
 - 0x01 - "INVALID" - The status of the Token is revoked, annulled, taken back, recalled or cancelled. This state is irreversible.
 - 0x02 - "SUSPENDED" - The status of the Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.

The issuer of the Status List Token MUST choose an adequate "bits" (bit size) to be able to describe the required Status Types for the application.

# Example JWT Status Lists

## Example Status List with 1-Bit Status Values

In this example, the Status List is used as a revocation list. It only requires the Status Types "VALID" and "INVALID"; therefore a "bits" of 1 is sufficient.

This example Status List represents the statuses of 16 Referenced Tokens, requiring 16 bits (2 bytes) of status.

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

Resulting in the byte array and compressed/base64url encoded status list:

~~~~~~~~~~
{::include ./examples/status_list_encoding}
~~~~~~~~~~

## Example Status List with 2-Bit Status Values

In thisexample, the Status List additionally includes the Status Type "SUSPENDED. As the Status Type value for "SUSPENDED" is 0x02 and does not fit into 1 bit, the "bits" is required to be 2.

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

# Verification and Processing

## Status List Request

To obtain the Status List or Status List Token, the Relying Party MUST send a HTTP GET request to the Status List Endpoint. Communication with the Status List Endpoint MUST utilize TLS. Which version(s) should be implemented will vary over time. A TLS server certificate check MUST be performed as defined in Section 5 and 6 of {{RFC6125}}.

The Relying Party SHOULD send the following Accept-Header to indicate the requested response type:

- "application/statuslist+jwt" for Status List JWTs
- "application/statuslist+cwt" for Status List CWTs

If the Relying Party does not send an Accept Header, the reponse type is assumed to be known implicit or out-of-band.

## Status List Response

In the successful response, the Status List Provider MUST use the following content-type:

- "application/statuslist+jwt" for Status List JWTs
- "application/statuslist+cwt" for Status List CWTs

In the case of "application/statuslist+jwt", the response MUST be of type JWT and follow the rules of [](#jwt-status-list-format-and-processing).
In the case of "application/statuslist+cwt", the response MUST be of type JWT and follow the rules of [](#cwt-status-list-format).

The response SHOULD use gzip Content-Encoding as defined in {{RFC9110}}.

## Caching

If caching is required (e.g., to enable the use of alternative mechanisms for hosting, like Content Delivery Networks), the control of the caching mechanism SHOULD be implemented using the standard HTTP Cache-Control as defined in {{RFC9111}}.

## Validation Rules

# CWT Representations {#cwt-status-list-format}

TBD Define parallel CWT representations for Status Lists and Referenced Tokens.

TBD Declare whether JWT and CWT representations can be used interchangeably by the same issuer.  For instance, declare whether a status list can reference both JWT and CWT tokens.

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

# IANA Considerations

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by [@!RFC7519].

*  Claim Name: `status`
*  Claim Description: Reference to a status list containing up-to-date status information on the JWT.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#jwt-referenced-token) of this specification ]]

<br/>

*  Claim Name: `status_list`
*  Claim Description: A status list containing up-to-date status information on multiple other JWTs encoded as a bitarray.
*  Change Controller: IETF
*  Specification Document(s):  [[ (#jwt-status-list-claim-format) of this specification ]]

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

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

To indicate that the content is an CWT-based Status List:

  * Type name: application
  * Subtype name: statuslist+cwt
  * Required parameters: n/a
  * Optional parameters: n/a
  * Encoding considerations: binary
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

* Applied editorial improvements suggested by Michael Jones.

-00

* Initial draft
