---
title: "JWT and CWT Status List"
category: info

docname: draft-looker-jwt-cwt-status-list-latest
submissiontype: independent  # also: "IETF", "IAB", or "IRTF"
number:
date:
v: 3
venue:
  github: "vcstuff/draft-looker-jwt-cwt-status-list"
  latest: "https://vcstuff.github.io/draft-looker-jwt-cwt-status-list/draft-looker-jwt-cwt-status-list.html"

author:
 -
    fullname: Tobias Looker
    organization: MATTR
    email: tobias.looker@mattr.global

normative:
  RFC7519: RFC7519
  RFC8392: RFC8392
  RFC3986: RFC3986
  RFC1952: RFC1952
informative:

--- abstract

This specification defines a status list representation and processing rules for usage with JSON Web Tokens {{RFC7519}} and CBOR Web Tokens {{RFC8392}}.

--- middle

# Introduction

JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}} as secure token formats, have vast possible applications. Some of these applications can involve issuing a token whereby certain semantics about the token can change over time which are important to be able to communicate to relying parties in an interoperable manner, such as whether the token is considered revoked by its issuer.

This document defines a status list using JWT and CWT for representation that is capable of communicating the individual statuses of multiple tokens. The document also defines how an issuer of a token references a status list in a JWT or CWT which has a status to convey.

The following diagram depicts the basic conceptual relationship.

~~~ ascii-art

+---------------+                     +---------------+
|               |                     |               |
|               |                     |               |
|     Token     |    References       |  Status List  |
|(JWT/CWT Based)|-------------------->|(JWT/CWT Based)|
|               |                     |               |
|               |                     |               |
+---------------+                     +---------------+

~~~

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# JSON Web Token Representation

## JWT Format and Processing Requirements {#jwt-format-and-processing}

The following rules apply to validating a JWT which references a status list. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string based identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the referenced status list JWT.

2. The JWT MUST contain an "status" (status) claim conforming to the rules outlined in [](#jwt-status-claim-format)

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
    "bits": 1,
    "idx": 0,
    "uri": "https://example.com/statuslists/1"
  }
}

~~~

### Status Claim Format {#jwt-status-claim-format}

The following rules apply to validating the "status" (status) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain an "idx" (index) attribute with a numeric based value that represents the index to check for status information in the status list for the current JWT. The value of this attribute MUST be a non-negative number, containing a value of zero or greater. Refer to xx for details on the validation procedure.

3. The claim value object MUST contain a "uri" attribute with a string based value that identifies the status list containing the status information for the JWT. The value of this attribute MUST be a uri conforming to {{RFC3986}}

## Status List JWT Format and Processing Requirements {#jwt-status-list-format-and-processing}

The following rules apply to validating a JWT based status list. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string based identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the JWT who's status is being verified.

2. The JWT MUST contain an "iat" (issued at) claim that identifies the time at which it was issued.

3. The JWT MUST contain an "status_list" (status list) claim conforming to the rules outlined in [](#jwt-status-list-claim-format).

4. The JWT MAY contain an "exp" (expiration time) claim that convey's when it is considered expired by its issuer.

5. The JWT MAY contain other claims.

6. The JWT MUST be digitally signed using an asymmetric cryptographic algorithm. Relying parties MUST reject the JWT if it is using a Message Authentication Code (MAC) based algorithm. Relying parties MUST reject JWTs with an invalid signature.

7. Relying parties MUST reject a JWT that is not valid in all other respects per "JSON Web Token (JWT)" {{RFC7519}}.

~~~ ascii-art

{
  "typ": "statuslist+jwt",
  "alg": "ES256",
  "kid": "11"
}
.
{
  "iss": "https://example.com",
  "iat": 1683560915,
  "exp": 1686232115,
  "status_list": {
    "bits": 1,
    "lst": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAA......IC3AYbSVKsAQAAA"
  }
}

~~~

### Status List Claim Format {#jwt-status-list-claim-format}

The following rules apply to validating the "status_list" (status list) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "bit_size" attribute with an numeric based value that represents the number of bits per Referenced Token in the Status List ("lst") of the Status List JWT. The allowed values for "bit_size" are 1,2,4 and 8.

3. The claim value object MUST contain a "lst" (list) attribute with a string based value that represents the bit array containing the Status Type values for all the Referenced Tokens it conveys statuses for. The value MUST be a base64 encoded string using RFCXXX containing a GZIP compressed octet string {{RFC1952}}.

# Status Types {#status-types}

This document defines the possible statuses of Referenced Tokens as Status Type values. If the Status List contains more than one bit per token (as defined by "bits" in the Status List) then the whole value of bits MUST describe one value. A Status List can not encompass multiple statuses per individual bits for a Reference Token.

The registry in this document describes the basic Status Type values required for the most common use cases. The registry may be extended as describes in XXX.

## Status Types Values

A status describes the state, mode, condition or stage of an entity that is described by the status list. Status Types MUST be numeric based values between 0 and 255.
Status types described by this specifiction comprise:
0x00 - "VALID" - The status of the Token is valid, correct or legal.
0x01 - "INVALID" - The status of the Token is revoked, annuled, taken back, recalled or cancelled. This state is irreversible.
0x02 - "SUSPENDED" - The status of the Token is temporarily unvalid, hanging, debared from privilege. This state is reversible.

The issuer of the Status List Token MUST choose an adequate "bit_size" to be able to describe the required Status Types.ST be used for the "typ" attribute within the "status_list".

### Examples
In the first example the Status List shall be used as a revocation list. It only requires the Status Types "VALID" and "INVALID", therefore a "bit_size" of 1 is sufficient.

In the second example the Status List shall additionally include the Status Type "SUSPENDED. As the Status Type value for "SUSPENDED" is 0x02 and doe snot fit into 1 bit, the "bit_size" is required to be 2.

## Extended Status List Types


# Security Considerations

## Correct decoding and parsing of the encoded status list
TODO elaborate on risks of incorrect parsing/decoding leading to erroneuos status data

## Cached and Stale status lists
TODO consumers/Verifiers of the status list should be aware if they fetch the up-to-date data

## Authorized access to the Status List
TODO elaborate on authorization mechanisms preventing misuse and profiling as described in privacy section

## History
TODO elaborate on status list only providing the up-to date/latest status, no historical data, may be provided by the underlying hosting architecture

# Privacy Considerations

## Herd Privacy
TODO elaborate on herd privacy, size of the status list

## Profiling
TODO elaborate on Verifiers regularly fetching the status list to create a profile, possible countermeasures with authorized access to the status list

## Correlation Risks and Tracking
TODO elaborate on Issuer-Verifier correlation and Verifier-Verifier correlation as the status list introduces unique,trackable data
TODO elaborate on issuers avoiding sequential usage of indices and status lists
TODO elaborate that a status list only gives information about the maximum number of possible statuses that a list conveys, issuers are recommended to pre-allocate lists, use dead entries that are never assigned or other obfuscation mechanisms

## Malicious Issuers
TODO elaborate on issuers generating unique status lists per JWT token that do not offer herd privacy

## Hosting Service (what's a better name here?)
TODO elaborate on increased privacy if the status list is hosted by a third party instead of the issuer reducing tracking possiblities

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
