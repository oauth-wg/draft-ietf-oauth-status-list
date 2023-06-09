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

JSON Web Tokens (JWTs) {{RFC7519}} and CBOR Web Tokens (CWTs) {{RFC8392}} as secure token formats, have vast possible applications. Some of these applications can involve issuing a token whereby certain semantics about the token can change over time which are important to be able to communicate to relying parties in an interoperable manner, such as whether the token is considered suspended or revoked by its issuer.

This document defines a Status List in JWT and CWT representation that describes the individual statuses of multiple Referenced Tokens. The statuses of each Referenced Token are conveyed via a bit array in the Status List. Each Referenced Token during issuance is allocated an index which represents a position within this bit array and the value of the bit(s) at this position correspond to the Referenced Token's status. The document also defines how an issuer of a Referenced Token in JWT or CTW representation references a Status List Token. Status Lists may be composed for expressing a range of Status Types, the document defines basic Status Types for the most common use cases as well as an extensibility mechanism for custom Status Types. The Status List Token may be used by an issuer in the Issuer-Holder-Verifier model, as described in (XXX) to express the status of verifiable credentials (Referenced Tokens) issued by an issuer.

The following diagram depicts the basic conceptual relationship.

~~~ ascii-art

+------------------+                    +-------------------+
|                  |      References    |                   |
|                  |------------------->|                   |
| Referenced Token |                    | Status List Token |
| (JWT/CWT Based)  |                    |  (JWT/CWT Based)  |
|                  |  Describes Status  |                   |
|                  |<-------------------|                   |
+------------------+                    +-------------------+

~~~

## Rationale

Revocation mechanisms are an essential part for most identity ecoosystems. In the past, revocation of X.509 TLS certificates has been proven difficult as traditional certificate revocation lists (CRLs) have limited scalability and the Online Certificate Status Protocol (OCSP) has additional privacy risks as the client is leaking the requested website to a third party. OSCP stapling is adressing some of these problems at the cost of less up-to-date data. Modern approaches use accumulator-based revocation registries and Zero-Knowledge-Proofs to accomodate for this privacy gap but face scalability issues again.

The approach of this specification seeks to find a balance between scalability, security and privacy by minimizing the status information to mere bits and compressing the resulting binary data. Thereby a Status List may contain statuses of 100.000 or more Referenced Tokens, but still remain relatively small. Placing large amounts of Referenced Tokens into the same list also enables a herd privacy towards the Issuer.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Status List
 A bit array that lists the statuses of many Referenced Tokens.

Status List Token
 A token in JWT or CWT representation that contains a Status List.

Referenced Token
 A token in JWT or CWT representation which contains a reference to a Status List Token. The information from the contained Status List may give a verifier additional information about up-to-date status of the Referenced Token.


# JSON Web Token Representation

## Referenced Token Format and Processing Requirements {#jwt-referenced-token}

The following rules apply to validating a Referenced Token in JWT representation which references a Status List Token. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string based identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the referenced Status List Token.

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
    "typ": "revocation-list",
    "idx": 0,
    "uri": "https://example.com/statuslists/1"
  }
}

~~~

### Status Claim Format {#jwt-referenced-token-status}

The following rules apply to validating the "status" (status) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of Status List referenced. The value MUST be equal to that of the "typ" attribute in the "status_list" claim for the referenced Status List.

3. The claim value object MUST contain an "idx" (index) attribute with a numberic based value that represents the index to check for status information in the Status List for the current JWT. The value of this attribute MUST be a non-negative number, containing a value of zero or greater. Refer to xx for details on the validation procedure.

4. The claim value object MUST contain a "uri" attribute with a string based value that identifies the Status List containing the status information for the JWT. The value of this attribute MUST be a uri conforming to {{RFC3986}}

## Status List JWT Format and Processing Requirements {#jwt-status-list-format-and-processing}

The following rules apply to validating a JWT based Status List Token. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string based identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the JWT who's status is being verified.

2. The JWT MUST contain an "iat" (issued at) claim that identifies the time at which it was issued.

2. The JWT MUST contain an "status_list" (status list) claim conforming to the rules outlined in [](#jwt-status-list-claim-format).

3. The JWT MAY contain an "exp" (expiration time) claim that convey's when it is considered expired by its issuer.

4. The JWT MAY contain other claims.

5. The JWT MUST be digitally signed using an asymmetric cryptographic algorithm. Relying parties MUST reject the JWT if it is using a Message Authentication Code (MAC) based algorithm. Relying parties MUST reject JWTs with an invalid signature.

6. Relying parties MUST reject a JWT that is not valid in all other respects per "JSON Web Token (JWT)" {{RFC7519}}.

~~~ ascii-art

{
  "alg": "ES256",
  "kid": "11"
}
.
{
  "iss": "https://example.com",
  "iat": 1683560915,
  "exp": 1686232115,
  "status_list": {
    "typ": "revocation-list",
    "lst": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAA......IC3AYbSVKsAQAAA"
  }
}

~~~

### Status List Claim Format {#jwt-status-list-claim-format}

The following rules apply to validating the "status_list" (status list) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of status list referenced. The value MUST be equal to that of the "typ" attribute in the "status" claim for the Referenced Token who's status is being validated.

3. The claim value object MUST contain a "lst" (list) attribute with a string based value that represents the status values for all the Referenced Tokens it conveys statuses for. The value MUST be a base64 encoded string using RFCXXX containing a GZIP compressed octet string {{RFC1952}}.

## Revocation Status List Definition

This document formally defines the "revocation-list" status list type which applies the following additional validation rules beyond those described in [](#jwt-referenced-token) and [](#jwt-status-list-format-and-processing).

The "uri" attribute contained within a JWT using the "status" claim MUST be an HTTPS based URL that when resolved via an HTTPS GET request returns a content type "application/jwt" containing the status list.

TODO add more

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
TODO elaborate on issuers generating unique status lists per Referenced Token that do not offer herd privacy

## Hosting Service (what's a better name here?)
TODO elaborate on increased privacy if the status list is hosted by a third party instead of the issuer reducing tracking possiblities
TODO evaluate deifnition of Status List Provider?
 An entity that hosts the Status List as a resource for potential verifiers. The Status List Provider may be the issuer of the Status List but may also be outsourced to a trusted third party.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
