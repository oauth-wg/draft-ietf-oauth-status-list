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
    "typ": "revocation-list",
    "idx": 0,
    "uri": "https://example.com/statuslists/1"
  }
}

~~~

### Status Claim Format {#jwt-status-claim-format}

The following rules apply to validating the "status" (status) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of status list referenced. The value MUST be equal to that of the "typ" attribute in the "status_list" claim for the referenced status list.

3. The claim value object MUST contain an "idx" (index) attribute with a numberic based value that represents the index to check for status information in the status list for the current JWT. The value of this attribute MUST be a non-negative number, containing a value of zero or greater. Refer to xx for details on the validation procedure.

4. The claim value object MUST contain a "uri" attribute with a string based value that identifies the status list containing the status information for the JWT. The value of this attribute MUST be a uri conforming to {{RFC3986}}

## Status List JWT Format and Processing Requirements {#jwt-status-list-format-and-processing}

The following rules apply to validating a JWT based status list. Application of additional restrictions and policy are at the discretion of the verifying party.

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

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of status list referenced. The value MUST be equal to that of the "typ" attribute in the "status" claim for the token who's status is being validated.

3. The claim value object MUST contain a "lst" (list) attribute with a string based value that represents the status values for all the tokens it conveys statuses for. The value MUST be a base64 encoded string using RFCXXX containing a GZIP compressed octet string {{RFC1952}}.

## Revocation Status List Definition

This document formally defines the "revocation-list" status list type which applies the following additional validation rules beyond those described in [](#jwt-format-and-processing) and [](#jwt-status-list-format-and-processing).

The "uri" attribute contained within a JWT using the "status" claim MUST be an HTTPS based URL that when resolved via an HTTPS GET request returns a content type "application/jwt" containing the status list.

TODO add more

# Security Considerations

## Correct decoding and parsing of the encoded status list
TODO elaborate on risks of incorrect parsing/decoding leading to erroneuos status data

## Cached and Stale status lists
TODO consumers/Verifiers of the status list should be aware if they fetch the up-to-date data

## Authorized access to the Status List {#security-authorization}
TODO elaborate on authorization mechanisms preventing misuse and profiling as described in privacy section

## History
TODO elaborate on status list only providing the up-to date/latest status, no historical data, may be provided by the underlying hosting architecture

# Privacy Considerations

## Issuer tracking and Herd Privacy {#privacy-issuer}
The main privacy consideration for a status list, especially in the context of the Issuer-Holder-Verifier model RFCXXX, is to prevent the Issuer/Status List Provider from tracking the usage of the Token when the status is being checked. If an issuer offers status information by referencing a specific Token, this would enable him to create a profile for the issued Token by correlating the date and identity of Verifiers, that are requesting the status.

The Status List approaches these privacy implications by integrating the status information of many Tokens into the same list. Therefore, the Status List Provider does not learn for which Token the Verifier is requesting the Status List. The privacy of the Token Holder is achieved by the anonymity within the set of Tokens in the Status List, also called herd privacy. This limits the risks of tracking by the Issuer.

The herd privacy is depending on the number of entities within the Status List called its size. A larger size results in better privacy but also impacts the performance as more data has to be transferred to read the Status List.

## Verifier tracking {#privacy-verifier}

Once the Verifier got the Token, this enables him to request the Status List to validate the status of the Token through the provided "uri" property. However, the Verifier may store the "uri" and "index" of the Token to request the Status List at a later time. By doing so regularly, the Verifier may create a profile of the Token's validity status. This behaviour may be inteded as a feature, e.g. for a KYC process that requires regular validity checks, but might also be abused in cases where this is not intended and unknown to the Holder, e.g. profiling the suspension of a driving license. This behaviour could be constrained by adding authorization rules to the Status List, see [](#security-authorization).

## Correlation Risks and Tracking
TODO elaborate on Issuer-Verifier correlation and Verifier-Verifier correlation as the status list introduces unique,trackable data
TODO elaborate on issuers avoiding sequential usage of indices and status lists
TODO elaborate that a status list only gives information about the maximum number of possible statuses that a list conveys, issuers are recommended to pre-allocate lists, use dead entries that are never assigned or other obfuscation mechanisms

## Malicious Issuers
A malicious Issuer/Status List Provider could bypass the privacy benefits of the herd privacy by generating a unique Status List for every Token. By these means, he could maintain a mapping between Tokens and Status Lists and thus track the usage of Tokens as described above. This malicious behaviour could be detected by Verifiers that request large amounts of Tokens by comparing the number of different Status Lists and their size.

## Hosting Service (what's a better name here?)
TODO elaborate on increased privacy if the status list is hosted by a third party instead of the issuer reducing tracking possiblities

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
