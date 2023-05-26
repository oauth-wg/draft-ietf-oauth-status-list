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

2. The claim value object MUST either contain a "typ" (type) attribute with a string based value that represents a well-known, pre-defined type of status list or a "typ_def" (type definition) attribute with a valid JSON object defining a new, custom type of status list as referenced in [](#status-list-definitions). The value MUST be equal to that of the "typ" attribute in the "sts" claim for the token who's status is being validated.

3. The claim value object MUST contain a "lst" (list) attribute with a string based value that represents the status values for all the tokens it conveys statuses for. The value MUST be a base64 encoded string using RFCXXX containing a GZIP compressed octet string {{RFC1952}}.

# Status List Definitions {#status-list-definitions}

Status List Types are definitions build on top of pre-defined, common status types. This specification defines the status types contained in the the well-known, pre-defined status list types

## Status Types

A status describes the state, mode, condition or stage of an entity that is described by the status list. Status Types MUST be string based values.
Status types described by this specifiction comprise:
- "VALID" - The status of the Token is valid, correct or legal.
- "INVALID" - The status of the Token is revoked, annuled, taken back, recalled or cancelled. This state is irreversible.
- "SUSPENDED" - The status of the Token is temporarily unvalid, hanging, debared from privilege. This state is reversible.

## Status List Types

A status list describes the possible statuses that an entity can encompass.
The following rules apply to validating a status list type:

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "bit_size" attribute with an Integer that represents the number of bits per entity in the status list ("lst") of the Status List JWT. The allowed values for `bit_size` are 1,2,4 and 8.

3. The claim value object MUST contain a "status_types" attribute that describes the possible Status Types that the entity may reflect. "status_types MUST be a valid JSON Object that defines up to "bit_size" Status Type encodings. The claim names MUST be the string based representation of the bit encoding and the claim values MUST describe the matching Status Type String values.

## Well-known Status List Types

This specification describes two well-known, pre-defined Status List Types. To use these, the name of the status list MUST be used for the "typ" attribute within the "status_list".

### Revocation List
The Status List Type "revocation-list" is defined as follows:

~~~ ascii-art

{
   "bit_size": 1,
   "status_types": {
      "0" : "VALID",
      "1" : "INVALID"
   }
}

~~~

Furthermore, the "uri" attribute contained within a JWT using the "status" claim MUST be an HTTPS based URL that when resolved via an HTTPS GET request returns a content type "application/jwt" containing the status list.

### Suspension-Revocation List
The Status List Type "suspension-revocation-list" is defined as follows:

~~~ ascii-art

{
   "bit_size": 2,
   "status_types": {
      "0" : "VALID",
      "1" : "INVALID",
      "2" : "SUSPENDED",
      "3" : "UNDEFINED" //ob absent
   }
}

~~~

## Defining Custom Status List Types

Issuers of Tokens MAY extend the status types and define new status list types to their needs. To use these, the definition of the status list type MUST be used for the "typ_def" attribute within the "status_list".

The following is a non-normative example for a "status_list" :

~~~ ascii-art

"sts_lst": {
    "typ_def" : {
       "bit_size": 2,
       "status_types": {
          "0" : "NOT_ISSUED",
          "1" : "REVOKED",
          "2" : "UNICORN_42",
          "3" : "WAITING_FOR_APPROVAL"
       }
    },
    "list": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAA......IC3AYbSVKsAQAAA"
  }

~~~

It is recommended to use the least signifcant bit for a "REVOKED" status.

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
