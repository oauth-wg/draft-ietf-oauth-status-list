---
title: "JWT and CWT Status List"
category: info

docname: draft-looker-jwt-cwt-status-list-latest
submissiontype: independent  # also: "IETF", "IAB", or "IRTF"
number:
date:
v: 3
venue:
  github: "tplooker/draft-looker-jwt-cwt-status-list"
  latest: "https://tplooker.github.io/draft-looker-jwt-cwt-status-list/draft-looker-jwt-cwt-status-list.html"

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

2. The JWT MUST contain an "sts" (status) claim conforming to the rules outlined in [](#jwt-status-claim-format)

The following example is the decoded header and payload of a JWT meeting the processing rules as defined above.

~~~ ascii-art

{
  "alg": "ES256",
  "kid": "11"
}
.
{
  "iss": "https://example.com",
  "sts": {
    "typ": "revocation-list",
    "idx": 0,
    "uri": "https://example.com/statuslists/1"
  }
}

~~~

### Status Claim Format {#jwt-status-claim-format}

The following rules apply to validating the "sts" (status) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of status list referenced. The value MUST be equal to that of the "typ" attribute in the "sts_lst" claim for the referenced status list.

3. The claim value object MUST contain an "idx" (index) attribute with a numberic based value that represents the index to check for status information in the status list for the current JWT. The value of this attribute MUST be a non-negative number, containing a value of zero or greater. Refer to xx for details on the validation procedure.

4. The claim value object MUST contain a "uri" attribute with a string based value that identifies the status list containing the status information for the JWT. The value of this attribute MUST be a uri conforming to {{RFC3986}}

## Status List JWT Format and Processing Requirements {#jwt-status-list-format-and-processing}

The following rules apply to validating a JWT based status list. Application of additional restrictions and policy are at the discretion of the verifying party.

1. The JWT MUST contain an "iss" (issuer) claim that contains a unique string based identifier for the entity that issued the JWT. In the absence of an application profile specifying otherwise, compliant applications MUST compare issuer values using the Simple String Comparison method defined in Section 6.2.1 of {{RFC3986}}. The value MUST be equal to that of the "iss" claim contained within the JWT who's status is being verified.

2. The JWT MUST contain an "iat" (issued at) claim that identifies the time at which it was issued.

2. The JWT MUST contain an "sts_lst" (status list) claim conforming to the rules outlined in [](#jwt-status-list-claim-format).

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
  "sts_lst": {
    "typ": "revocation-list",
    "lst": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAA......IC3AYbSVKsAQAAA"
  }
}

~~~

### Status List Claim Format {#jwt-status-list-claim-format}

The following rules apply to validating the "sts_lst" (status list) claim

1. The claim value MUST be a valid JSON object.

2. The claim value object MUST contain a "typ" (type) attribute with a string based value that represents the type of status list referenced. The value MUST be equal to that of the "typ" attribute in the "sts" claim for the token who's status is being validated.

3. The claim value object MUST contain a "lst" (list) attribute with a string based value that represents the status values for all the tokens it conveys statuses for. The value MUST be a base64 encoded string using RFCXXX containing a GZIP compressed octet string {{RFC1952}}.

## Revocation Status List Definition

This document formally defines the "revocation-list" status list type which applies the following additional validation rules beyond those described in [](#jwt-format-and-processing) and [](#jwt-status-list-format-and-processing).

The "uri" attribute contained within a JWT using the "sts" claim MUST be an HTTPS based URL that when resolved via an HTTPS GET request returns a content type "application/jwt" containing the status list.

TODO add more

# Security Considerations

TODO Security

# Privacy Considerations

TODO elaborate on heard privacy

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
