from datetime import datetime

from cbor2 import dumps
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, CWTClaims
from jwcrypto import jwk


def CWT(
    jwk: jwk.JWK,
    iat: datetime,
    sub: str,
    iss: str,
    status_url: str,
    status_idx: int,
    exp: datetime | None = None,
):
    claims = {}
    claims[CWTClaims.SUB] = sub
    claims[CWTClaims.ISS] = iss
    claims[CWTClaims.IAT] = int(iat.timestamp())
    if exp is not None:
        claims[CWTClaims.EXP] = int(exp.timestamp())

    claims[65535] = {
        "status_list": {
            "idx": status_idx,
            "uri": status_url,
        }
    }

    protected_header = {}
    unprotected_header = {}

    if jwk.key_id:
        unprotected_header[COSEHeaders.KID] = jwk.key_id.encode("utf-8")
    protected_header[COSEHeaders.ALG] = COSEAlgs.ES256

    key = COSEKey.from_jwk(jwk)

    sender = COSE.new()
    encoded = sender.encode(
        dumps(claims), key, protected=protected_header, unprotected=unprotected_header
    )

    return encoded
    return encoded
