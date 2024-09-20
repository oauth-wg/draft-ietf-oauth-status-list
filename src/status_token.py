import json
from datetime import datetime, timedelta
from typing import Dict

from cbor2 import dumps
from cwt import COSE, COSEHeaders, COSEKey, CWTClaims
from jwcrypto import jwk, jwt

from status_list import StatusList

DEFAULT_ALG = "ES256"
STATUS_LIST_TYP_JWT = "statuslist+jwt"
STATUS_LIST_TYP_CWT = "statuslist+cwt"


class StatusListToken:
    list: StatusList
    issuer: str
    subject: str
    _key: jwk.JWK
    _alg: str

    def __init__(
        self,
        subject: str,
        key: jwk.JWK,
        issuer: str | None = None,
        list: StatusList | None = None,
        size: int = 2**20,
        bits: int = 1,
        alg: str | None = None,
    ):
        if list is not None:
            self.list = list
            self.bits = list.bits
        else:
            self.list = StatusList(size, bits)
            self.bits = bits
        self.issuer = issuer
        self.subject = subject
        self._key = key
        if alg is not None:
            self._alg = alg
        else:
            self._alg = DEFAULT_ALG

    @classmethod
    def fromJWT(cls, input: str, key: jwk.JWK):
        decoded = jwt.JWT(jwt=input, key=key, expected_type="JWS")
        header = json.loads(decoded.header)
        alg = header["alg"]
        typ = header["typ"]
        assert typ == STATUS_LIST_TYP_JWT
        claims = json.loads(decoded.claims)
        status_list = claims["status_list"]
        lst = status_list["lst"]
        bits = status_list["bits"]
        issuer = claims["iss"]
        subject = claims["sub"]
        list = StatusList.fromEncoded(encoded=lst, bits=bits)

        return cls(
            issuer=issuer,
            subject=subject,
            key=key,
            list=list,
            size=list.size,
            bits=list.bits,
            alg=alg,
        )

    def set(self, pos: int, value: int):
        self.list.set(pos, value)

    def get(self, pos: int) -> int:
        return self.list.get(pos)

    def buildJWT(
        self,
        iat: datetime = datetime.utcnow(),
        exp: datetime | None = None,
        ttl: timedelta | None = None,
        optional_claims: Dict | None = None,
        optional_header: Dict | None = None,
        compact=True,
    ) -> str:
        # build claims
        if optional_claims is not None:
            claims = optional_claims
        else:
            claims = {}
        claims["sub"] = self.subject
        if self.issuer is not None:
            claims["iss"] = self.issuer
        claims["iat"] = int(iat.timestamp())
        if exp is not None:
            claims["exp"] = int(exp.timestamp())
        if ttl is not None:
            claims["ttl"] = int(ttl.total_seconds())
        claims["status_list"] = self.list.encodeAsJSON()

        # build header
        if optional_header is not None:
            header = optional_header
        else:
            header = {}
        if self._key.key_id:
            header["kid"] = self._key.key_id
        header["alg"] = self._alg
        header["typ"] = STATUS_LIST_TYP_JWT

        token = jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self._key)
        return token.serialize(compact=compact)

    def buildCWT(
        self,
        iat: datetime = datetime.utcnow(),
        exp: datetime | None = None,
        ttl: timedelta | None = None,
        optional_claims: Dict | None = None,
        optional_protected_header: Dict | None = None,
        optional_unprotected_header: Dict | None = None,
    ) -> bytes:
        # build claims
        if optional_claims is not None:
            claims = optional_claims
        else:
            claims = {}
        claims[CWTClaims.SUB] = self.subject
        if self.issuer is not None:
            claims[CWTClaims.ISS] = self.issuer
        claims[CWTClaims.IAT] = int(iat.timestamp())
        if exp is not None:
            claims[CWTClaims.EXP] = int(exp.timestamp())
        if ttl is not None:
            claims[65534] = int(ttl.total_seconds())
        claims[65533] = self.list.encodeAsCBOR()

        # build header
        if optional_protected_header is not None:
            protected_header = optional_protected_header
        else:
            protected_header = {}

        if optional_unprotected_header is not None:
            unprotected_header = optional_unprotected_header
        else:
            unprotected_header = {}

        if self._key.key_id:
            unprotected_header[COSEHeaders.KID] = self._key.key_id.encode("utf-8")
        protected_header[COSEHeaders.ALG] = self._alg
        protected_header[16] = STATUS_LIST_TYP_CWT

        key = COSEKey.from_jwk(self._key)

        # The sender side:
        sender = COSE.new()
        encoded = sender.encode(
            dumps(claims),
            key,
            protected=protected_header,
            unprotected=unprotected_header,
        )

        return encoded
