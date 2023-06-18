from jwcrypto import jwk, jwt
from status_list import StatusList
from datetime import datetime
from typing import Dict
import json

DEFAULT_ALG = "ES256"
STATUS_LIST_TYP = "statuslist+jwt"

class StatusListJWT:
    list: StatusList
    issuer: str
    subject: str
    _key: jwk.JWK
    _alg: str

    def __init__(
        self,
        issuer: str,
        subject: str,
        key: jwk.JWK,
        list: StatusList = None,
        size: int = 2**20,
        bits: int = 1,
        alg: str = None,
    ):
        if list is not None:
            self.list = list
        else:
            self.list = StatusList(size, bits)
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
        assert typ == STATUS_LIST_TYP
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
        exp: datetime = None,
        optional_claims: Dict = None,
        optional_header: Dict = None,
        compact=True,
        mtime=None
    ) -> str:
        # build claims
        if optional_claims is not None:
            claims = optional_claims
        else:
            claims = {}
        claims["sub"] = self.subject
        claims["iss"] = self.issuer
        claims["iat"] = int(iat.timestamp())
        if exp is not None:
            claims["exp"] = int(exp.timestamp())
        encoded_list = self.list.encode(mtime=mtime)
        claims["status_list"] = {
            "bits": self.list.bits,
            "lst": encoded_list,
        }

        # build header
        if optional_header is not None:
            header = optional_header
        else:
            header = {}
        if self._key.key_id:
            header["kid"] = self._key.key_id
        header["alg"] = self._alg
        header["typ"] = STATUS_LIST_TYP

        token = jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self._key)
        return token.serialize(compact=compact)
