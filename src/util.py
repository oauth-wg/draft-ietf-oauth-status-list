from jwcrypto import jwk, jwt
import json

example = {
    "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8",
    "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
    "d": "Ur2bNKuBPOrAaxsRnbSH6hIhmNTxSGXshDSUD1a1y7g",
    "crv": "P-256",
    "kty": "EC",
    "kid": "12",
}
EXAMPLE_KEY = jwk.JWK(**example)


def formatToken(input: str, key: jwk.JWK) -> str:
    token = jwt.JWT(jwt=input, key=key, expected_type="JWS")
    header = printJson(token.header)
    claims = printJson(token.claims)
    return f"""{header}
.
{claims}"""


def printJson(input: str) -> str:
    return json.dumps(json.loads(input), sort_keys=True, indent=4)
