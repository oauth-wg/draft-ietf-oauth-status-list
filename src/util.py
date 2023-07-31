from jwcrypto import jwk, jwt
from textwrap import fill
import json

example = {
    "kty": "EC",
    "d": "xzUEdsyLosZF0acZGRAjTKImb0lQvAvssDK5XIZELd0",
    "use": "sig",
    "crv": "P-256",
    "x": "I3HWm_0Ds1dPMI-IWmf4mBmH-YaeAVbPVu7vB27CxXo",
    "y": "6N_d5Elj9bs1htgV3okJKIdbHEpkgTmAluYKJemzn1M",
    "kid": "12",
    "alg": "ES256",
}

EXAMPLE_KEY = jwk.JWK(**example)
MAX_LENGTH = 68


def formatToken(input: str, key: jwk.JWK) -> str:
    token = jwt.JWT(jwt=input, key=key, expected_type="JWS")
    header = printJson(token.header)
    claims = printJson(token.claims)
    return f"""{header}
.
{claims}"""


def printJson(input: str) -> str:
    text = json.dumps(
        json.loads(input), sort_keys=True, indent=2, ensure_ascii=False
    )
    return text


def printText(input: str) -> str:
    return fill(input, width=MAX_LENGTH, break_on_hyphens=False)


def outputFile(file_name: str, input: str):
    with open(file_name, "w") as file:
        file.write(input)
