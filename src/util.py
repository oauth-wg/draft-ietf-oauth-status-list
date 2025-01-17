import json
import subprocess
from textwrap import fill
from typing import Dict

from jwcrypto import jwk, jwt

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
    text = json.dumps(json.loads(input), sort_keys=True, indent=2, ensure_ascii=False)
    return fill(
        text, width=MAX_LENGTH, break_on_hyphens=False, replace_whitespace=False, subsequent_indent=''
    )


def printObject(input: Dict) -> str:
    return printJson(json.dumps(input))


def printText(input: str) -> str:
    return fill(input, width=MAX_LENGTH, break_on_hyphens=False)


# TODO: find a better way to do create CBOR Diagnostics output
# this is still too wide
def printCBORDiagnostics(input: bytes) -> str:
    diag = subprocess.check_output(
        "cborg hex2diag --width 65 " + input.hex(), shell=True
    ).decode("utf8")
    return diag


def outputFile(file_name: str, input: str):
    with open(file_name, "w") as file:
        file.write(input)
