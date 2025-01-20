import os
import random
from datetime import datetime, timedelta, timezone

import util
from referenced_token import CWT
from status_list import StatusList
from status_token import StatusListToken

key = util.EXAMPLE_KEY
iat = datetime.fromtimestamp(1686920170, timezone.utc)
exp = iat + timedelta(days=7000)
ttl = timedelta(hours=12)
folder = "./examples/"


def exampleStatusList1Bit() -> StatusList:
    status_list = StatusList(16, 1)
    status_list.set(0, 1)
    status_list.set(1, 0)
    status_list.set(2, 0)
    status_list.set(3, 1)
    status_list.set(4, 1)
    status_list.set(5, 1)
    status_list.set(6, 0)
    status_list.set(7, 1)
    status_list.set(8, 1)
    status_list.set(9, 1)
    status_list.set(10, 0)
    status_list.set(11, 0)
    status_list.set(12, 0)
    status_list.set(13, 1)
    status_list.set(14, 0)
    status_list.set(15, 1)
    return status_list


def exampleStatusList2Bit() -> StatusList:
    status_list = StatusList(12, 2)
    status_list.set(0, 1)
    status_list.set(1, 2)
    status_list.set(2, 0)
    status_list.set(3, 3)
    status_list.set(4, 0)
    status_list.set(5, 1)
    status_list.set(6, 0)
    status_list.set(7, 1)
    status_list.set(8, 1)
    status_list.set(9, 2)
    status_list.set(10, 3)
    status_list.set(11, 3)
    return status_list


def exampleStatusList2BitLong() -> StatusList:
    status_list = StatusList(2**20, 2)
    status_list.set(0, 1)
    status_list.set(1993, 2)
    status_list.set(25460, 1)
    status_list.set(159495, 3)
    status_list.set(495669, 1)
    status_list.set(554353, 1)
    status_list.set(645645, 2)
    status_list.set(723232, 1)
    status_list.set(854545, 1)
    status_list.set(934534, 2)
    status_list.set(1000345, 3)
    return status_list


def exampleStatusList4Bit() -> StatusList:
    status_list = StatusList(2**20, 4)
    status_list.set(0, 1)
    status_list.set(1993, 2)
    status_list.set(35460, 3)
    status_list.set(459495, 4)
    status_list.set(595669, 5)
    status_list.set(754353, 6)
    status_list.set(845645, 7)
    status_list.set(923232, 8)
    status_list.set(924445, 9)
    status_list.set(934534, 10)
    status_list.set(1004534, 11)
    status_list.set(1000345, 12)
    status_list.set(1030203, 13)
    status_list.set(1030204, 14)
    status_list.set(1030205, 15)
    return status_list


def exampleStatusList8Bit() -> StatusList:
    status_list = StatusList(2**20, 8)
    random.seed(42)
    for x in range(2**8):
        y = random.randint(0, 2**20 - 1)
        # print("status[{}] = {}".format(y,x))
        status_list.set(y, x)
    return status_list


def statusListEncoding1Bit():
    status_list = exampleStatusList1Bit()
    encoded = status_list.encodeAsJSON()
    text = "byte_array = [{}, {}] \nencoded:\n{}".format(
        hex(status_list.list[0]), hex(status_list.list[1]), util.printObject(encoded)
    )
    util.outputFile(folder + "status_list_encoding_json", text)


def statusListEncoding1BitCBOR():
    status_list = exampleStatusList1Bit()
    encoded = status_list.encodeAsCBORRaw()
    hex_encoded = encoded.hex()
    text = "byte_array = [{}, {}] \nencoded:\n{}".format(
        hex(status_list.list[0]), hex(status_list.list[1]), util.printText(hex_encoded)
    )
    util.outputFile(folder + "status_list_encoding_cbor", text)
    diag = util.printCBORDiagnostics(encoded)
    util.outputFile(folder + "status_list_encoding_cbor_diag", diag)


def statusListEncoding2Bit():
    status_list = exampleStatusList2Bit()
    encoded = status_list.encodeAsJSON()
    text = "byte_array = [{}, {}, {}] \nencoded:\n{}".format(
        hex(status_list.list[0]),
        hex(status_list.list[1]),
        hex(status_list.list[2]),
        util.printObject(encoded),
    )
    util.outputFile(folder + "status_list_encoding2_json", text)


def statusListEncoding2BitLong():
    status_list = exampleStatusList2BitLong()
    encoded = status_list.encodeAsJSON()
    text = "{}".format(
        util.printObject(encoded),
    )
    util.outputFile(folder + "status_list_encoding2_long_json", text)


def statusListEncoding2BitLongCBOR():
    status_list = exampleStatusList2BitLong()
    encoded = status_list.encodeAsCBORRaw()
    hex_encoded = encoded.hex()
    text = "{}".format(
        util.printText(hex_encoded)
    )
    util.outputFile(folder + "status_list_encoding2_long_cbor", text)


def statusListEncoding4Bit():
    status_list = exampleStatusList4Bit()
    encoded = status_list.encodeAsJSON()
    text = "{}".format(
        util.printObject(encoded),
    )
    util.outputFile(folder + "status_list_encoding4_json", text)


def statusListEncoding4BitCBOR():
    status_list = exampleStatusList4Bit()
    encoded = status_list.encodeAsCBORRaw()
    hex_encoded = encoded.hex()
    text = "{}".format(
        util.printText(hex_encoded)
    )
    util.outputFile(folder + "status_list_encoding4_cbor", text)


def statusListEncoding8Bit():
    status_list = exampleStatusList8Bit()
    encoded = status_list.encodeAsJSON()
    text = "{}".format(
        util.printObject(encoded),
    )
    util.outputFile(folder + "status_list_encoding8_json", text)

def statusListEncoding8BitCBOR():
    status_list = exampleStatusList8Bit()
    encoded = status_list.encodeAsCBORRaw()
    hex_encoded = encoded.hex()
    text = "{}".format(
        util.printText(hex_encoded)
    )
    util.outputFile(folder + "status_list_encoding8_cbor", text)


def statusListEncoding2BitCBOR():
    status_list = exampleStatusList2Bit()
    encoded = status_list.encodeAsCBORRaw()
    hex_encoded = encoded.hex()
    text = "byte_array = [{}, {}, {}] \nencoded:\n{}".format(
        hex(status_list.list[0]),
        hex(status_list.list[1]),
        hex(status_list.list[2]),
        util.printText(hex_encoded),
    )
    util.outputFile(folder + "status_list_encoding2_cbor", text)
    diag = util.printCBORDiagnostics(encoded)
    util.outputFile(folder + "status_list_encoding2_cbor_diag", diag)


def statusListJWT():
    status_list = exampleStatusList1Bit()
    jwt = StatusListToken(
        subject="https://example.com/statuslists/1",
        list=status_list,
        key=key,
    )
    status_jwt = jwt.buildJWT(iat=iat, exp=exp, ttl=ttl)
    text = util.formatToken(status_jwt, key)
    util.outputFile(folder + "status_list_jwt", text)


def statusListJWTRaw():
    status_list = exampleStatusList1Bit()
    jwt = StatusListToken(
        issuer="https://example.com",
        subject="https://example.com/statuslists/1",
        list=status_list,
        key=key,
    )
    status_jwt = jwt.buildJWT(iat=iat, exp=exp, ttl=ttl)
    text = util.printText(status_jwt)
    util.outputFile(folder + "status_list_jwt_raw", text)


def statusListCWT():
    status_list = exampleStatusList1Bit()
    cwt = StatusListToken(
        subject="https://example.com/statuslists/1",
        list=status_list,
        key=key,
        alg=-7,
    )
    status_cwt = cwt.buildCWT(iat=iat, exp=exp, ttl=ttl)
    hex_encoded = status_cwt.hex()
    util.outputFile(folder + "status_list_cwt", util.printText(hex_encoded))
    util.outputFile(
        folder + "status_list_cwt_diag", util.printCBORDiagnostics(status_cwt)
    )


def referencedTokenCWT():
    encoded = CWT(
        iat=iat,
        exp=exp,
        sub="12345",
        iss="https://example.com",
        jwk=key,
        status_url="https://example.com/statuslists/1",
        status_idx=0,
    )
    hex_encoded = encoded.hex()
    util.outputFile(folder + "referenced_token_cwt", util.printText(hex_encoded))
    util.outputFile(
        folder + "referenced_token_cwt_diag", util.printCBORDiagnostics(encoded)
    )


if __name__ == "__main__":
    if not os.path.exists(folder):
        os.makedirs(folder)
    statusListEncoding1Bit()
    statusListEncoding2Bit()
    statusListEncoding2BitLong()
    statusListEncoding2BitLongCBOR()
    statusListEncoding4Bit()
    statusListEncoding4BitCBOR()
    statusListEncoding8Bit()
    statusListEncoding8BitCBOR()
    statusListJWT()
    statusListJWTRaw()
    statusListEncoding1BitCBOR()
    statusListEncoding2BitCBOR()
    statusListCWT()
    referencedTokenCWT()
