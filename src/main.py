from status_list import StatusList
from status_token import StatusListToken
from datetime import datetime, timedelta
import os
import util

key = util.EXAMPLE_KEY
iat = datetime.utcfromtimestamp(1686920170)
exp = iat + timedelta(days=7000)
folder = "./examples/"


def statusListEncoding1Bit():
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
    encoded = status_list.encode()
    text = 'byte_array = [{}, {}] \nencoded = "{}"'.format(
        hex(status_list.list[0]), hex(status_list.list[1]), encoded
    )
    util.outputFile(folder + "status_list_encoding", text)


def exampleStatusList() -> StatusList:
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


def statusListEncoding2Bit():
    status_list = exampleStatusList()
    encoded = status_list.encode()
    text = 'byte_array = [{}, {}, {}] \nencoded = "{}"'.format(
        hex(status_list.list[0]),
        hex(status_list.list[1]),
        hex(status_list.list[2]),
        encoded,
    )
    util.outputFile(folder + "status_list_encoding2", text)


def statusListJWT():
    status_list = exampleStatusList()
    jwt = StatusListToken(
        issuer="https://example.com",
        subject="https://example.com/statuslists/1",
        list=status_list,
        key=key,
        bits=2,
    )
    status_jwt = jwt.buildJWT(iat=iat, exp=exp)
    text = util.formatToken(status_jwt, key)
    util.outputFile(folder + "status_list_jwt", text)


if __name__ == "__main__":
    if not os.path.exists(folder):
        os.makedirs(folder)
    statusListEncoding1Bit()
    statusListEncoding2Bit()
    statusListJWT()
