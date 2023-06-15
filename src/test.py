from status_list import StatusList
from status_jwt import StatusListJWT
from datetime import datetime, timedelta
import util


test = StatusList(16, 1)
test.set(0, 1)
test.set(1, 0)
test.set(2, 0)
test.set(3, 1)
test.set(4, 1)
test.set(5, 1)
test.set(6, 0)
test.set(7, 1)
test.set(8, 1)
test.set(9, 1)
test.set(10, 0)
test.set(11, 0)
test.set(12, 0)
test.set(13, 1)
test.set(14, 0)
test.set(15, 1)
print(test)
print(bin(test.list[0]), bin(test.list[1]))
print(hex(test.list[0]), hex(test.list[1]))
encoded = test.encode()
print(encoded)


test = StatusList(12, 2)
test.set(0, 1)
test.set(1, 2)
test.set(2, 0)
test.set(3, 3)
test.set(4, 0)
test.set(5, 1)
test.set(6, 0)
test.set(7, 1)
test.set(8, 1)
test.set(9, 2)
test.set(10, 3)
test.set(11, 3)
print(test)
print(hex(test.list[0]), hex(test.list[1]), hex(test.list[2]))
encoded = test.encode()
print(encoded)

key = util.EXAMPLE_KEY
jwt = StatusListJWT(
    issuer="example.com", list=test, key=key, bits=2
)
exp = datetime.utcnow() + timedelta(7)
status_jwt = jwt.buildJWT(
    exp=exp,
    optional_claims={"custom": "value"},
    optional_header={"x5c": ["here_be_dragons"]},
)
print("-----------")
print(status_jwt)
print("-----------")
print(util.formatToken(status_jwt, key))
print("-----------")

status_jwt = jwt.buildJWT()
print(status_jwt)
print("-----------")
print(util.formatToken(status_jwt, key))
decoded_list = StatusListJWT.fromJWT(status_jwt, key)
print(decoded_list.list)
