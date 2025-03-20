import math
import zlib
from random import choices
from uuid import uuid4

from py_markdown_table.markdown_table import markdown_table

from status_list import StatusList


def display_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB")
    floored = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, floored)
    rounded = round(size_bytes / p, 1)
    return "%s %s" % (rounded, size_name[floored])


sizes = [100000, 1000000, 10000000, 100000000]
rev_rates = [0.0001, 0.001, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 0.75, 1]

data_sl = []
data_uuid = []

for size in sizes:
    newdata_sl = {"size": size}
    newdata_uuid = {"size": size}
    for rev_rate in rev_rates:
        print(f"Revocation Rate: {rev_rate}")
        vals = [0, 1]
        p = [1 - rev_rate, rev_rate]
        sample = choices(population=vals, weights=p, k=size)

        statuslist = StatusList(size, 1)
        idlist = bytearray()
        for idx, val in enumerate(sample):
            statuslist.set(idx, val)
            if val == 1:
                idlist.extend(uuid4().bytes)

        rawsl = statuslist.encodeAsBytes()
        rawidlist = zlib.compress(idlist, level=9)

        percentage = str(rev_rate * 100) + "%"
        newdata_sl[percentage] = display_size(len(rawsl))
        newdata_uuid[percentage] = display_size(len(rawidlist))
        print(f"Size in Bytes: {display_size(len(rawsl))}")
        print(f"Size in Bytes uuid: {display_size(len(rawidlist))}")
    data_sl.append(newdata_sl)
    data_uuid.append(newdata_uuid)

markdown_sl = (
    markdown_table(data_sl)
    .set_params(
        padding_width=3,
        padding_weight="centerleft",
    )
    .get_markdown()
)
print(markdown_sl)
markdown_uuid = (
    markdown_table(data_uuid)
    .set_params(
        padding_width=3,
        padding_weight="centerleft",
    )
    .get_markdown()
)
print(markdown_uuid)
