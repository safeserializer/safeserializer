import warnings
from pickle import dumps, loads
from timeit import timeit

import pyarrow as pa
import pyarrow.parquet as pq
from lz4.frame import compress, decompress
from pandas import DataFrame as DF
from pandas import Series as S
from pyarrow.feather import read_feather, write_feather

from lazydf.compression import pack, unpack

print("All options, except 'deprecated' and 'pickle' are unable to handle np.object (e.g., DF containing strings).")
print("Both options are unsafe (deprecated seems to use pickle).")

for l in [1, 10, 100, 1000]:
    df = DF({"a": ['5', '9', '11'] * l, "b": [7, 13, 19] * l})
    # s = DF({"a": [5, 9, 11] * l, "b": [7, 13, 19] * l})
    d = {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6}
    s = S(data=d, index=['a', 'b', 'c', 'd', 'e', 'f'])


    def a():
        a = pack(s, ensure_determinism=True, unsafe_fallback=False, compressed=True)
        b = pack(df, ensure_determinism=True, unsafe_fallback=False, compressed=True)
        unpack(a), unpack(b)
        return len(a) + len(b)


    def b():
        a = compress(dumps(df, protocol=5))
        b = compress(dumps(s, protocol=5))
        loads(decompress(a)), loads(decompress(b))
        return len(a) + len(b)


    def c():
        o1 = pa.BufferOutputStream()
        o2 = pa.BufferOutputStream()
        write_feather(df, o1, compression='lz4', compression_level=0)
        write_feather(s.to_frame(), o2, compression='lz4', compression_level=0)
        a = bytes(o1.getvalue())
        b = bytes(o2.getvalue())
        c = read_feather(pa.BufferReader(a))
        d = read_feather(pa.BufferReader(b))
        c, d
        return len(a) + len(b)


    def d():
        table = pa.Table.from_pandas(df)
        col = pa.Table.from_pandas(s.to_frame())
        buf = pa.BufferOutputStream()
        buf2 = pa.BufferOutputStream()
        pq.write_table(table, buf, compression='lz4', compression_level=0)
        pq.write_table(col, buf2, compression='lz4', compression_level=0)
        a = bytes(buf.getvalue())
        b = bytes(buf2.getvalue())

        c = pa.parquet.read_table(pa.BufferReader(a))
        d = pa.parquet.read_table(pa.BufferReader(b))
        c.to_pandas(), d.to_pandas().iloc[:, 0]

        return len(a) + len(b)


    t = timeit(a, number=1000)
    print(f"pack\t{round(t, 3):3.6}\tms", a(), sep="\t", end="\t\t")
    t = timeit(b, number=1000)
    print(f"pickle\t{round(t, 3):3.6}\tms", b(), sep="\t")
    # t = timeit(c, number=1000)
    # print("feather", round(t , 3), "ms", sep="\t\t")
    # t = timeit(d, number=1000)
    # print("parquet", round(t , 3), "ms", sep="\t\t")

"""
pack	3.111	ms	2735		pickle	0.222	ms	1287
pack	3.225	ms	2742		pickle	0.219	ms	1281
pack	3.796	ms	2753		pickle	0.224	ms	1301
pack	3.872	ms	2775		pickle	0.242	ms	1469

pack	1.717	ms	178		pickle	0.216	ms	1287
pack	1.833	ms	184		pickle	0.216	ms	1281
pack	2.34	ms	201		pickle	0.221	ms	1301
pack	2.422	ms	370		pickle	0.238	ms	1469

pack	4.551	ms	1450		pickle	0.22	ms	1310
pack	4.752	ms	1456		pickle	0.242	ms	1323
pack	5.77	ms	1464		pickle	0.24	ms	1332
pack	6.262	ms	1488		pickle	0.344	ms	1455

pack	1.621	ms	178		pickle	0.228	ms	1287
pack	1.813	ms	184		pickle	0.218	ms	1281
pack	2.317	ms	201		pickle	0.221	ms	1301
pack	2.367	ms	370		pickle	0.237	ms	1469

pack	1.694	ms	150		pickle	0.23	ms	1287
pack	1.911	ms	582		pickle	0.229	ms	1281
pack	2.486	ms	4902		pickle	0.235	ms	1301
pack	2.513	ms	48102		pickle	0.251	ms	1469

pack	4.546	ms	2231		pickle	0.222	ms	1310
pack	4.778	ms	2246		pickle	0.226	ms	1323
pack	5.84	ms	2265		pickle	0.245	ms	1332
pack	6.311	ms	2286		pickle	0.322	ms	1455

pack	4.587	ms	1446		pickle	0.223	ms	1310
pack	4.751	ms	1453		pickle	0.234	ms	1323
pack	5.796	ms	1462		pickle	0.236	ms	1332
pack	6.331	ms	1478		pickle	0.323	ms	1455

pack	3.611	ms	366		pickle	0.233	ms	1310
pack	3.791	ms	381		pickle	0.224	ms	1323
pack	4.514	ms	396		pickle	0.243	ms	1332
pack	5.123	ms	468		pickle	0.338	ms	1455

"""
