from pickle import dumps, loads
from timeit import timeit

import pyarrow as pa
import pyarrow.parquet as pq
from lz4.frame import compress, decompress
from pandas import DataFrame as DF
from pandas import Series as S
from pyarrow.feather import read_feather, write_feather

from safeserializer.compression import pack, unpack

print("All options, except 'deprecated' and 'pickle' are unable to handle np.object (e.g., DF containing strings).")
print("Both options are unsafe (deprecated seems to use pickle).")

s = S({"a": "5", "b": "6"})
for l in [5, 1000]:
    df1 = DF({"a": [5, 9, 11] * l, "b": [7, 13, 19] * l})
    df2 = DF({"a": ['5', '9', '11'] * l, "b": [7, 13, 19] * l})


    def a():
        a = pack(s, ensure_determinism=True, unsafe_fallback=False, compressed=True)
        b = pack(df1, ensure_determinism=True, unsafe_fallback=False, compressed=True)
        c = pack(df2, ensure_determinism=True, unsafe_fallback=False, compressed=True)
        unpack(a), unpack(b), unpack(c)
        return len(a) + len(b) + len(c)


    def b():
        a = compress(dumps(df1, protocol=5))
        b = compress(dumps(df2, protocol=5))
        c = compress(dumps(s, protocol=5))
        loads(decompress(a)), loads(decompress(b)), loads(decompress(c))
        return len(a) + len(b) + len(c)


    def c():
        o1 = pa.BufferOutputStream()
        o2 = pa.BufferOutputStream()
        o3 = pa.BufferOutputStream()
        write_feather(df1, o1, compression='lz4', compression_level=0)
        write_feather(df2, o2, compression='lz4', compression_level=0)
        write_feather(s.to_frame(), o3, compression='lz4', compression_level=0)
        a = bytes(o1.getvalue())
        b = bytes(o2.getvalue())
        c = bytes(o3.getvalue())
        d = read_feather(pa.BufferReader(a))
        e = read_feather(pa.BufferReader(b))
        f = read_feather(pa.BufferReader(c))
        d, e, f
        return len(a) + len(b) + len(c)


    def d():
        table = pa.Table.from_pandas(df1)
        table2 = pa.Table.from_pandas(df2)
        col = pa.Table.from_pandas(s.to_frame())
        buf = pa.BufferOutputStream()
        buf2 = pa.BufferOutputStream()
        buf3 = pa.BufferOutputStream()
        pq.write_table(table, buf, compression='lz4', compression_level=0)
        pq.write_table(table2, buf2, compression='lz4', compression_level=0)
        pq.write_table(col, buf3, compression='lz4', compression_level=0)
        a = bytes(buf.getvalue())
        b = bytes(buf2.getvalue())
        c = bytes(buf3.getvalue())

        d = pa.parquet.read_table(pa.BufferReader(a))
        e = pa.parquet.read_table(pa.BufferReader(b))
        f = pa.parquet.read_table(pa.BufferReader(c))
        d.to_pandas(), e.to_pandas(), f.to_pandas().iloc[:, 0]
        return len(a) + len(b) + len(c)


    t = timeit(a, number=100)
    print(f"pack\t{round(t * 10, 3):2.3} ms", a(), sep="\t", end="\t\t")
    t = timeit(b, number=50)
    print(f"pickle\t{round(t * 10, 3):2.3} ms", b(), sep="\t", end="\t\t")
    # t = timeit(c, number=1000)
    # print("feather", round(t , 3), "ms", sep="\t\t")
    t = timeit(d, number=1000)
    print(f"parquet\t{round(t * 10, 3):2.3} ms", d(), sep="\t\t")
