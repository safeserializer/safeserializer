#  Copyright (c) 2021. Davi Pereira dos Santos
#  This file is part of the lazydf project.
#  Please respect the license - more about this in the section (*) below.
#
#  lazydf is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  lazydf is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with lazydf.  If not, see <http://www.gnu.org/licenses/>.
#
#  (*) Removing authorship by any means, e.g. by distribution of derived
#  works or verbatim, obfuscated, compiled or rewritten versions of any
#  part of this work is illegal and unethical regarding the effort and
#  time spent here.
import json
import pickle
from importlib import import_module

import bson
from bson import InvalidDocument
from orjson import OPT_SORT_KEYS, orjson, dumps


def topickle(obj, ensure_determinism):
    try:
        try:
            prefix = b"05pckl_"
            dump = pickle.dumps(obj, protocol=5)
        except Exception as e:
            if ensure_determinism:  # pragma: no cover
                print(e)
                raise NondeterminismException("Cannot serialize deterministically.")
            import dill

            prefix = b"05dill_"
            dump = dill.dumps(obj, protocol=5)

        blob = prefix + dump
        return blob
    except KeyError as e:  # pragma: no cover
        if str(e) == "'__getstate__'":  # pragma: no cover
            raise Exception("Unpickable value:", type(obj))
        else:
            raise e


def frompickle(blob):
    prefix = blob[:7]
    blob = blob[7:]
    if prefix == b"05pckl_":
        return pickle.loads(blob)
    elif prefix == b"05dill_":
        import dill

        return dill.loads(blob)


m = {"<class 'pandas.core.frame.DataFrame'>": b"00pddf_", "<class 'pandas.core.series.Series'>": b"00pdsr_"}


def traversal_enc(obj, ensure_determinism, unsafe_fallback):
    if isinstance(obj, bytes):
        return obj
    try:
        return b"00json_" + orjson.dumps(obj)
    except TypeError as e:
        pass
    try:
        return b"00bson_" + bson.encode({"_": obj})
    except InvalidDocument as e:
        pass
    except OverflowError as o:
        if "8-byte ints" in str(o) and isinstance(obj, int):
            return b"00bint_" + str(obj).encode()
    klass = str(obj.__class__)
    if klass in ["<class 'numpy.ndarray'>"]:
        return serialize_numpy(obj, ensure_determinism, unsafe_fallback)
    if klass in ["<class 'pandas.core.frame.DataFrame'>", "<class 'pandas.core.series.Series'>"]:
        return serialize_numpy(obj.to_numpy(), ensure_determinism, unsafe_fallback, m[klass])
    if isinstance(obj, list):
        lst_of_bins = []
        for o in obj:
            lst_of_bins.append(traversal_enc(o, ensure_determinism, unsafe_fallback))
        return b"00trav_" + bson.encode({"_": lst_of_bins})
    if unsafe_fallback:
        return topickle(obj, ensure_determinism)
    raise Exception(f"Cannot pack {type(obj)}.")


def traversal_dec(dump):
    if isinstance(dump, bytes):
        header = dump[2:7]
        blob = dump[7:]
        if header == b"json_":
            return orjson.loads(blob)
        if header == b"bson_":
            return bson.decode(blob)["_"]
        if header == b"bint_":
            return int(blob.decode())
        if header == b"nmpy_":
            return deserialize_numpy(blob)
        if header == b"pddf_":
            from pandas import DataFrame

            return DataFrame(deserialize_numpy(blob))
        if header == b"pdsr_":
            from pandas import Series

            return Series(deserialize_numpy(blob))
        if header == b"trav_":
            return traversal_dec(bson.decode(blob)["_"])
        if header in [b"pckl_", b"dill_"]:
            return frompickle(dump)
        return dump
    if isinstance(dump, (int, str, bool)):
        return dump
    if isinstance(dump, list):
        lst = []
        for d in dump:
            lst.append(traversal_dec(d))
        return lst
    if isinstance(dump, dict):
        dic = {}
        for k, v in dump.items():
            dic[k] = traversal_dec(v)
        return dic
    raise Exception(f"Cannot unpack {type(dump)}.")


def pack(obj, ensure_determinism, unsafe_fallback, compressed=True):
    r"""
    >>> import numpy as np
    >>> d = [[np.array([[1, 2/3], [4, 5]]), {"x": b"dsa"}], [b"asd", 5]]
    >>> blob = pack(d, ensure_determinism=True, unsafe_fallback=False)
    >>> unpack(blob)
    [[array([[1.        , 0.66666667],
           [4.        , 5.        ]]), {'x': b'dsa'}], [b'asd', 5]]
    >>> blob = pack(d, compressed=False, ensure_determinism=True, unsafe_fallback=False)
    >>> unpack(blob)
    [[array([[1.        , 0.66666667],
           [4.        , 5.        ]]), {'x': b'dsa'}], [b'asd', 5]]
    >>> import pandas as pd
    >>> df = pd.DataFrame(np.array([[1, 2/3], [4, 5]]))
    >>> unpack(pack(df, ensure_determinism=True, unsafe_fallback=False))
         0         1
    0  1.0  0.666667
    1  4.0  5.000000
    """
    dump = traversal_enc(obj, ensure_determinism, unsafe_fallback)
    if compressed:
        import lz4.frame as lz4

        return b"00lz4__" + lz4.compress(dump)
    return dump


def unpack(blob):
    if blob[:7] == b"00lz4__":
        import lz4.frame as lz4

        blob = lz4.decompress(blob[7:])
    return traversal_dec(blob)


class NondeterminismException(Exception):
    pass


def serialize_numpy(obj, ensure_determinism, unsafe_fallback, prefix=b"00nmpy_"):
    import numpy as np

    if isinstance(obj, np.ndarray):
        if obj.dtype in [np.dtype(object)]:
            if unsafe_fallback:
                return topickle(obj, ensure_determinism)
            raise Exception(f"Cannot handle this ndarray dtype: '{np.dtype(object)}'")

        dims = str(len(obj.shape))
        dtype = str(obj.dtype)
        rest_of_header = f"§{dims}§{dtype}§".encode() + integers2bytes(obj.shape)
        rest_of_header_len = str(len(rest_of_header)).encode()
        header = rest_of_header_len + rest_of_header
        # return header + lz4.compress(ascontiguousarray(obj).data)
        return prefix + header + obj.data.tobytes()
    raise Exception(f"Cannot handle this type '{type(obj)}', check its shape or dtype")


def deserialize_numpy(blob):
    import numpy as np

    rest_of_header_len = blob[:10].split(b"\xc2\xa7")[0]
    first_len = len(rest_of_header_len)
    header_len = first_len + int(rest_of_header_len)
    dims, dtype, hw = blob[first_len + 2 : header_len].split(b"\xc2\xa7")
    dims = int(dims.decode())
    dtype = dtype.decode().rstrip()
    shape = bytes2integers(hw.ljust(4 * dims))

    dump = memoryview(blob)[header_len:]
    # dump = lz4.decompress(dump)
    m = np.frombuffer(dump, dtype=dtype)
    if dims > 1:
        m = np.reshape(m, newshape=shape)
    return m


def integers2bytes(lst, n=4) -> bytes:
    """Each int becomes N bytes. max=4294967294 for 4 bytes"""
    return b"".join(d.to_bytes(n, byteorder="little") for d in lst)


def bytes2integers(bytes_content: bytes, n=4):
    """Each 4 bytes become an int."""
    return [int.from_bytes(bytes_content[i : i + n], "little") for i in range(0, len(bytes_content), n)]


########################################################################################
########################################################################################
########################################################################################
########################################################################################


# def import_dependence(dep):
#     try:
#         return import_module(dep)
#     except ImportError as e:
#         raise Exception(f"Missing {dep} library. Need a complete install\n" "pip install -U lazydf[full]")


# def custom_orjson_encoder(obj):
#     # E.g., pandas dataframes.
#     typ = str(type(obj))
#     if typ == "<class 'pandas.core.frame.DataFrame'>":
#         return obj.to_numpy()
#     if typ == "<class 'pandas.core.series.Series'>":
#         return obj.to_numpy()
#     # if hasattr(obj, 'to_json'):
#     #     # REMINDER: default_handler=str is to avoid infinite recursion, e.g., on iris.arff
#     #     txt = obj.to_json(force_ascii=False, default_handler=str)
#     #     return {"_type_orjson": str(type(obj)), "_obj.to_json()": txt}
#
#     # Numpy objects generic type and ndarray, keeping dtype.
#     if typ == "<class 'numpy.ndarray'>":
#         print(typ)
#         try:
#             return serialize_numpy(obj,ensure_determinism,unsafe_fallback) is None ???
#         except Exception as e:
#             print(e)
#             exit()
#
#     # try:
#     #     import numpy
#     #     if isinstance(obj, numpy.generic):
#     #         return {"_type_orjson": str(obj.dtype), "_numpy.asscalar(obj)": numpy.asscalar(obj)}
#     #     if isinstance(obj, numpy.ndarray):
#     #         return {"_type_orjson": str(obj.dtype), "_numpy.ndarray.tolist()": obj.tolist()}
#     # except ImportError as e:
#     #     pass
#
#     if isinstance(obj, bytes):
#         return obj.decode()  # nem qq byte vira string!
#     raise TypeError


# def json_object_hook_decoder(dic):
#     if "_type_orjson" in dic:
#         if "_obj.to_json()" in dic:
#             if dic["_type_orjson"] == "<class 'pandas.core.frame.DataFrame'>":
#                 m = import_dependence("pandas")
#                 return m.read_json(dic["_obj.to_json()"])  # , default_handler=str)
#             if dic["_type_orjson"] == "<class 'pandas.core.series.Series'>":
#                 m = import_dependence("pandas")
#                 # default_handler=callable
#                 return m.read_json(dic["_obj.to_json()"], typ=dic["_type_orjson"])
#             else:  # pragma: no cover
#                 raise Exception(f"Cannot desserialize object of type '{dic['_type_orjson']}'")
#         if (c := "_numpy.asscalar(obj)") in dic or (c := "_numpy.ndarray.tolist()") in dic:
#             m = import_dependence("numpy")
#             dtype = "str" if len(dic["_type_orjson"]) > 10 else dic["_type_orjson"]
#             return m.array(dic[c], dtype=dtype)
#     return dic


# def serialize_json(obj):
#     # r"""
#     # >>> import numpy as np
#     # >>> import math
#     # >>> a = np.array([[1/3, 5/4], [1.3**6, "text"]])
#     # >>> a
#     # array([['0.3333333333333333', '1.25'],
#     #        ['4.826809000000001', 'text']], dtype='<U32')
#     # >>> b = np.array([[1/3,5/4], [1.3**6, 4]], dtype = np.int64)
#     # >>> b
#     # array([[0, 1],
#     #        [4, 4]])
#     # >>> c = np.array([[1/3,5/4], [1.3**6, 4]], dtype = np.int8)
#     # >>> c
#     # array([[0, 1],
#     #        [4, 4]], dtype=int8)
#     # >>> serialize_json([math.inf, a, b, c])
#     # b'[null,{"_numpy.ndarray.tolist()":[["0.3333333333333333","1.25"],["4.826809000000001","text"]],"_type_orjson":"<U32"},{"_numpy.ndarray.tolist()":[[0,1],[4,4]],"_type_orjson":"int64"},{"_numpy.ndarray.tolist()":[[0,1],[4,4]],"_type_orjson":"int8"}]'
#     # >>> import pandas as pd
#     # >>> df = pd.DataFrame(
#     # ...     [[1/3, 5/4], [1.3**54, "text"]],
#     # ...     index=["row 1", "row 2"],
#     # ...     columns=["col 1", "col 2"],
#     # ... )
#     # >>> df
#     #               col 1 col 2
#     # row 1  3.333333e-01  1.25
#     # row 2  1.422136e+06  text
#     # >>> serialize_json(df)
#     # b'{"_obj.to_json()":"{\\"col 1\\":{\\"row 1\\":0.3333333333,\\"row 2\\":1422135.6537506874},\\"col 2\\":{\\"row 1\\":1.25,\\"row 2\\":\\"text\\"}}","_type_orjson":"<class \'pandas.core.frame.DataFrame\'>"}'
#     # >>> s = pd.Series(
#     # ...     [1/3, 5/4, (1.3)**54, "text"],
#     # ...     index=["row 1", "row 2", "row 3", "row 4"],
#     # ... )
#     # >>> s
#     # row 1          0.333333
#     # row 2              1.25
#     # row 3    1422135.653751
#     # row 4              text
#     # dtype: object
#     # >>> serialize_json(s)
#     # b'{"_obj.to_json()":"{\\"row 1\\":0.3333333333,\\"row 2\\":1.25,\\"row 3\\":1422135.6537506874,\\"row 4\\":\\"text\\"}","_type_orjson":"<class \'pandas.core.series.Series\'>"}'
#     # """
#     return dumps(obj, default=custom_orjson_encoder, option=OPT_SORT_KEYS)


# def deserialize_json(blob):
#     return json.loads(blob, object_hook=json_object_hook_decoder)
