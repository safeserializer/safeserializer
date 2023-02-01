#  Copyright (c) 2023. Davi Pereira dos Santos
#  This file is part of the safeserializer project.
#  Please respect the license - more about this in the section (*) below.
#
#  safeserializer is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  safeserializer is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with safeserializer.  If not, see <http://www.gnu.org/licenses/>.
#
#  (*) Removing authorship by any means, e.g. by distribution of derived
#  works or verbatim, obfuscated, compiled or rewritten versions of any
#  part of this work is illegal and unethical regarding the effort and
#  time spent here.
import pickle
from binascii import hexlify, unhexlify

import bson
from bson import InvalidDocument
from orjson import orjson


def topickle(obj, ensure_determinism):
    """
    >>> f = print
    >>> du = topickle({"a": [3, f]}, ensure_determinism=False)
    >>> res = frompickle(du)
    >>> res["a"][1]() is None
    <BLANKLINE>
    True
    >>> frompickle(topickle({"a": [3, None]}, ensure_determinism=True))
    {'a': [3, None]}
    """
    try:
        prefix = b"05pckl_"
        dump = pickle.dumps(obj, protocol=5)
    except Exception as e:  # pragma: no cover
        if ensure_determinism:
            print(e)
            raise NondeterminismException("Cannot serialize deterministically.")
        import dill

        try:
            prefix = b"05dill_"
            dump = dill.dumps(obj, protocol=5)
        except KeyError as e:
            if str(e) == "'__getstate__'":
                raise Exception("Unpickable value:", type(obj))
            else:
                raise e
    blob = prefix + dump
    return blob


def frompickle(blob):
    """
    >>> du = frompickle(b'05pckl_\\x80\\x05\\x95#\\x00\\x00\\x00\\x00\\x00\\x00\\x00}\\x94\\x8c\\x01a\\x94]\\x94(K\\x03\\x8c\\x08builtins\\x94\\x8c\\x05print\\x94\\x93\\x94es.')
    >>> du["a"][1]() is None
    <BLANKLINE>
    True
    """
    prefix = blob[:7]
    blob = blob[7:]
    if prefix == b"05pckl_":
        return pickle.loads(blob)
    elif prefix == b"05dill_":  # pragma: no cover
        import dill

        return dill.loads(blob)


def traversal_enc(obj, ensure_determinism, unsafe_fallback):
    """
    >>> unpack(pack(["a", ["3", 4], "b", 4], ensure_determinism=False, unsafe_fallback=False))
    ['a', ['3', 4], 'b', 4]
    >>> unpack(pack([{0: [{"3":4}], "b": b"b"}], ensure_determinism=False, unsafe_fallback=False))
    [{0: [{'3': 4}], 'b': b'b'}]
    >>> du = pack(True, ensure_determinism=False, unsafe_fallback=True, compressed=False)
    >>> du
    b'00json_true'
    >>> unpack(du)
    True
    >>> unpack(pack([True], ensure_determinism=False, unsafe_fallback=True, compressed=False))
    [True]
    >>> unpack(pack([{"a": b"some bytes", "b":print}], ensure_determinism=False, unsafe_fallback=True))[0]["a"]
    b'some bytes'
    >>> unpack(pack(b"some bytes", ensure_determinism=False, unsafe_fallback=True))
    b'some bytes'
    >>> unpack(pack(99999999999999999999999999999999999999999, ensure_determinism=False, unsafe_fallback=True))
    99999999999999999999999999999999999999999
    >>> from pandas import Series as S, DataFrame as DF
    >>> s = S({"a": 5, "b": 6}, name="column")
    >>> a = pack(s, ensure_determinism=True, unsafe_fallback=False)
    >>> a
    b'00lz4__\\x04"M\\x18h@^\\x00\\x00\\x00\\x00\\x00\\x00\\x00@\\\\\\x00\\x00\\x00\\xf1\\x0e00bsos_W\\x00\\x00\\x00\\x04i\\x00\\x17\\x00\\x00\\x00\\x020\\x00\\x02\\x00\\x00\\x00a\\x00\\x021\\t\\x00\\xf0\\nb\\x00\\x00\\x05v\\x00"\\x00\\x00\\x00\\x0016\\xc2\\xa71\\xc2\\xa7int64\\xc2\\xa7&\\x00\\x10\\x05\\x17\\x00A\\x00\\x00\\x00\\x06\\x06\\x00\\xf0\\x02\\x00\\x00\\x02n\\x00\\x07\\x00\\x00\\x00column\\x00\\x00\\x00\\x00\\x00\\x00'
    >>> unpack(a)
    a    5
    b    6
    Name: column, dtype: int64
    >>> s = S({"a": "5", "b": "6"})
    >>> b = pack(s, ensure_determinism=True, unsafe_fallback=False)
    >>> b
    b'00lz4__\\x04"M\\x18h@\\x1d\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\xec\\xe2\\x04\\x00\\x00\\xf0\\x1100prqs_PAR1\\x15\\x04\\x15\\x14\\x15\\x18L\\x15\\x04\\x15\\x00\\x12\\x00\\x00\\n$\\x01\\x00\\x00\\x005\\x05\\x00\\xf696\\x15\\x00\\x15\\x12\\x15\\x16,\\x15\\x04\\x15\\x10\\x15\\x06\\x15\\x06\\x1c6\\x00(\\x016\\x18\\x015\\x00\\x00\\x00\\t \\x02\\x00\\x00\\x00\\x04\\x01\\x01\\x03\\x02&\\x88\\x01\\x1c\\x15\\x0c\\x195\\x10\\x00\\x06\\x19\\x18\\x06_none_\\x15\\x02\\x16\\x04\\x16x\\x16\\x80\\x01&<&\\x088\\x00\\x10\\x19L\\x00\\x90\\x00\\x15\\x02\\x00\\x15\\x00\\x15\\x10\\x15B\\x00\\x0f}\\x00\\x01\\x10a}\\x00\\x1fb}\\x00\\x01Kb\\x18\\x01a}\\x00&\\x82\\x03}\\x00\\xf7\\x02\\x11__index_level_0_\\x88\\x00Q\\xb6\\x02&\\x82\\x02\\x8a\\x00\\x01E\\x00\\x0f\\x8a\\x00\\x01\\xf4\\x04\\x19<5\\x00\\x18\\x06schema\\x15\\x04\\x00\\x15\\x0c%\\x02\\xd0\\x00b%\\x00L\\x1c\\x00\\x00\\x13\\x00\\x0ef\\x00\\x03\\x1e\\x00o\\x16\\x04\\x19\\x1c\\x19,\\x0f\\x01*\\x0f\\xcf\\x007\\xf2\\r\\x16\\xf0\\x01\\x16\\x04&\\x08\\x16\\x80\\x02\\x14\\x00\\x00\\x19,\\x18\\x06pandas\\x18\\xfc\\x03{"%\\x01\\xcdcolumns": ["9\\x01R"], ""\\x00\\x02T\\x01\\x11e)\\x00\\xfa\\x07{"name": null, "field_\\x14\\x00\\x02i\\x00@_typ)\\x00\\xf5\\x02"unicode", "numpy\\x19\\x00`object\\x18\\x00\\xf6\\x12metadata": {"encoding": "UTF-8"}}\\x8d\\x00\\n\\x86\\x00\\x12"n\\x02\\x00D\\x00\\t\\x8a\\x00\\x07\\x18\\x00\\x0f\\x8e\\x00*\\x00\\xe6\\x00?}, \\xf6\\x00\\n\\x0f<\\x01\\x00\\x0fw\\x002\\x01\\xf4\\x00areator\\x18\\x01plibrary\\x17\\x01ppyarrow\\xf7\\x00pversion\\x16\\x00\\x8611.0.0"}~\\x00\\x08\\x1d\\x00\\xf2\\x00.5.3"}\\x00\\x18\\x0cARROW:\\xe6\\x02@\\x18\\xe0\\x07/\\x01\\x00\\x82+ACAAAQA\\x01\\x00\\xf1\\x00KAA4ABgAFAAgACg\\x15\\x00)BB \\x00\\x10w\\x15\\x00\\x15E \\x00 DQ@\\x00\\x10E\\x15\\x00\\x02F\\x00\\x01 \\x00\\x10I\\x08\\x00\\x11B\\x08\\x00\\x01E\\x00\\x10I \\x00\\x02%\\x00\\xf4FYAAABwYW5kYXMAAPwBAAB7ImluZGV4X2NvbHVtbnMiOiBbIl9faW5kZXhfbGV2ZWxfMF9fIl0sICJjb2x1bW5$\\x00\\xf0\\x01lcyI6IFt7Im5hbWUD\\x00\\xf3\\x15udWxsLCAiZmllbGRfbmFtZSI6IG51bGwsICJ\\x90\\x00aNfdHlw\\x1c\\x00\\xf0\\x0eCJ1bmljb2RlIiwgIm51bXB5X3R5cGX\\x00\\xa2Aib2JqZWN0 \\x00\\xf0\\x0c1ldGFkYXRhIjogeyJlbmNvZGluZ\\x94\\x00\\xd9CJVVEYtOCJ9fV\\xbc\\x00\\x10z0\\x00EW3si\\x98\\x00\\xbfCJfbm9uZV8i\\xb8\\x00\\x02\\x0b \\x00\\x88cGFuZGFz\\x9c\\x00\\xb0dW5pY29kZSI\\xe0\\x00\\xd0udW1weV90eXBlp\\x00\\xa1Im9iamVjdC \\x00\\xa5tZXRhZGF0Y\\x18\\x01@x9LC\\x98\\x01\\x0fH\\x01\\x10TCJfX2\\xc0\\x01\\xc1xldmVsXzBfXy\\\\\\x00\\x0f\\\\\\x01>\\x80bnVsbH1d\\x1c\\x01\\xf0\\nY3JlYXRvciI6IHsibGlicmFye\\xc8\\x00\\xb1CJweWFycm93\\xa4\\x01\\xa1nZlcnNpb24\\xc0\\x01\\xa1MTEuMC4wIn\\x90\\x01\\x06\\xa8\\x00\\x80mVyc2lvbT\\x00\\xb0CIxLjUuMyJ9\\xc4\\x02\\x02\\xcb\\x02 BM\\n\\x00\\x10B\\x05\\x00\\xb1Mz///8AAAEF\\xe0\\x02\\x11CK\\x03\\x01\\x0b\\x00\\x01\\x02\\x00\\x10B\\x0b\\x00\\x1fB \\x01\\x03`wAAAMj@\\x00@QABQ\\x89\\x03`GAAcAD9\\x00\\x17BE\\x00!QUU\\x00\\x10H\\x18\\x00\\x02e\\x03\\x01\\x02\\x00\\x10B[\\x03\\x94F9ub25lXw3\\x00\\x01+\\x00\\x01\\x02\\x00\\xf1\\x00\\x00\\x18 parquet-cpp-9\\x04\\x13 \\x19\\x04\\x12 3\\x04P\\x19,\\x1c\\x00\\x00\\xdf\\x06\\x80\\x03\\x07\\x00\\x00PAR1\\x00\\x00\\x00\\x00'
    >>> unpack(b)
    a    5
    b    6
    dtype: object
    >>> s = S({"a": "5", "b": 6}, name="column")
    >>> unpack(pack(s, ensure_determinism=True, unsafe_fallback=True))
    a    5
    b    6
    Name: column, dtype: object
    >>> df = DF({"a": ["5","6","7"], "b": [1,2,3]}, index=["x","y","z"])
    >>> unpack(pack(df, ensure_determinism=True, unsafe_fallback=False))
       a  b
    x  5  1
    y  6  2
    z  7  3
    >>> df = DF({"a": ["5",6,"7"], "b": ["1","2","3"]}, index=["x","y","z"])
    >>> unpack(pack(df, ensure_determinism=True, unsafe_fallback=True))
       a  b
    x  5  1
    y  6  2
    z  7  3
    """
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
    if klass == "<class 'pandas.core.series.Series'>":
        try:
            idx = obj.index.values.tolist()
            vals = serialize_numpy(obj.to_numpy(), ensure_determinism, False, b"")
            dic = {"i": idx, "v": vals}
            if obj.name is not None:
                dic["n"] = obj.name
            return b"00bsos_" + bson.encode(dic)
        except Exception as e:
            if str(e).startswith("Please enable 'unsafe_fallback'"):
                from pandas import DataFrame
                try:
                    return b"00prqs_" + obj.to_frame(obj.name or "_none_").to_parquet()  # .convert_dtypes().to_parquet()
                except Exception as e:
                    pass
    elif klass == "<class 'pandas.core.frame.DataFrame'>":
        try:
            return serialize_numpy(obj.to_numpy(), ensure_determinism, unsafe_fallback=False, prefix=b"00npdf_")
        except Exception as e:
            if str(e).startswith("Please enable 'unsafe_fallback'"):
                try:
                    return b"00prqd_" + obj.to_parquet()
                except:
                    pass
    elif isinstance(obj, list):
        lst_of_binaries = []
        for o in obj:
            lst_of_binaries.append(traversal_enc(o, ensure_determinism, unsafe_fallback))
        return b"00list_" + bson.encode({"_": lst_of_binaries})
    elif isinstance(obj, dict):
        dic_of_binaries, prefix = {}, b"00dict_"
        hexfy = False
        for k, o in obj.items():
            if not isinstance(k, str):
                hexfy = True
            if hexfy:
                prefix = b"00dicB_"
                bk = traversal_enc(k, ensure_determinism, unsafe_fallback)
                k = hexlify(bk).decode('utf-8')
            dic_of_binaries[k] = traversal_enc(o, ensure_determinism, unsafe_fallback)
        return prefix + bson.encode(dic_of_binaries)
    if unsafe_fallback:
        return topickle(obj, ensure_determinism)
    raise Exception(f"Cannot safely pack {type(obj)}.")  # pragma: no cover


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
        if header == b"prqs_":
            import pandas as pd
            from io import BytesIO
            obj = pd.read_parquet(BytesIO(blob)).squeeze()
            if obj.name == "_none_":
                obj.rename(None, inplace=True)
            return obj
        if header == b"bsos_":
            from pandas import Series
            dec = bson.decode(blob)
            obj = deserialize_numpy(dec["v"])
            kwargs = {"name": dec["n"]} if "n" in dec else {}
            return Series(obj, dec["i"], **kwargs)
        if header == b"prqd_":
            import pandas as pd
            from io import BytesIO
            return pd.read_parquet(BytesIO(blob))
        if header == b"npdf_":
            from pandas import DataFrame
            return DataFrame(deserialize_numpy(blob))
        if header == b"list_":
            return traversal_dec(bson.decode(blob)["_"])
        if header == b"dict_":
            return traversal_dec(bson.decode(blob))
        if header == b"dicB_":
            decoded = bson.decode(blob).items()
            a = ({k.encode('utf-8'): traversal_dec(v) for k, v in decoded})
            return {traversal_dec(unhexlify(k.encode('utf-8'))): traversal_dec(v) for k, v in decoded}
        if header in [b"pckl_", b"dill_"]:
            return frompickle(dump)
        return dump
    # if isinstance(dump, (int, str, bool)):
    #     return dump
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
    raise Exception(f"Cannot unpack {type(dump)}.")  # pragma: no cover


def pack(obj, ensure_determinism, unsafe_fallback, compressed=True):
    r"""
    Serialize 'obj' to bytes.

    Attempt to serialize using one of the following options, in this order:
        orjson
        bson
        bigints as str
        numpy ndarray as raw bytes
        pandas numeric Series/DataFrame as ndarray raw bytes
        pandas ill-behaved Series/DataFrame as parquet
        pickle when 'unsafe_fallback=True'
        dill when 'ensure_determinism=False'.

    >>> import numpy as np
    >>> d = [[np.array([[1, 2/3], [4, 5]]), {"x": b"dsa"}], [b"asd", 5]]
    >>> blob = pack(d, ensure_determinism=True, unsafe_fallback=False)
    >>> unpack(blob)
    [[array([[1.        , 0.66666667],
           [4.        , 5.        ]]), {'x': b'dsa'}], [b'asd', 5]]
    >>> blob = pack(d, ensure_determinism=True, unsafe_fallback=False, compressed=False)
    >>> unpack(blob)
    [[array([[1.        , 0.66666667],
           [4.        , 5.        ]]), {'x': b'dsa'}], [b'asd', 5]]
    >>> import pandas as pd
    >>> df = pd.DataFrame(np.array([[1, 2/3], [4, 5]]))
    >>> unpack(pack(df, ensure_determinism=True, unsafe_fallback=False))
         0         1
    0  1.0  0.666667
    1  4.0  5.000000

    >>> unpack(pack({"0": 3, "b": print}, ensure_determinism=True, unsafe_fallback=True, compressed=False))
    {'0': 3, 'b': <built-in function print>}
    >>> unpack(pack({"0": 3, "b": b"b"}, ensure_determinism=True, unsafe_fallback=False, compressed=False))
    {'0': 3, 'b': b'b'}
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
    """
    >>> from pandas import Series as S, DataFrame as DF, Series as S
    >>> df = DF({"a": ["5","6","7"], "b": ["1","2","3"]}, index=["x","y","z"]).to_numpy()
    >>> serialize_numpy(df, ensure_determinism=True, unsafe_fallback=True)
    b'05pckl_\\x80\\x05\\x95\\xa3\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x8c\\x15numpy.core.multiarray\\x94\\x8c\\x0c_reconstruct\\x94\\x93\\x94\\x8c\\x05numpy\\x94\\x8c\\x07ndarray\\x94\\x93\\x94K\\x00\\x85\\x94C\\x01b\\x94\\x87\\x94R\\x94(K\\x01K\\x03K\\x02\\x86\\x94h\\x03\\x8c\\x05dtype\\x94\\x93\\x94\\x8c\\x02O8\\x94\\x89\\x88\\x87\\x94R\\x94(K\\x03\\x8c\\x01|\\x94NNNJ\\xff\\xff\\xff\\xffJ\\xff\\xff\\xff\\xffK?t\\x94b\\x88]\\x94(\\x8c\\x015\\x94\\x8c\\x011\\x94\\x8c\\x016\\x94\\x8c\\x012\\x94\\x8c\\x017\\x94\\x8c\\x013\\x94et\\x94b.'
    """
    import numpy as np

    if isinstance(obj, np.ndarray):
        if obj.dtype in [np.dtype(object)]:
            if unsafe_fallback:
                return topickle(obj, ensure_determinism)
            raise Exception(f"Please enable 'unsafe_fallback' or handle numpy types." f"Cannot handle this ndarray dtype: '{obj.dtype}'")
        dims = str(len(obj.shape))
        dtype = str(obj.dtype)
        rest_of_header = f"§{dims}§{dtype}§".encode() + integers2bytes(obj.shape)
        rest_of_header_len = str(len(rest_of_header)).encode()
        header = rest_of_header_len + rest_of_header
        # return header + lz4.compress(ascontiguousarray(obj).data)
        return prefix + header + obj.data.tobytes()
    if unsafe_fallback:  # pragma: no cover
        return topickle(obj, ensure_determinism)
    raise Exception(f"Please enable 'unsafe_fallback'. Cannot handle this type '{type(obj)}'.")  # pragma: no cover


def deserialize_numpy(blob):
    import numpy as np

    rest_of_header_len = blob[:10].split(b"\xc2\xa7")[0]
    first_len = len(rest_of_header_len)
    header_len = first_len + int(rest_of_header_len)
    dims, dtype, hw = blob[first_len + 2: header_len].split(b"\xc2\xa7")
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
    return [int.from_bytes(bytes_content[i: i + n], "little") for i in range(0, len(bytes_content), n)]

########################################################################################
########################################################################################
########################################################################################
########################################################################################


# def import_dependence(dep):
#     try:
#         return import_module(dep)
#     except ImportError as e:
#         raise Exception(f"Missing {dep} library. Need a complete install\n" "pip install -U safeserializer[full]")


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
