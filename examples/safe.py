# Packing and safe unpacking
from pandas import DataFrame as DF

from safeserializer import unpack, pack

df = DF({"a": ["5", "6", "7"], "b": [1, 2, 3]}, index=["x", "y", "z"])
complex_data = {"a": b"Some binary content", ("mixed-types tuple as a key", 4): 123, "df": df}
print(complex_data)
# ...

dump = pack(complex_data, ensure_determinism=True, unsafe_fallback=False)
print(dump)
# ...

obj = unpack(dump)
print(obj)
# ...
