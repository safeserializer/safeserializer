# Packing and unsafe unpacking
from pandas import DataFrame as DF

from safeserializer import unpack, pack

# Packing a function.
df = DF({"a": [print, 1, 2], "b": [1, 2, 3]}, index=["x", "y", "z"])
print(df)
# ...

dump = pack(df, ensure_determinism=True, unsafe_fallback=True)
print(dump)
# ...

obj = unpack(dump)
print(obj)
# ...
