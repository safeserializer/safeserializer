![test](https://github.com/safeserializer/safeserializer/workflows/test/badge.svg)
[![codecov](https://codecov.io/gh/safeserializer/safeserializer/branch/main/graph/badge.svg)](https://codecov.io/gh/safeserializer/safeserializer)
<a href="https://pypi.org/project/safeserializer">
<img src="https://img.shields.io/github/v/release/safeserializer/safeserializer?display_name=tag&sort=semver&color=blue" alt="github">
</a>
![Python version](https://img.shields.io/badge/python-3.10-blue.svg)
[![license: GPL v3](https://img.shields.io/badge/License-GPLv3_%28ask_for_options%29-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![API documentation](https://img.shields.io/badge/doc-API%20%28auto%29-a0a0a0.svg)](https://safeserializer.github.io/safeserializer)


# safeserializer - Serialization of nested objects to binary format 
An alternative to pickle, but may use pickle if safety is not needed.
Principle: Start from the simplest and safest possible and try to be fast.
Serialization is attempted in the following order:
* try orjson
  * `dict`, `str`, `int`, etc
* try bson
  * standard types accepted by mongodb
* convert bigints to str
* try to serialize as raw numpy bytes
  * ndarray, pandas homogeneous Series/DataFrame
* try parquet
  * pandas ill-typed Series/DataFrame
* resort to pickle if allowed (`unsafe_fallback=True`)
* resort to dill if allowed (`ensure_determinism=False`).

Top level tuples are preserved, insted of converted to lists (e.g., by bson).


## Python installation
### from package
```bash
# Set up a virtualenv. 
python3 -m venv venv
source venv/bin/activate

# Install from PyPI
pip install safeserializer[full]
```

### from source
```bash
git clone https://github.com/safeserializer/safeserializer
cd safeserializer
poetry install --extras full
```

### Examples
<<safe>>

<<unsafe>>



## Grants
This work was partially supported by Fapesp under supervision of
Prof. André C. P. L. F. de Carvalho at CEPID-CeMEAI (Grants 2013/07375-0 – 2019/01735-0).
