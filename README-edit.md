![test](https://github.com/lazydf/lazydf/workflows/test/badge.svg)
[![codecov](https://codecov.io/gh/lazydf/lazydf/branch/main/graph/badge.svg)](https://codecov.io/gh/lazydf/lazydf)
<a href="https://pypi.org/project/lazydf">
<img src="https://img.shields.io/github/v/release/lazydf/lazydf?display_name=tag&sort=semver&color=blue" alt="github">
</a>
![Python version](https://img.shields.io/badge/python-3.10-blue.svg)
[![license: GPL v3](https://img.shields.io/badge/License-GPLv3_%28ask_for_options%29-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![API documentation](https://img.shields.io/badge/doc-API%20%28auto%29-a0a0a0.svg)](https://lazydf.github.io/lazydf)


# lazydf - Serialization of nested objects to binary format 
An alternative to pickle, but may use pickle if safety is not needed.

Principle: Start from the simplest and safest possible and try to be fast.
* try orjson
  * `dict`, `str`, `int`, etc
* try bson
  * standard types accepted by mongodb
* serialize as numpy
  * ndarray, pandas dataframe/series

Non-deterministic and unsafe modes (pickle) are planned for the near future. 
 


## Python installation
### from package
```bash
# Set up a virtualenv. 
python3 -m venv venv
source venv/bin/activate

# Install from PyPI
pip install lazydf
```

### from source
```bash
git clone https://github.com/lazydf/lazydf
cd lazydf
poetry install
```

### Examples
Some usage examples.




## Grants
This work was partially supported by Fapesp under supervision of
Prof. André C. P. L. F. de Carvalho at CEPID-CeMEAI (Grants 2013/07375-0 – 2019/01735-0).
