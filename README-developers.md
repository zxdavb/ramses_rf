![Linting](https://github.com/zxdavb/ramses_rf/actions/workflows/check-lint.yml/badge.svg)
![Typing](https://github.com/zxdavb/ramses_rf/actions/workflows/check-type.yml/badge.svg)
![Testing](https://github.com/zxdavb/ramses_rf/actions/workflows/check-test.yml/badge.svg)

# Ramses_rf developer's resource

## Installation

Confirm you have Python 3.13.x installed by running:
```
python3 --version
```

### Virtual environment

Create a `venv` virtual environment, for example on macOS or Linux:
```
mkdir /your-path-to/virtual-envs
mkdir /your-path-to/virtual-envs/ramses_rf
cd /your-path-to/virtual-envs/ramses_rf 
Python3.13 -m venv ~/your-path-to/virtual-envs/ramses_rf
```
For venv hints, see [Where to put your venvs](https://pybit.es/articles/a-better-place-to-put-your-python-virtual-environments/)

Repeat for every session:
```
cd /your-path-to/ramses_rf
source ~/your-path-to/virtual-envs/ramses_rf/bin/activate
```
and confirm your Terminal prompt looks like
`(ramses_rf) user:ramses_rf `

### Clone this repo

Clone this repo and install the requirements.
Using `pip`, in a location where your IDE has access:
```
git clone https://github.com/zxdavb/ramses_rf
cd ramses_rf
pip install -r requirements.txt
pip install -r requirements_dev.txt
```

You need to repeat this after an update or bump.

### Install pre-commit hook
Install the repo's pre-commit hook
```
pre-commit install
```

Running `pre-commit run` will only check staged files before a commit, while
`pre-commit run -a` will check all files.

## Test locally
Run the following three commands on your branch in your venv daily, and before each commit:
```
mypy
pytest
ruff format .
```
and confirm they pass.

To fix import sorts flagged (but not fixed) by `ruff format`, run:
```
ruff check --select I --fix
```
