import os
import sys

from setuptools import find_packages, setup
from setuptools.command.install import install

VERSION = "0.0.8p1"

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()


class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our VERSION."""

    def run(self):
        tag = os.getenv("CIRCLE_TAG")

        if tag != VERSION:
            info = "Git tag: {tag} does not match the version of this pkg: {VERSION}"
            sys.exit(info)


setup(
    name="evohome",
    version=VERSION,
    packages=find_packages(),  # packages=["evohome"],
    install_requires=["aiofiles>=0.4.0", "aiosqlite==0.11.0", "pyserial-asyncio>=0.4"],
    # metadata to display on PyPI
    author="David Bonnes",
    author_email="zxdavb@gmail.com",
    description="A Honeywell evohome RF agent (compliant with RAMSES II).",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/zxdavb/evohome",
    download_url="{url}tarball/{VERSION}",
    keywords=["evohome", "ramses"],
    license="XXXX",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.7",
        "Topic :: Home Automation",
    ],
    cmdclass={"verify": VerifyVersionCommand},
)
