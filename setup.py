import setuptools

VERSION = "0.0.3"

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setuptools.setup(
    name="evohome",
    version=VERSION,
    author="David Bonnes",
    author_email="zxdavb@gmail.com",
    description="A Honeywell evohome RF agent (compliant with RAMSES II).",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/zxdavb/evohome",
    download_url="https://github.com/zxdavb/evohome/archive/VERSION.tar.gz",
    packages=["evohome"],
    keywords=["evohome", "ramses"],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: Home Automation",
    ],
)
