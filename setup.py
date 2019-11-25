import setuptools

VERSION = "0.0.1"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="evohome",
    version=VERSION,
    author="David Bonnes",
    author_email="zxdavb@gmail.com",
    description="A Honeywell evohome RF agent (compliant with RAMSES II).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zxdavb/evohome",
    download_url="https://github.com/zxdavb/evohome/archive/VERSION.tar.gz",
    packages=["evohome"],
    keywords=["evohome", "ramses"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
    ],
)
