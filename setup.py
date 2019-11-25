import setuptools

VERSION = "0.0.1"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ramses",
    version=VERSION,

    author="David Bonnes",
    author_email="zxdavb@gmail.com",

    description="A Honeywell RAMSES II client",
    long_description=long_description,
    long_description_content_type="text/markdown",

    url="https://github.com/zxdavb/ramses-client",
    download_url="https://github.com/zxdavb/ramses-client/archive/VERSION.tar.gz",

    packages=['ramsesclient'],
    keywords=["evohome", "ramses"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    ],
)
