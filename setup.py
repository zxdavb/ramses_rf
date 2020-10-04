import setuptools

VERSION = "0.3.2"

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setuptools.setup(
    name="evohome-rf",
    version=VERSION,
    author="David Bonnes",
    author_email="zxdavb@gmail.com",
    description="A Honeywell evohome RF agent (compliant with RAMSES II).",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/zxdavb/evohome_rf",
    # download_url="https://github.com/zxdavb/evohome_rf/archive/VERSION.tar.gz",
    packages=["evohome_rf"],
    # packages=setuptools.find_packages(exclude=['test']),
    keywords=["evohome", "ramses"],
    # install_requires=[list(val.strip() for val in open("requirements.txt"))],
    install_requires=["pyserial-asyncio==0.4", "voluptuous>=0.11.7"],
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: Home Automation",
    ],
)
