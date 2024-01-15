import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    requirements = fh.read().split('\n')

setuptools.setup(
    name="mwdb-iocextract",
    version="1.2.2",
    data_files=[('requirements.txt', ['requirements.txt'])],
    author="CERT Polska",
    author_email="info@cert.pl",
    package_dir={"mwdb_iocextract": "src"},
    packages=["mwdb_iocextract"],
    description="Mwdb config parser",
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
