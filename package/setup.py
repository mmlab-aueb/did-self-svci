from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

long_description = (here / 'README.md').read_text(encoding='utf-8')

setup(
    name="didselfsvci",
    version="1.0",
    author="Nikos Fotiou",
    author_email="fotiou@aueb.gr",
    description="Self-verifiable content items using did:self",
    license='MIT',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mmlab-aueb/did-self-svci",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires=">=3.6, <4",
    install_requires=['didself','jwcrypto']
)