from setuptools import setup, find_packages
import os

from jarm import __version__, __license__, __author__

try:
    with open("README.md", encoding="utf8") as readme_file:
        readme = readme_file.read()
except TypeError:
    with open("README.md") as readme_file:
        readme = readme_file.read()

setup(
    name="pyjarm",
    version=__version__,
    description="pyJarm is a convenience library for the JARM fingerprinting tool.",
    author=__author__,
    long_description=readme,
    long_description_content_type="text/markdown",
    license=__license__,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    keywords="expanse, palo alto, jarm",
    packages=[*find_packages(exclude=["tests"])],
    install_requires=[],
    include_package_data=True,
    python_requires=">=3.6",
)
