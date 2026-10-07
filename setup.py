"""Setup script for crlf-hunter"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="crlf-hunter",
    version="1.0.0",
    author="Security Researcher",
    author_email="security@example.com",
    description="CRLF Injection / HTTP Response Splitting Detection Tool for Authorized Penetration Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/crlf-hunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "crlf-hunter=crlf_hunter.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)