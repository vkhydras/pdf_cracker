"""
Setup script for the PDF Password Cracker package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pdf-password-cracker",
    version="0.1.0",
    author="PDF Cracker Team",
    author_email="example@example.com",
    description="Advanced PDF Password Cracker",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/pdf-password-cracker",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",
    install_requires=[
        "pikepdf>=2.0.0",
        "tqdm>=4.50.0",
    ],
    entry_points={
        "console_scripts": [
            "pdf-cracker=pdf_cracker.cli:main",
        ],
    },
)