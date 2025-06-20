# setup.py
import re
from pathlib import Path
from setuptools import setup, find_packages

# Read requirements from requirements.txt
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

def get_version():
    content = Path("whisper/__init__.py").read_text()
    return re.search(r'^__version__ = ["\']([^"\']+)["\']', content, re.M).group(1)

setup(
    name="whisper",
    version=get_version(),
    description="Decrypt messages and attachments from the Whisper system.",
    author="Indrajit Ghosh",
    author_email="rs_math1902@isibang.ac.in",
    url="https://github.com/indrajit912/Whisper",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "whisper=whisper.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.7",
)
