# setup.py (UPDATED)
from setuptools import setup, find_packages

setup(
    name="cyberchef-cli",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0.0",
        "rich>=13.0.0",
        "pycryptodome>=3.10.0", 
        "chardet>=5.0.0",
    ],
    entry_points={
        'console_scripts': [
            'cyberchef=cli.main:cli',
        ],
    },
    python_requires=">=3.7",
)