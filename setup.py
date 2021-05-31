#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='expresso-deltapatcher',
    version='0.2.0',
    include_package_data=True,
    description="Expresso Delta Patcher",
    packages=find_packages(),
    scripts=['patchtool.py'],
    install_requires=[],
    extras_require={
      'dev': [
         'pytest',
         'pytest-cov',
         'rangehttpserver'
      ]
    }
)
