#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='expresso-deltapatcher',
    version='0.2.1',
    include_package_data=True,
    description="Expresso Delta Patcher",
    packages=find_packages(),
    scripts=['deltapatcher.py'],
    install_requires=[],
    extras_require={
      'dev': [
         'pytest',
         'pytest-cov',
         'rangehttpserver'
      ]
    }
)
