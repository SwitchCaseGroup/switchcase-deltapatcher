#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='expresso-deltapatcher',
    version='0.2.0',
    include_package_data=True,
    description="Expresso Delta Patcher",
    packages=find_packages(),
    install_requires=['pytest', 'pytest-cov', 'rangehttpserver']
)
