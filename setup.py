#!/usr/bin/env python

from setuptools import setup

setup(
    name='deltapatcher',
    version='0.1.0',
    include_package_data=True,
    package_dir=".",
    description="Expresso Delta Patcher",
    scripts=['patchtool.py'],
    install_requires=[]
)
