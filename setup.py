#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='expresos-deltapatcher',
    version='0.1.0',
    include_package_data=True,
    description="Expresso Delta Patcher",
    packages=find_packages(),
#    scripts=['patchtool.py'],
    entry_points= {
      'console_scripts': ['patchtool=patchtool.py']
    },
    install_requires=[]
)
