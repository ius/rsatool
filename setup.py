#!/usr/bin/env python3
from setuptools import setup

setup(
    name='rsatool',
    version='1.0',
    description='rsatool calculates RSA and RSA-CRT parameters',
    author='Joerie de Gram',
    author_email='j.de.gram@gmail.com',
    url='https://github.com/ius/rsatool',
    install_requires=['gmpy2', 'pyasn1'],
    scripts=['rsatool.py']
)
