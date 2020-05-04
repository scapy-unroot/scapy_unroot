#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

from setuptools import setup, find_packages
import os
import sys


name = "scapy_unroot"
version = "0.3.0b3"
description = "Daemon and tooling to enable using scapy without " \
              "root permissions."
author = "Martine S. Lenders"
author_email = "m.lenders@fu-berlin.de"
url = "https://github.com/scapy-unroot/scapy-unroot"


def with_directory(filename):
    return os.path.join(os.path.dirname(sys.argv[0]), filename)


def get_requirements():
    with open(with_directory("requirements.txt")) as req_file:
        for line in req_file:
            yield line.strip()


def get_readme():
    with open(with_directory("README.md")) as readme:
        return readme.read()

setup(
    name=name,
    version=version,
    description=description,
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=("tests",)),

    author=author,
    author_email=author_email,
    url=url,

    keywords=["network"],
    entry_points={
        'console_scripts': [
            'scapy-unroot = scapy_unroot.daemon:run',
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",
    ],

    install_requires=list(get_requirements()),
    python_requires=">=3.6",
    test_suite="tests"
)
