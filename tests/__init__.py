#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

"""
scapy_unroot test suite
"""

import unittest


def test_all():
    # use the default shared TestLoader instance
    test_loader = unittest.defaultTestLoader
    # use the basic test runner that outputs to sys.stderr
    test_runner = unittest.TextTestRunner()
    # automatically discover all tests in the current dir of the form test*.py
    test_suite = test_loader.discover('.')
    # run the test suite
    test_runner.run(test_suite)
