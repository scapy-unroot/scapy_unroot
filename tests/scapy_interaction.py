# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

"""
Interaction tests.
"""

import logging
import pexpect
import os
import shutil
import socket
import tempfile
import threading
import unittest

from scapy.all import conf, raw, send, sendp, sr1, srp1, \
                      Ether, ICMPv6EchoRequest, ICMPv6EchoReply, IPv6, UDP

from scapy_unroot import configure_sockets
from scapy_unroot.sockets import logger

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_TIMEOUT = 5


class MockLoggingHandler(logging.Handler):
    """
    Mock logging handler to check for expected logs.

    We can't use `assertLogs()` as we also want to check for empty logs

    See https://stackoverflow.com/a/1049375
    """

    def __init__(self, *args, **kwargs):
        self.reset()
        logging.Handler.__init__(self, *args, **kwargs)

    def emit(self, record):
        self.messages[record.levelname.lower()].append(record.getMessage())

    def reset(self):
        self.messages = {
            'debug': [],
            'info': [],
            'warning': [],
            'error': [],
            'critical': [],
        }


class TestScapyInteraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.run_dir = tempfile.TemporaryDirectory(
            prefix="scapy_unroot.tests."
        )

    @classmethod
    def tearDownClass(cls):
        cls.run_dir.cleanup()

    def setUp(self):
        self.log_handler = MockLoggingHandler()
        logger.setLevel("WARNING")
        logger.addHandler(self.log_handler)

        conf.verb = False
        self.comm_sockaddr = os.path.join(self.run_dir.name, "client-socket")
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.comm_sock.settimeout(TEST_TIMEOUT)
        self.comm_sock.bind(self.comm_sockaddr)

        self.spawn = pexpect.spawnu(
            "{} {}".format(
                os.path.join(SCRIPT_DIR, "interaction-server.py"),
                self.comm_sockaddr
            ),
            timeout=TEST_TIMEOUT
        )
        self.spawn.expect(
            r"Starting server for group .+ on run_dir (.+)\s"
        )
        self.server_run_dir = self.spawn.match.group(1).strip()
        # wait for server to listen
        self.spawn.expect(
            r"Starting to listen on .*laddr={}/.*".format(self.server_run_dir)
        )

        configure_sockets(server_addr=os.path.join(self.server_run_dir,
                                                   "server-socket"))

    def tearDown(self):
        self.comm_sock.close()
        os.remove(self.comm_sockaddr)
        self.spawn.terminate()
        shutil.rmtree(self.server_run_dir)

    def _expect_sending(self, scapy_socket_type, send_data):
        self.spawn.expect(
            r"Initializing {} with arguments".format(scapy_socket_type)
        )
        self.spawn.expect(
            r"Sending from {} with data='<{}.*>'"
            .format(scapy_socket_type, type(send_data).__name__)
        )
        data, remote = self.comm_sock.recvfrom(128)
        self.assertEqual(raw(send_data), data)
        return data, remote

    def test_scapy_send(self):
        send_data = Ether() / IPv6() / UDP()
        send(send_data)
        self._expect_sending("L3socket", send_data)
        self.spawn.expect(
            r"Closing L3socket with arguments"
        )

    def test_scapy_sendp(self):
        send_data = Ether() / IPv6() / UDP(dport=742) / "abc"
        sendp(send_data)
        self.spawn.expect(
            r"Closing L2socket with arguments"
        )

    def _test_sndrcv1(self, func, scapy_socket_type, send_data, exp_reply):
        self.log_handler.reset()

        def echo_server():
            _, remote = self._expect_sending(scapy_socket_type, send_data)
            self.assertEqual(len(raw(exp_reply)),
                             self.comm_sock.sendto(raw(exp_reply), remote))

        t = threading.Thread(target=echo_server)
        t.start()
        p = func(send_data, timeout=TEST_TIMEOUT)
        self.assertIsNotNone(p)
        self.assertEqual(raw(exp_reply), raw(p))
        self.spawn.expect(
            r"Receiving on {} with arguments".format(scapy_socket_type)
        )
        t.join(timeout=TEST_TIMEOUT)
        self.spawn.expect(
            r"Closing {} with arguments".format(scapy_socket_type)
        )
        self.assertEqual(0, len(self.log_handler.messages["error"]))

    def test_scapy_sr1(self):
        send_data = IPv6(src="fe80::1", dst="fe80::2") / \
            UDP(sport=31245, dport=8788) / b"abcdef"
        exp_reply = IPv6(src="fe80::2", dst="fe80::1") / \
            UDP(sport=8788, dport=31245) / b"12345"
        self._test_sndrcv1(sr1, "L3socket", send_data, exp_reply)

    def test_scapy_srp1(self):
        send_data = Ether(src="99:54:8f:91:12:f6", dst="44:35:a2:a6:d0:bd") / \
            IPv6(src="fe80::1", dst="fe80::2") / \
            ICMPv6EchoRequest()
        exp_reply = Ether(src="44:35:a2:a6:d0:bd", dst="99:54:8f:91:12:f6") / \
            IPv6(src="fe80::2", dst="fe80::1") / \
            ICMPv6EchoReply()
        self._test_sndrcv1(srp1, "L2socket", send_data, exp_reply)
