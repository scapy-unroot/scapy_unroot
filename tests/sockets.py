# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

"""
Tests for the sockets to communicate with the daemon to enable using scapy
without root.
"""

import json
import socket
import unittest
import unittest.mock

import scapy_unroot.daemon
import scapy_unroot.sockets


@unittest.mock.patch("socket.socket")
class TestSocketInit(unittest.TestCase):
    def setUp(self):
        # disable logger on default as the mocks cause
        # ScapyUnrootSocket.close() print warnings when object is destroye
        scapy_unroot.sockets.logger.disabled = True

    def tearDown(self):
        scapy_unroot.sockets.logger.disabled = False

    def _test_init(self, socket_mock, scapy_conf_type, recv_data, **args):
        socket_mock.return_value.recv = lambda x: recv_data
        sock = scapy_unroot.sockets.ScapyUnrootSocket(
            "test-server", scapy_conf_type, **args
        )
        self.assertEqual("test-server", sock.server_addr)
        self.assertEqual(scapy_conf_type, sock.scapy_conf_type)
        socket_mock.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        self.assertEqual(socket_mock.return_value, sock.ins)
        sock.ins.connect.assert_called_once_with(sock.server_addr)
        exp_req = {"op": "init", "type": scapy_conf_type}
        if len(args) > 0:
            exp_req["args"] = args
        sock.ins.send.assert_called_once_with(
            json.dumps(exp_req, separators=(",", ":")).encode()
        )
        return sock

    def test_init__empty_response(self, socket_mock):
        with self.assertRaises(json.decoder.JSONDecodeError):
            self._test_init(socket_mock, "avxoxocx", b'')

    def test_init__broken_json(self, socket_mock):
        with self.assertRaises(json.decoder.JSONDecodeError):
            self._test_init(socket_mock, "mqfgafs", b'{"uwl')

    def test_init__unexpected_response(self, socket_mock):
        with self.assertRaisesRegex(
            RuntimeError,
            r"Unexpected response from daemon 'test-server'"
        ):
            self._test_init(socket_mock, "aexbgn", b'{"uwlfgo":124}')

    def test_init__unknown_error_code(self, socket_mock):
        with self.assertRaisesRegex(
            RuntimeError,
            r"Unexpected error code None from daemon"
        ):
            error_code = b'{"error":{}}'
            self._test_init(socket_mock, "skdtngm", error_code)

    def test_init__unknown_op(self, socket_mock):
        with self.assertRaisesRegex(AttributeError, r"glarbfoo"):
            error_code = '{{"error":{{"type": {},"msg": "glarbfoo"}}}}' \
                         .format(scapy_unroot.daemon.UNKNOWN_OP)
            self._test_init(socket_mock, "ioovovi", error_code)

    def test_init__unknown_op_no_msg(self, socket_mock):
        with self.assertRaisesRegex(AttributeError, r"^$"):
            error_code = '{{"error":{{"type": {}}}}}' \
                         .format(scapy_unroot.daemon.UNKNOWN_OP)
            self._test_init(socket_mock, "ioovovi", error_code)

    def test_init__unknown_type(self, socket_mock):
        with self.assertRaisesRegex(TypeError, r"foobar"):
            error_code = '{{"error":{{"type": {},"msg": "foobar"}}}}' \
                         .format(scapy_unroot.daemon.UNKNOWN_TYPE)
            self._test_init(socket_mock, "xfogxcno", error_code)

    def test_init__unknown_type_no_msg(self, socket_mock):
        with self.assertRaisesRegex(TypeError, r"^$"):
            error_code = '{{"error":{{"type": {}}}}}' \
                         .format(scapy_unroot.daemon.UNKNOWN_TYPE)
            self._test_init(socket_mock, "8fr7swc", error_code)

    def test_init__os_error(self, socket_mock):
        with self.assertRaisesRegex(OSError, r"^\[Errno 228\] globgrod$"):
            error_code = '{{"error":{{"type": {},"errno":228,"msg": ' \
                         '"globgrod"}}}}'.format(scapy_unroot.daemon.OS)
            self._test_init(socket_mock, "xfogxcno", error_code)

    def test_init__os_error_no_msg(self, socket_mock):
        with self.assertRaisesRegex(OSError, r"^\[Errno 243\]\s*$"):
            error_code = '{{"error":{{"type": {},"errno":243}}}}' \
                         .format(scapy_unroot.daemon.OS)
            self._test_init(socket_mock, "8fr7swc", error_code)

    def test_init__os_error_no_errno(self, socket_mock):
        with self.assertRaisesRegex(OSError, r"^\[Errno None\] mathematical$"):
            error_code = '{{"error":{{"type": {},"msg":   "mathematical"}}}}' \
                         .format(scapy_unroot.daemon.OS)
            self._test_init(socket_mock, "8fr7swc", error_code)

    def test_init__os_error_no_errno_no_msg(self, socket_mock):
        with self.assertRaisesRegex(OSError, r"^\[Errno None\]\s*$"):
            error_code = '{{"error":{{"type": {}}}}}' \
                         .format(scapy_unroot.daemon.OS)
            self._test_init(socket_mock, "8fr7swc", error_code)

    def _test_init_success(self, socket_mock, scapy_conf_type, **args):
        return self._test_init(socket_mock, scapy_conf_type, b'{"success":0}',
                               **args)

    def test_init__success(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2socket")
        self.assertEqual(sock.ins, sock.outs)

    def test_init__success_listen_socket(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2listen")
        self.assertIsNone(sock.outs)

    def test_init__success_with_args(self, socket_mock):
        self._test_init_success(socket_mock, "L2socket",
                                that_argument=12345)

    def test_close__success(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2socket")
        socket_mock.return_value.recv = lambda x: '{"closed":""}'
        socket_mock.return_value.is_closed = lambda: False
        sock.close()
        sock.ins.close.assert_called_once()
        sock.outs.close.assert_called_once()

    def test_close__success_listen_socket(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2listen")
        socket_mock.return_value.recv = lambda x: '{"closed":""}'
        socket_mock.return_value.is_closed = lambda: False
        sock.close()
        sock.ins.close.assert_called_once()
        self.assertIsNone(sock.outs)

    def test_close__exception_on_close_op(self, socket_mock):
        scapy_unroot.sockets.logger.disabled = False
        sock = self._test_init_success(socket_mock, "L2socket")
        socket_mock.return_value.recv = lambda x: \
            '{{"error":{{"type": {}}}}}' \
            .format(scapy_unroot.daemon.UNINITILIZED)
        socket_mock.return_value.is_closed = lambda: False
        with self.assertLogs('scapy_unroot.sockets', level='WARNING') as cm:
            sock.close()
        self.assertIn("WARNING:scapy_unroot.sockets:Exception on sending "
                      "close to daemon ''",
                      cm.output)
        sock.ins.close.assert_called_once()
        sock.outs.close.assert_called_once()
