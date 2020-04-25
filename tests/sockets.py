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

import base64
import json
import socket
import unittest
import unittest.mock

from scapy.all import Dot15d4, Scapy_Exception, SixLoWPAN

import scapy_unroot.daemon
import scapy_unroot.sockets


class TestSocketBase(unittest.TestCase):
    def setUp(self):
        # disable logger on default as the mocks cause
        # ScapyUnrootSocket.close() print warnings when object is destroye
        scapy_unroot.sockets.logger.setLevel("CRITICAL")

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

    def _test_init_success(self, socket_mock, scapy_conf_type, **args):
        return self._test_init(socket_mock, scapy_conf_type, b'{"success":0}',
                               **args)


@unittest.mock.patch("socket.socket")
class TestSocketInit(TestSocketBase):
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

    def test_init__success(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2socket")
        self.assertEqual(sock.ins, sock.outs)

    def test_init__success_listen_socket(self, socket_mock):
        sock = self._test_init_success(socket_mock, "L2listen")
        self.assertIsNone(sock.outs)

    def test_init__success_with_args(self, socket_mock):
        self._test_init_success(socket_mock, "L2socket",
                                that_argument=12345)


@unittest.mock.patch("socket.socket")
class TestSocketClose(TestSocketBase):
    def _init_socket(self, socket_mock, scapy_conf_type,
                     recv_return_value='{"closed":""}'):
        sock = self._test_init_success(socket_mock, scapy_conf_type)
        socket_mock.return_value.recv = lambda x: recv_return_value
        return sock

    def _test_close_success(self, socket_mock, scapy_conf_type):
        sock = self._init_socket(socket_mock, scapy_conf_type)
        sock.close()
        exp_req = {"op": "close"}
        sock.ins.send.assert_called_with(
            json.dumps(exp_req, separators=(",", ":")).encode()
        )
        sock.ins.close.assert_called_once()
        return sock

    def test_close__success(self, socket_mock):
        sock = self._test_close_success(socket_mock, "L2socket")
        sock.outs.close.assert_called_once()

    def test_close__success_listen_socket(self, socket_mock):
        sock = self._test_close_success(socket_mock, "L2listen")
        self.assertIsNone(sock.outs)

    def test_close__exception_on_close_op(self, socket_mock):
        sock = self._init_socket(
            socket_mock, "L3socket",
            '{{"error":{{"type": {}}}}}'.format(
                scapy_unroot.daemon.UNINITILIZED
            )
        )
        scapy_unroot.sockets.logger.disabled = False
        with self.assertLogs('scapy_unroot.sockets', level='WARNING') as cm:
            sock.close()
        self.assertIn("WARNING:scapy_unroot.sockets:Exception on sending "
                      "close to daemon ''",
                      cm.output)
        sock.ins.close.assert_called_once()
        sock.outs.close.assert_called_once()


class TestSocketSend(TestSocketBase):
    @unittest.mock.patch("socket.socket")
    def setUp(self, socket_mock):
        super().setUp()
        self.sock = self._test_init_success(socket_mock, "L3socket6")
        self.socket_mock = socket_mock

    def _test_send_success(self, data, exp_type=None):
        self.socket_mock.return_value.recv = lambda x: \
            '{{"success":{}}}'.format(len(data))
        self.assertEqual(len(data), self.sock.send(data))
        exp_req = {"op": "send"}
        if exp_type is not None:
            exp_req["type"] = exp_type
            data = bytes(data)
        exp_req["data"] = base64.b64encode(data).decode()
        self.socket_mock.send.called_with(json.dumps(exp_req))

    def test_send__success_raw(self):
        self._test_send_success(b"hallo")

    def test_send__success_packet(self):
        self._test_send_success(Dot15d4() / SixLoWPAN(), "Dot15d4")

    def test_send__invalid_data(self):
        data = b"Some test data"
        self.socket_mock.return_value.recv = lambda x: \
            '{{"error":{{"type": {}, "msg":"This is only a test"}}}}' \
            .format(scapy_unroot.daemon.INVALID_DATA)
        with self.assertRaisesRegex(ValueError, "^This is only a test$"):
            self.sock.send(data)
        exp_req = {"op": "send", "data": base64.b64encode(data).decode()}
        self.socket_mock.send.called_with(json.dumps(exp_req))

    def test_send__invalid_data_no_msg(self):
        data = b"Some test data"
        self.socket_mock.return_value.recv = lambda x: \
            '{{"error":{{"type": {}}}}}' \
            .format(scapy_unroot.daemon.INVALID_DATA)
        with self.assertRaisesRegex(ValueError, "^$"):
            self.sock.send(data)
        exp_req = {"op": "send", "data": base64.b64encode(data).decode()}
        self.socket_mock.send.called_with(json.dumps(exp_req))

    @unittest.mock.patch("socket.socket")
    def test_send__listen_socket(self, socket):
        sock = self._test_init_success(socket, "L2listen")
        with self.assertRaises(Scapy_Exception):
            sock.send(b"abcdefg")
