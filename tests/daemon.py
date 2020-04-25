# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

"""
Tests for the daemon to enable using scapy without root.
"""

import base64
import errno
import io
import json
import os
import sys
import tempfile
import socket
import time
import threading
import unittest
import unittest.mock

from scapy.all import conf, Ether, IP, raw, SimpleSocket, SuperSocket

import scapy_unroot.daemon


MOCK_FD = 7
CONNECTION_TIMEOUT = 0.005


@unittest.mock.patch('grp.getgrnam')
class TestInitDaemon(unittest.TestCase):
    def test_success(self, getgrnam):
        d = scapy_unroot.daemon.UnrootDaemon("group")
        getgrnam.assert_called_with("group")
        self.assertEqual(getgrnam("group").gr_gid, d.group)
        self.assertFalse(d.daemonize)
        self.assertEqual(scapy_unroot.daemon.RUN_DIR_DEFAULT, d.run_dir)
        self.assertEqual([], d.iface_blacklist)
        self.assertIsNone(d.pidfile)
        self.assertEqual(
            os.path.join(scapy_unroot.daemon.RUN_DIR_DEFAULT, "server-socket"),
            d.socketname
        )
        self.assertIsNone(d.pidfile)
        self.assertEqual({}, d.clients)

    def test_group_none(self, getgrnam):
        def raise_type_error(value):
            if value is None:
                raise TypeError()
            return value
        getgrnam.side_effect = raise_type_error
        with self.assertRaises(TypeError):
            scapy_unroot.daemon.UnrootDaemon(None)
        getgrnam.assert_called_with(None)

    def test_run_dir_none(self, getgrnam):
        with self.assertRaises(TypeError):
            scapy_unroot.daemon.UnrootDaemon("group", run_dir=None)

    def test_interface_blacklist_none(self, getgrnam):
        d = scapy_unroot.daemon.UnrootDaemon("group", interface_blacklist=None)
        self.assertEqual([], d.iface_blacklist)


class TestRunDaemonBase(unittest.TestCase):
    daemonize = False
    blacklist = None

    @unittest.mock.patch('grp.getgrnam')
    def setUp(self, *args):
        self.run_dir = tempfile.TemporaryDirectory(
            prefix="scapy_unroot.tests."
        )
        self.assertTrue(os.path.exists(self.run_dir.name))
        self.daemon = scapy_unroot.daemon.UnrootDaemon(
            "group", run_dir=self.run_dir.name, daemonize=self.daemonize,
            interface_blacklist=self.blacklist
        )

    def tearDown(self):
        self.run_dir.cleanup()

    def _assert_socket_correct(self, chown, chmod):
        self.assertIsNotNone(self.daemon.socket)
        chown.assert_called_once_with(self.daemon.socketname, 0o660)
        chmod.assert_called_once_with(self.daemon.socketname, os.getuid(),
                                      self.daemon.group)


@unittest.mock.patch('scapy.all.SuperSocket.select',
                     side_effect=InterruptedError)
@unittest.mock.patch('os.chmod')
@unittest.mock.patch('os.chown')
@unittest.mock.patch('socket.socket')
@unittest.mock.patch('os.makedirs')
class TestRunDaemonSetup(TestRunDaemonBase):
    def _assert_socket_correct(self, chown, chmod):
        super()._assert_socket_correct(chown, chmod)
        self.daemon.socket.bind.assert_called_once_with(self.daemon.socketname)
        self.daemon.socket.listen.assert_called_once()

    @unittest.mock.patch('os.path.exists', return_value=True)
    def test_run__run_dir_exists(self, path_exists, makedirs, socket, chmod,
                                 chown, select):
        self.assertIsNone(self.daemon.socket)
        # triggered by select mock to interrupt infinite loop
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        path_exists.assert_called_with(self.run_dir.name)
        makedirs.assert_not_called()
        self._assert_socket_correct(chown, chmod)
        select.assert_called_with(self.daemon.read_sockets)

    @unittest.mock.patch('os.path.exists', return_value=False)
    def test_run__run_dir_not_exists(self, path_exists, makedirs, socket,
                                     chmod, chown, select):
        self.assertIsNone(self.daemon.socket)
        # triggered by select mock to interrupt infinite loop
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        path_exists.assert_called_with(self.run_dir.name)
        makedirs.assert_called_once_with(self.run_dir.name)
        self._assert_socket_correct(chown, chmod)
        # run loop was started
        select.assert_called_with(self.daemon.read_sockets)


@unittest.mock.patch('scapy.all.SuperSocket.select',
                     side_effect=InterruptedError)
@unittest.mock.patch('os.chmod')
@unittest.mock.patch('os.chown')
@unittest.mock.patch('os.unlink')
@unittest.mock.patch('socket.socket')
@unittest.mock.patch('os.path.exists', return_value=True)
@unittest.mock.patch('grp.getgrnam')
class TestRunFunction(unittest.TestCase):
    @unittest.mock.patch.object(sys, 'argv', ["run", "group"])
    def test_success(self, getgrnam, path_exists, socket, unlink, chown, chmod,
                     select):
        with self.assertRaises(InterruptedError):
            scapy_unroot.daemon.run()
        # constructor was called
        getgrnam.assert_called_with("group")
        # run loop was started
        select.assert_called()

    @unittest.mock.patch.object(sys, 'argv', ["run"])
    @unittest.mock.patch('sys.stderr', new_callable=io.StringIO)
    @unittest.mock.patch('sys.exit', side_effect=InterruptedError)
    def test_group_none(self, exit, stderr, getgrnam, path_exists, socket,
                        unlink, chown, chmod, select):
        with self.assertRaises(InterruptedError):
            scapy_unroot.daemon.run()
        exit.assert_called()
        # exit was not called with argument 0
        self.assertNotEqual(unittest.mock.call(0), exit.call_args)
        # constructor was not called
        getgrnam.assert_not_called()
        # run loop was not started
        select.assert_not_called()


class FileNoStringIO(io.StringIO):
    def fileno(self):
        return MOCK_FD


@unittest.mock.patch('grp.getgrnam')
@unittest.mock.patch('os.dup2')
@unittest.mock.patch('os.getpid', return_value=16195)
@unittest.mock.patch('os.chdir')
@unittest.mock.patch('os.chmod')
@unittest.mock.patch('os.chown')
@unittest.mock.patch('os.setsid')
@unittest.mock.patch('os.umask')
@unittest.mock.patch('socket.socket')
@unittest.mock.patch('scapy.all.SuperSocket.select',
                     side_effect=InterruptedError)
@unittest.mock.patch('sys.exit', side_effect=InterruptedError)
@unittest.mock.patch('sys.stderr', new_callable=FileNoStringIO)
@unittest.mock.patch('sys.stdout', new_callable=FileNoStringIO)
class TestRunDaemonized(TestRunDaemonBase):
    daemonize = True

    @unittest.mock.patch('os.fork', return_value=0)
    def test_success__both_forked(self, fork, stdout, stderr, exit, select,
                                  socket, umask, setsid, chown, chmod, chdir,
                                  getpid, dup2, getgrnam):
        self.assertTrue(self.daemon.daemonize)
        self.assertIsNone(self.daemon.pidfile)
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        fork.assert_has_calls([unittest.mock.call(), unittest.mock.call()])
        exit.assert_not_called()
        umask.assert_called_once_with(0)
        setsid.assert_called_once()
        chdir.assert_called_once_with("/")
        getpid.assert_called_once()
        # pidfile is now set
        self.assertEqual(os.path.join(self.run_dir.name, "pidfile"),
                         self.daemon.pidfile)
        dup2.assert_called()
        # run loop was started
        select.assert_called_with(self.daemon.read_sockets)
        self.assertTrue(os.path.exists(self.daemon.pidfile))
        with open(self.daemon.pidfile) as f:
            self.assertEqual(getpid.return_value, int(f.read()))

    def test_pidfile_removal(self, *args, **kwargs):
        self.test_success__both_forked()
        pidfile = self.daemon.pidfile
        # check if pidfile is removed correctly
        self.daemon.__del__()
        self.daemon = False
        self.assertTrue(os.path.exists(self.run_dir.name))
        self.assertFalse(os.path.exists(pidfile))

    @unittest.mock.patch('os.fork', return_value=17273)
    def test_success__first_parent(self, fork, stdout, stderr, exit, select,
                                   socket, umask, setsid, chown, chmod,
                                   chdir, getpid, dup2, getgrnam):
        self.assertTrue(self.daemon.daemonize)
        self.assertIsNone(self.daemon.pidfile)
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        fork.assert_called_once()
        exit.assert_any_call(0)
        umask.assert_not_called()
        setsid.assert_not_called()
        chdir.assert_not_called()
        # getpid gets called somewhere
        # but pidfile stays unset
        self.assertIsNone(self.daemon.pidfile)
        dup2.assert_not_called()
        # run loop was not started
        select.assert_not_called()

    @unittest.mock.patch('os.fork', side_effect=[0, 33211])
    def test_success__second_parent(self, fork, stdout, stderr, exit, select,
                                    socket, umask, setsid, chown, chmod, chdir,
                                    getpid, dup2, getgrnam):
        self.assertTrue(self.daemon.daemonize)
        self.assertIsNone(self.daemon.pidfile)
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        fork.assert_has_calls([unittest.mock.call(), unittest.mock.call()])
        exit.assert_any_call(0)
        umask.assert_called_once_with(0)
        setsid.assert_called_once()
        chdir.assert_called_once_with("/")
        # getpid gets called somewhere
        # but pidfile stays unset
        self.assertIsNone(self.daemon.pidfile)
        dup2.assert_not_called()
        # run loop was not started
        select.assert_not_called()

    @unittest.mock.patch('os.fork',
                         side_effect=[OSError(249, "test"), 0])
    def test_first_fork_fail(self, fork, stdout, stderr, exit, select, socket,
                             umask, setsid, chown, chmod, chdir, getpid, dup2,
                             getgrnam):
        self.assertTrue(self.daemon.daemonize)
        self.assertIsNone(self.daemon.pidfile)
        with self.assertRaises(InterruptedError):
            with self.assertLogs('scapy_unroot.daemon', level='ERROR') as cm:

                self.daemon.run()
        # check if log error was printed correctly
        self.assertIn("ERROR:scapy_unroot.daemon.UnrootDaemon:"
                      "fork #1 failed: 249 (test)", cm.output)
        fork.assert_called_once()
        exit.assert_called()
        # sys.exit was never called with 0
        self.assertNotIn(unittest.mock.call(0), exit.call_args)
        umask.assert_not_called()
        setsid.assert_not_called()
        chdir.assert_not_called()
        # getpid gets called somewhere
        # but pidfile stays unset
        self.assertIsNone(self.daemon.pidfile)
        dup2.assert_not_called()
        # run loop was not started
        select.assert_not_called()

    @unittest.mock.patch('os.fork',
                         side_effect=[0, OSError(72, "testing")])
    def test_second_fork_fail(self, fork, stdout, stderr, exit, select, socket,
                              umask, setsid, chown, chmod, chdir, getpid, dup2,
                              getgrnam):
        self.assertTrue(self.daemon.daemonize)
        self.assertIsNone(self.daemon.pidfile)
        with self.assertRaises(InterruptedError):
            with self.assertLogs('scapy_unroot.daemon', level='ERROR') as cm:

                self.daemon.run()
        # check if log error was printed correctly
        self.assertIn("ERROR:scapy_unroot.daemon.UnrootDaemon:"
                      "fork #2 failed: 72 (testing)", cm.output)
        fork.assert_has_calls([unittest.mock.call(), unittest.mock.call()])
        exit.assert_called()
        # sys.exit was never called with 0
        self.assertNotIn(unittest.mock.call(0), exit.call_args)
        umask.assert_called_once_with(0)
        setsid.assert_called_once()
        chdir.assert_called_once_with("/")
        # getpid gets called somewhere
        # but pidfile stays unset
        self.assertIsNone(self.daemon.pidfile)
        dup2.assert_not_called()
        # run loop was not started
        select.assert_not_called()


@unittest.mock.patch('os.chmod')
@unittest.mock.patch('os.chown')
class TestRunDaemonUnexpectedSocket(TestRunDaemonBase):
    @unittest.mock.patch('scapy.all.SuperSocket.select')
    def test_run__unexpected_socket(self, select, chown, chmod):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            select.side_effect = [([sock], None), InterruptedError]
            with self.assertRaises(InterruptedError):
                with self.assertLogs('scapy_unroot.daemon', level='ERROR') \
                     as cm:
                    self.daemon.run()
            # check if log error was printed correctly
            self.assertTrue(any(
                "Unexpected socket selected {}".format(sock) in line
                for line in cm.output
            ), msg="No warning about unknown socket {}".format(sock))
        self.assertDictEqual({}, self.daemon.clients)


class TestRunDaemonThreaded(TestRunDaemonBase):
    class Stop(BaseException):
        pass

    def _select_wrapper(self):
        def _select(read_sockets, *args, **kwargs):
            self.select_called.set()
            if self.stop:
                raise self.Stop()
            # make sure Mocks are not accidentally end up in a system function
            _read_sockets = read_sockets
            read_sockets = _read_sockets.copy()
            for sock in list(read_sockets.keys()):
                if isinstance(sock, unittest.mock.Mock):
                    read_sockets.pop(sock)
            res = self._orig_select(read_sockets, *args, **kwargs)
            self.last_res = res
            return res
        return _select

    def _wait_for_next_select(self, timeout=None):
        res = self.select_called.wait(timeout)
        self.select_called.clear()
        return res

    def wait_for_next_select(self, timeout=None):
        start = time.time()
        res = self._wait_for_next_select(timeout)
        while res and not self.last_res:
            timeout -= (time.time() - start)
            res = self._wait_for_next_select(timeout)
        return res

    def stop_daemon(self):
        self.stop = True
        # trigger select to exit
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
        self.assertTrue(self.stopped.wait(1))
        self.stopped.clear()

    @unittest.mock.patch('os.chmod')
    @unittest.mock.patch('os.chown')
    def setUp(self, *args):
        super().setUp(*args)

        def _run():
            try:
                self._orig_select = SuperSocket.select
                SuperSocket.select = self._select_wrapper()
                self.daemon.run()
            except self.Stop:
                self.stopped.set()
                return

        self.stop = False
        self.last_res = None, None
        self.select_called = threading.Event()
        self.stopped = threading.Event()
        self.daemon_thread = threading.Thread(target=_run)
        self.daemon_thread.start()
        self.assertTrue(self.wait_for_next_select(1))

    def tearDown(self):
        self.stop_daemon()
        SuperSocket.select = self._orig_select
        self.daemon.__del__()
        super().tearDown()


class TestSocketInteraction(TestRunDaemonThreaded):
    blacklist = ["blacklisted_iface"]

    def setUp(self):
        super().setUp()
        self._orig_scapy_conf = {}
        for type in ["L2socket", "L2listen", "L3socket", "L3socket6"]:
            self._orig_scapy_conf[type] = getattr(conf, type)

    def tearDown(self):
        super().tearDown()
        for type in ["L2socket", "L2listen", "L3socket", "L3socket6"]:
            setattr(conf, type, self._orig_scapy_conf[type])

    def test_accept(self):
        self.assertDictEqual({}, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            self.assertEqual(1, len(self.daemon.clients))
            self.assertEqual(2, len(self.daemon.read_sockets))

    def test_broken_json(self):
        self.assertDictEqual({}, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(b"{,")
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(CONNECTION_TIMEOUT)
            # broken JSON is silently ignored
            with self.assertRaises(socket.timeout):
                sock.recv(scapy_unroot.daemon.DAEMON_MTU)
            self.assertEqual(1, len(self.daemon.clients))
            self.assertEqual(2, len(self.daemon.read_sockets))

    def test_unknown_op(self):
        self.assertDictEqual({}, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "thisdoesnotexist",
                "type": "thisdoesnotexist",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNKNOWN_OP,
                             res["error"]["type"])
            self.assertEqual("Operation 'thisdoesnotexist' unknown",
                             res["error"]["msg"])
            self.assertEqual(1, len(self.daemon.clients))
            self.assertEqual(2, len(self.daemon.read_sockets))

    def test_init_unknown_type(self):
        self.assertDictEqual({}, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "thisdoesnotexist",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNKNOWN_TYPE,
                             res["error"]["type"])
            self.assertEqual("Unknown socket type 'thisdoesnotexist'",
                             res["error"]["msg"])
            self.assertEqual(1, len(self.daemon.clients))
            self.assertEqual(2, len(self.daemon.read_sockets))

    def _test_init_scapy_socket(self, sock, scapy_socket_type, init_args=None):
        self.assertDictEqual({}, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        sock.connect(self.daemon.socketname)
        self.assertTrue(self.wait_for_next_select(1))
        self.assertEqual(1, len(self.daemon.clients))
        self.assertEqual(2, len(self.daemon.read_sockets))
        req = {"op": "init", "type": scapy_socket_type}
        if init_args is not None:
            req["args"] = init_args
        sock.send(json.dumps(req).encode())

    def _expect_init_oserror(self, sock):
        self.assertEqual(1, len(self.daemon.clients))
        self.assertEqual(2, len(self.daemon.read_sockets))
        self.assertTrue(self.wait_for_next_select(1))
        sock.settimeout(CONNECTION_TIMEOUT)
        res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
        self.assertIn("error", res)
        self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
        self.assertEqual(1, len(self.daemon.clients))
        self.assertEqual(2, len(self.daemon.read_sockets))
        return res

    def _test_init_success_w_sock(self, scapy_socket_type, sock,
                                  init_args=None):
        with unittest.mock.patch(
            "scapy.config.conf.{}".format(scapy_socket_type)
        ) as scapy_socket_mock:
            self._test_init_scapy_socket(sock, scapy_socket_type,
                                         init_args)
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("success", res)
            if init_args is None:
                scapy_socket_mock.assert_called_once_with()
            else:
                scapy_socket_mock.assert_called_once_with(**init_args)
            self.assertTrue(
                any("supersocket" in v and
                    v["supersocket"] is scapy_socket_mock.return_value
                    for v in self.daemon.clients.values()),
                msg="supersocket missing"
            )
            self.assertIn(scapy_socket_mock.return_value,
                          self.daemon.read_sockets)

    def _test_init_success(self, scapy_socket_type, init_args=None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_success_w_sock(scapy_socket_type, sock, init_args)

    def _test_init_wrong_args(self, scapy_socket_type):
        setattr(conf, scapy_socket_type, SimpleSocket)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            init_args = {"why_would_you_even_pfgncd": 37165}
            self._test_init_scapy_socket(sock, scapy_socket_type,
                                         init_args)
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNKNOWN_TYPE,
                             res["error"]["type"])
            self.assertIn("__init__() got an unexpected keyword argument ",
                          res["error"]["msg"])
            self.assertFalse(any("supersocket" in v
                             for v in self.daemon.clients.values()),
                             msg="A supersocket was unexpectedly added")
            self.assertEqual(2, len(self.daemon.read_sockets))

    def _test_init_oserror(self, scapy_socket_type, init_args=None):
        with unittest.mock.patch(
            "scapy.config.conf.{}".format(scapy_socket_type),
            side_effect=OSError(133, "That error")
        ) as scapy_socket_mock:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                self._test_init_scapy_socket(sock, scapy_socket_type,
                                             init_args)
                res = self._expect_init_oserror(sock)
                self.assertEqual(133, res["error"]["errno"])
                self.assertEqual("That error", res["error"]["msg"])
                if init_args is None:
                    scapy_socket_mock.assert_called_once_with()
                else:
                    scapy_socket_mock.assert_called_once_with(**init_args)
                self.assertFalse(any("supersocket" in v
                                 for v in self.daemon.clients.values()),
                                 msg="A supersocket was unexpectedly added")

    def _test_init_blacklisted_iface(self, scapy_socket_type):
        with unittest.mock.patch(
            "scapy.config.conf.{}".format(scapy_socket_type),
            side_effect=OSError(133, "That error")
        ) as scapy_socket_mock:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                self._test_init_scapy_socket(sock, scapy_socket_type,
                                             {"iface": self.blacklist[0]})
                res = self._expect_init_oserror(sock)
                self.assertEqual(errno.EPERM, res["error"]["errno"])
                self.assertEqual(os.strerror(errno.EPERM), res["error"]["msg"])
                scapy_socket_mock.assert_not_called()
                self.assertFalse(any("supersocket" in v
                                 for v in self.daemon.clients.values()),
                                 msg="A supersocket was unexpectedly added")

    def test_init_l2socket__oserror(self):
        self._test_init_oserror("L2socket", {"blafoo": "test", "this": "that"})

    def test_init_l2socket__wrong_args(self):
        self._test_init_wrong_args("L2socket")

    def test_init_l2socket__no_args(self):
        self._test_init_success("L2socket")

    def test_init_l2socket__blacklisted_iface(self):
        self._test_init_blacklisted_iface("L2socket")

    def test_init_l2socket__other_arg(self):
        self._test_init_success("L2socket",
                                {"blafoo": "test", "this": "that"})

    def test_init_l2listen__oserror(self):
        self._test_init_oserror("L2listen", {"blafoo": "test", "this": "that"})

    def test_init_l2listen__wrong_args(self):
        self._test_init_wrong_args("L2listen")

    def test_init_l2listen__no_args(self):
        self._test_init_success("L2listen")

    def test_init_l2listen__blacklisted_iface(self):
        self._test_init_blacklisted_iface("L2listen")

    def test_init_l2listen__other_arg(self):
        self._test_init_success("L2listen",
                                {"blafoo": "test", "this": "that"})

    def test_init_l3socket__oserror(self):
        self._test_init_oserror("L3socket", {"blafoo": "test", "this": "that"})

    def test_init_l3socket__wrong_args(self):
        self._test_init_wrong_args("L3socket")

    def test_init_l3socket__no_args(self):
        self._test_init_success("L3socket")

    def test_init_l3socket__blacklisted_iface(self):
        self._test_init_blacklisted_iface("L3socket")

    def test_init_l3socket__other_arg(self):
        self._test_init_success("L3socket",
                                {"blafoo": "test", "this": "that"})

    def test_init_l3socket6__oserror(self):
        self._test_init_oserror("L3socket6",
                                {"blafoo": "test", "this": "that"})

    def test_init_l3socket6__wrong_args(self):
        self._test_init_wrong_args("L3socket6")

    def test_init_l3socket6__no_args(self):
        self._test_init_success("L3socket6")

    def test_init_l3socket6__blacklisted_iface(self):
        self._test_init_blacklisted_iface("L3socket6")

    def test_init_l3socket6__other_arg(self):
        self._test_init_success("L3socket6",
                                {"blafoo": "test", "this": "that"})

    def test_close(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_success_w_sock("L2listen", sock)
            sock.send(json.dumps({"op": "close"}).encode())
            self.assertTrue(self.wait_for_next_select(1))
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("closed", res)
            self.assertDictEqual({}, self.daemon.clients)

    def test_broken_close(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_success_w_sock("L2socket", sock)
            supersocket = next(iter(self.daemon.clients.values()))[
                "supersocket"
            ]
            attrs = {'close.side_effect': Exception("Testing")}
            supersocket.configure_mock(**attrs)
            with self.assertLogs('scapy_unroot.daemon', level='WARNING') as cm:
                sock.send(json.dumps({"op": "close"}).encode())
                self.assertTrue(self.wait_for_next_select(1))
                res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("closed", res)
            self.assertDictEqual({}, self.daemon.clients)
            # check if log error was printed correctly
            self.assertTrue(any(
                "Error on closing {}".format(supersocket) in line
                for line in cm.output
            ), msg="No warning about unknown socket {}".format(sock))

    def test_send__uninitialized(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "send",
                "data": base64.b64encode(b"test").decode(),
            }).encode())
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNINITILIZED,
                             res["error"]["type"])
            self.assertRegex(res["error"]["msg"],
                             r"Socket for '.*' is uninitialized")

    def test_send__unknown_type(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_success_w_sock("L3socket", sock)
            sock.send(json.dumps({
                "op": "send",
                "type": "uedfgnlxtoxf",
                "data": base64.b64encode(b"test").decode(),
            }).encode())
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNKNOWN_TYPE,
                             res["error"]["type"])
            self.assertEqual("Unknown packet type uedfgnlxtoxf",
                             res["error"]["msg"])

    def test_send__non_base64_data(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_success_w_sock("L3socket", sock)
            sock.send(json.dumps({
                "op": "send",
                "data": "*#%/\\\0",
            }).encode())
            sock.settimeout(CONNECTION_TIMEOUT)
            res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.INVALID_DATA,
                             res["error"]["type"])
            self.assertEqual("data '*#%/\\\0' is not base64 encoded",
                             res["error"]["msg"])

    def _test_send_correct(self, sock, req, mock_attrs=None):
        self._test_init_success_w_sock("L3socket6", sock)
        supersocket = next(iter(self.daemon.clients.values()))[
            "supersocket"
        ]
        if mock_attrs is not None:
            supersocket.configure_mock(**mock_attrs)
        req["op"] = "send"
        sock.send(json.dumps(req).encode())
        sock.settimeout(CONNECTION_TIMEOUT)
        res = json.loads(sock.recv(scapy_unroot.daemon.DAEMON_MTU))
        return supersocket, res

    def _test_send_success(self, packet_type=None):
        test_data = b"%\x8a:\xde\x14\rc\x97\x0fcI\xf08\xde\xf7\xa4\x98m\x04@"
        req = {"data": base64.b64encode(test_data).decode()}
        if packet_type is None:
            packet_type = raw
        else:
            req["type"] = packet_type.__name__
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:

            supersocket, res = self._test_send_correct(
                sock, req, {'send.return_value': len(test_data)}
            )
            self.assertIn("success", res)
            supersocket.send.called_with(packet_type(test_data))

    def test_send__oserror(self):
        test_data = b"%\x8a:\xde\x14\rc\x97\x0fcI\xf08\xde\xf7\xa4\x98m\x04@"
        req = {"data": base64.b64encode(test_data).decode()}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            supersocket, res = self._test_send_correct(
                sock, req, {'send.side_effect': OSError(180, "Arghs!")}
            )
            supersocket.send.called_with(raw(test_data))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(180, res["error"]["errno"])
            self.assertEqual("Arghs!", res["error"]["msg"])

    def test_send__success_raw(self):
        self._test_send_success()

    def test_send__success_ether(self):
        self._test_send_success(Ether)

    @unittest.mock.patch("scapy.config.conf.L2socket")
    def test_connection_reset_client(self, L2socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            self._test_init_scapy_socket(sock, "L2socket")
            sock.close()
            self.assertTrue(self.wait_for_next_select(1))
            L2socket.assert_called_once_with()
            self.assertEqual({}, self.daemon.clients)


class TestRunDaemonReceive(TestRunDaemonBase):
    def setUp(self, *args):
        super().setUp(*args)
        self.sock = unittest.mock.MagicMock()

    def tearDown(self, *args):
        super().tearDown(*args)
        self.sock.reset()

    @unittest.mock.patch('os.chmod')
    @unittest.mock.patch('os.chown')
    @unittest.mock.patch('scapy.all.SuperSocket.select')
    def _run_daemon(self, client, select, *args):
        select.side_effect = [([self.sock], None), InterruptedError]
        self.daemon.clients[client] = {"supersocket": self.sock}
        with self.assertRaises(InterruptedError):
            self.daemon.run()

    def test_receive__success(self):
        data = b"\x9c\x1f]8\x19\xc2P\x99>\xc3\xa0\xb9yh\x8a$\xbe\x8d[\xe7c" \
               b"\x00\xd3\xdbM\x0c\xc2\xb4\xd3\x1d"
        ts = 5975408383.001369
        client = unittest.mock.MagicMock()
        attrs = {'recv_raw.return_value': (IP, data, ts)}
        self.sock.configure_mock(**attrs)
        with self.assertLogs('scapy_unroot.daemon', level='INFO') as cm:
            self._run_daemon(client)
        self.assertTrue(any(
            "Sending IP(" in line for line in cm.output
        ))
        self.assertTrue(any(
            "Unexpected socket selected" not in line for line in cm.output
        ))
        client.send.assert_called_once_with(
            '{{"recv":{{"type":"IP","data":"{}","ts":{}}}}}'
            .format(base64.b64encode(data).decode(), ts)
        )

    def test_receive__connection_error1(self):
        client = unittest.mock.MagicMock()
        attrs = {'recv_raw.side_effect': ConnectionError}
        self.sock.configure_mock(**attrs)
        self._run_daemon(client)
        client.send.assert_not_called()
        self.assertNotIn(client, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        self.assertIn(self.daemon.socket, self.daemon.read_sockets)

    def test_receive__connection_error2(self):
        data = b'\xfd\xbcm\t\xf6'
        ts = 434950436.991872
        attrs = {
            'send.side_effect': ConnectionError,
        }
        client = unittest.mock.MagicMock(**attrs)
        attrs = {
            'recv_raw.return_value': (raw, data, ts),
        }
        self.sock.configure_mock(**attrs)
        self._run_daemon(client)
        client.send.assert_called_once_with(
            '{{"recv":{{"type":"raw","data":"{}","ts":{}}}}}'
            .format(base64.b64encode(data).decode(), ts)
        )
        self.assertNotIn(client, self.daemon.clients)
        self.assertEqual(1, len(self.daemon.read_sockets))
        self.assertIn(self.daemon.socket, self.daemon.read_sockets)
