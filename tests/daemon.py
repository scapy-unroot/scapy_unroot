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

from scapy.all import MTU, SuperSocket

import scapy_unroot.daemon


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
        select.assert_called()

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
        select.assert_called()


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
        return 1


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
        select.assert_called()
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
        def _select(*args, **kwargs):
            self.select_called.set()
            if self.stop:
                raise self.Stop()
            res = self._orig_select(*args, **kwargs)
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

    def test_accept(self):
        self.assertEqual(0, len(self.daemon.clients))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            self.assertEqual(1, len(self.daemon.clients))

    def test_broken_json(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(b"{,")
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            # broken JSON is silently ignored
            with self.assertRaises(socket.timeout):
                sock.recv(MTU)

    def test_init_unknown_type(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "thisdoesnotexist",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.UNKNOWN_TYPE,
                             res["error"]["type"])
            self.assertLess(0, len(res["error"]["msg"]))

    @unittest.mock.patch("scapy.config.conf.L2socket",
                         side_effect=OSError(133, "That error"))
    def test_init_l2socket__oserror(self, L2socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L2socket",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(133, res["error"]["errno"])
            self.assertEqual("That error", res["error"]["msg"])
            L2socket.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L2socket")
    def test_init_l2socket__no_args(self, L2socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({"op": "init",
                                  "type": "L2socket"}).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("success", res)
            L2socket.assert_called_once_with()

    @unittest.mock.patch("scapy.config.conf.L2socket")
    def test_init_l2socket__blacklisted_iface(self, L2socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L2socket",
                "args": {"iface": self.blacklist[0]},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(errno.EPERM, res["error"]["errno"])
            self.assertEqual(os.strerror(errno.EPERM), res["error"]["msg"])
            L2socket.assert_not_called()

    @unittest.mock.patch("scapy.config.conf.L2socket")
    def test_init_l2socket__other_arg(self, L2socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L2socket",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("success", res)
            L2socket.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L2listen",
                         side_effect=OSError(133, "That error"))
    def test_init_l2listen__oserror(self, L2listen):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L2listen",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(133, res["error"]["errno"])
            self.assertEqual("That error", res["error"]["msg"])
            L2listen.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L2listen")
    def test_init_l2listen__other_arg(self, L2listen):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L2listen",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("success", res)
            L2listen.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L3socket",
                         side_effect=OSError(133, "That error"))
    def test_init_l3socket__oserror(self, L3socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L3socket",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(133, res["error"]["errno"])
            self.assertEqual("That error", res["error"]["msg"])
            L3socket.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L3socket")
    def test_init_l3socket__other_arg(self, L3socket):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L3socket",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("success", res)
            L3socket.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L3socket6",
                         side_effect=OSError(133, "That error"))
    def test_init_l3socket6__oserror(self, L3socket6):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L3socket6",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("error", res)
            self.assertEqual(scapy_unroot.daemon.OS, res["error"]["type"])
            self.assertEqual(133, res["error"]["errno"])
            self.assertEqual("That error", res["error"]["msg"])
            L3socket6.assert_called_once_with(blafoo="test", this="that")

    @unittest.mock.patch("scapy.config.conf.L3socket6")
    def test_init_l3socket6__other_arg(self, L3socket6):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.daemon.socketname)
            self.assertTrue(self.wait_for_next_select(1))
            sock.send(json.dumps({
                "op": "init",
                "type": "L3socket6",
                "args": {"blafoo": "test", "this": "that"},
            }).encode())
            self.assertTrue(self.wait_for_next_select(1))
            sock.settimeout(0.3)
            res = json.loads(sock.recv(MTU))
            self.assertIn("success", res)
            L3socket6.assert_called_once_with(blafoo="test", this="that")
