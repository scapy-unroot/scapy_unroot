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

import io
import os
import sys
import tempfile
import unittest
import unittest.mock

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

    @unittest.mock.patch('grp.getgrnam')
    def setUp(self, *args):
        self.run_dir = tempfile.TemporaryDirectory()
        self.assertTrue(os.path.exists(self.run_dir.name))
        self.daemon = scapy_unroot.daemon.UnrootDaemon(
            "group", run_dir=self.run_dir.name, daemonize=self.daemonize
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
    def test_success__first_fork_fail(self, fork, stdout, stderr, exit,
                                      select, socket, umask, setsid, chown,
                                      chmod, chdir, getpid, dup2, getgrnam):
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
    def test_success__second_fork_fail(self, fork, stdout, stderr, exit,
                                       select, socket, umask, setsid, chown,
                                       chmod, chdir, getpid, dup2, getgrnam):
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
