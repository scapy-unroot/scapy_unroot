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

import os
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

@unittest.mock.patch('scapy.all.SuperSocket.select',
                     side_effect=InterruptedError)
@unittest.mock.patch('os.chmod')
@unittest.mock.patch('os.chown')
@unittest.mock.patch('socket.socket')
@unittest.mock.patch('os.makedirs')
class TestRunDaemonDefault(unittest.TestCase):
    @unittest.mock.patch('grp.getgrnam')
    def setUp(self, *args):
        self.run_dir = "abcdef"
        self.daemon = scapy_unroot.daemon.UnrootDaemon("group",
                                                       run_dir=self.run_dir)

    def _assert_socket_correct(self, chown, chmod):
        self.assertIsNotNone(self.daemon.socket)
        self.daemon.socket.bind.assert_called_once_with(self.daemon.socketname)
        chown.assert_called_once_with(self.daemon.socketname, 0o660)
        chmod.assert_called_once_with(self.daemon.socketname, os.getuid(),
                                      self.daemon.group)
        self.daemon.socket.listen.assert_called_once()

    @unittest.mock.patch('os.path.exists', return_value=True)
    def test_run_run_dir_exists(self, path_exists, makedirs, socket, chmod,
                                chown, select):
        self.assertIsNone(self.daemon.socket)
        # triggered by select mock to interrupt infinite loop
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        path_exists.assert_called_with(self.run_dir)
        makedirs.assert_not_called()
        self._assert_socket_correct(chown, chmod)
        select.assert_called()

    @unittest.mock.patch('os.path.exists', return_value=False)
    def test_run_run_dir_not_exists(self, path_exists, makedirs, socket, chmod,
                                    chown, select):
        self.assertIsNone(self.daemon.socket)
        # triggered by select mock to interrupt infinite loop
        with self.assertRaises(InterruptedError):
            self.daemon.run()
        path_exists.assert_called_with(self.run_dir)
        makedirs.assert_called_once_with(self.run_dir)
        self._assert_socket_correct(chown, chmod)
        select.assert_called()
