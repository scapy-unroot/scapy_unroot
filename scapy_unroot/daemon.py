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
Daemon to enable using scapy without root permissions.
"""

import argparse
import atexit
import binascii
import base64
import errno
import grp
import json
import logging
import os
import socket
import sys

from scapy.all import conf, MTU, SuperSocket
from scapy.layers import all as layers

RUN_DIR_DEFAULT = "/var/run/scapy-unroot"


UNKNOWN_OP = 1
UNKNOWN_TYPE = 2
UNINITILIZED = 3
INVALID_DATA = 4
OS = 5

DAEMON_MTU = (4 * MTU) + len('{"op":"write","type":"","data":""}') + 100


def _os_error_resp(error):
    if isinstance(error, OSError):
        return {"error": {
            "type": OS,
            "msg": error.strerror,
            "errno": error.errno,
        }}
    else:
        return {"error": {
            "type": OS,
            "msg": os.strerror(error),
            "errno": error,
        }}


def _error_resp(type, msg):
    return {"error": locals()}


def _exc_to_error_resp(type, exc):
    return _error_resp(type, str(exc))


def _success_resp(res=0):
    return {"success": res}


def _closed_resp(info):
    return {"closed": info}


def _is_closed_resp(resp):
    return "closed" in resp


class UnrootDaemon:
    def __init__(self, group, daemonize=False, run_dir=RUN_DIR_DEFAULT,
                 interface_blacklist=None, logger=None):
        if logger is None:
            module = self.__class__.__module__
            name = self.__class__.__name__
            if module is not None:
                name = "{}.{}".format(module, name)
            self.logger = logging.getLogger(name)
        self.group = grp.getgrnam(group).gr_gid
        self.daemonize = daemonize
        self.run_dir = run_dir
        self._iface_blacklist = interface_blacklist or []
        self.pidfile = None
        self.socketname = os.path.join(run_dir, "server-socket")
        self.socket = None
        self.clients = dict()
        self.read_sockets = dict()

    def _guarded_fork(self, num):
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as exc:
            self.logger.error("fork #{} failed: {exc.errno} ({exc.strerror})"
                              .format(num, exc=exc))
            sys.exit(1)

    def _create_pidfile(self):
        self.pidfile = os.path.join(self.run_dir, "pidfile")

        atexit.register(self._delete_pidfile)
        pid = os.getpid()
        # write pidfile
        with open(self.pidfile, "w+") as f:
            print("{}".format(pid), file=f)

    def _delete_pidfile(self):
        if hasattr(self, "pidfile") and self.pidfile and \
           os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def _fork_as_daemon(self):
        """
        Does the UNIX double-fork magic to the calling process, see Stevens'
        "Advanced Programming in the UNIX Environment" for details
        (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        self._guarded_fork(1)
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # do second fork
        self._guarded_fork(2)
        output_file = os.path.join(self.run_dir, "output.log")
        output = open(output_file, 'a+')
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(output.fileno(), sys.stdout.fileno())
        os.dup2(output.fileno(), sys.stderr.fileno())
        self._create_pidfile()

    def __del__(self):
        self._delete_pidfile()
        if hasattr(self, "clients"):
            for client in self.clients:
                self.clients[client].close_supersocket()
                client.close()
        if hasattr(self, "socket") and self.socket:
            self.socket.close()
        if hasattr(self, "socketname") and self.socketname and \
           os.path.exists(self.socketname):
            os.unlink(self.socketname)

    def _eval_req(self, req, client):
        op = req.pop("op")
        if op == "init":
            return client.init_supersocket(**req)
        elif op == "send":
            return client.send_via_supersocket(**req)
        elif op == "close":
            return client.close_supersocket()
        else:
            return _error_resp(
                UNKNOWN_OP, "Operation '{}' unknown".format(op)
            )

    @property
    def iface_blacklist(self):
        return self._iface_blacklist

    def run(self):
        if not os.path.exists(self.run_dir):
            os.makedirs(self.run_dir)
        if self.daemonize:
            self._fork_as_daemon()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(self.socketname)
        os.chown(self.socketname, os.getuid(), self.group)
        os.chmod(self.socketname, 0o660)
        self.socket.listen(1024)
        self.read_sockets[self.socket] = "server_socket"
        while True:
            sockets, _ = SuperSocket.select(
                set(self.read_sockets) | set(self.clients)
            )
            for sock in sockets:
                if self.socket == sock:
                    s, address = sock.accept()
                    self.clients[s] = UnrootDaemonClient(self, s, address)
                elif sock in self.clients:
                    client = self.clients.get(sock)
                    assert client.socket == sock
                    try:
                        b = sock.recv(DAEMON_MTU)
                        if len(b) == 0:
                            # don't bother trying to parse this
                            continue
                        try:
                            req = json.loads(b)
                        except json.decoder.JSONDecodeError:
                            # silently ignore JSON decode errors as empty
                            # messages are exchanged between UNIX domain stream
                            # sockets all the time
                            continue
                        res = self._eval_req(req, client)
                        sock.send(
                            json.dumps(res, separators=(",", ":")).encode()
                        )
                        if _is_closed_resp(res):
                            self.close_client(client)
                    except ConnectionError:
                        self.close_client(client)
                else:
                    client = self.read_sockets.get(sock)
                    if isinstance(client, UnrootDaemonClient):
                        try:
                            ll, data_raw, ts = sock.recv_raw(MTU)
                            self.logger.info(
                                "Sending {}({}) (ts={}) to {}"
                                .format(ll.__name__, data_raw,
                                        ts, client.ins.getpeername())
                            )
                            data = base64.b64encode(data_raw)
                            client.ins.send(json.dumps({"recv": {
                                "type": ll.__name__,
                                "data": data.decode(),
                                "ts": float(ts) if ts is not None
                                else ts,
                            }}, separators=(",", ":")).encode())
                        except ConnectionError:
                            self.close_client(client)
                    else:
                        self.logger.error("Unexpected socket selected {}"
                                          .format(sock))

    def remove_client(self, client):
        self.clients.pop(client.socket, None)

    def close_client(self, client):
        self.remove_client(client)
        client.close()

    def get_client_by_address(self, client_address):
        for client_sock in self.clients:
            client = self.clients[client_sock]
            if client.address == client_address:
                return client

    def watch_socket(self, socket, mapping=None):
        self.read_sockets[socket] = mapping

    def unwatch_socket(self, socket):
        self.read_sockets.pop(socket, None)


class UnrootDaemonClient:
    def __init__(self, daemon, socket, address):
        self.daemon = daemon
        self.socket = socket
        self.address = address
        self.supersocket = None
        self.ins = None

    def close(self):
        self.daemon.unwatch_socket(self.supersocket)
        self.close_supersocket()
        self.socket.close()

    def is_supersocket_initialized(self):
        return self.supersocket is not None

    def init_supersocket(self, type=None, ins=None, args=None):
        if type in ["L2listen", "L2socket", "L3socket", "L3socket6"]:
            if args is None:
                args = {}
            iface = args.get("iface", conf.iface)
            if iface in self.daemon.iface_blacklist:
                return _os_error_resp(errno.EPERM)
            enotconn = _os_error_resp(errno.ENOTCONN)
            if ins is None:
                return enotconn
            ins_client = self.daemon.get_client_by_address(ins)
            if ins_client is None:
                return enotconn
            # don't manage ins socket in daemon anymore, client class is now
            # responsible
            self.daemon.remove_client(ins_client)
            self.ins = ins_client.socket
            try:
                supersocket = getattr(conf, type)(**args)
            except TypeError as e:
                return _exc_to_error_resp(UNKNOWN_TYPE, e)
            except OSError as e:
                return _os_error_resp(e)
            else:
                self.supersocket = supersocket
                self.daemon.watch_socket(supersocket, self)
                return _success_resp()
        else:
            return _error_resp(
                UNKNOWN_TYPE,
                "Unknown socket type '{}'".format(type)
            )

    def send_via_supersocket(self, type="raw", data=""):
        if not self.is_supersocket_initialized():
            return _error_resp(
                UNINITILIZED,
                "Socket for '{}' is uninitialized".format(self.address)
            )
        try:
            bytes = base64.b64decode(data.encode())
        except binascii.Error:
            return _error_resp(
                INVALID_DATA, "data '{}' is not base64 encoded".format(data)
            )
        if not hasattr(layers, type):
            return _error_resp(
                UNKNOWN_TYPE, "Unknown packet type {}".format(type)
            )
        try:
            res = self.supersocket.send(getattr(layers, type)(bytes))
            return _success_resp(res)
        except OSError as e:
            return _os_error_resp(e)

    def close_supersocket(self):
        if self.is_supersocket_initialized():
            try:
                self.supersocket.close()
            except Exception as exc:
                self.daemon.logger.warning("Error on closing {} ({})"
                                           .format(self.supersocket, exc))
        return _closed_resp(str(self.address))


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemonize", action="store_true",
                        help="Run in background")
    parser.add_argument("-r", "--run-dir", default=RUN_DIR_DEFAULT,
                        help="Directory to store run information")
    parser.add_argument("group",
                        help="Permission group that is allowed to use scapy")
    parser.add_argument("-b", "--interface-blacklist", default=None, nargs="*",
                        help="Interfaces for which not to open sockets on")

    args = parser.parse_args()

    UnrootDaemon(**vars(args)).run()


if __name__ == "__main__":
    run()
