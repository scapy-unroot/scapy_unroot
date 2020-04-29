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
        self.iface_blacklist = interface_blacklist or []
        self.pidfile = None
        self.socketname = os.path.join(run_dir, "server-socket")
        self.socket = None
        self.clients = dict()

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
                if "supersocket" in self.clients[client]:
                    self.clients[client]["supersocket"].close()
                client.close()
        if hasattr(self, "socket") and self.socket:
            self.socket.close()
        if hasattr(self, "socketname") and self.socketname and \
           os.path.exists(self.socketname):
            os.unlink(self.socketname)

    @staticmethod
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

    @staticmethod
    def _error_resp(type, msg):
        return {"error": locals()}

    @classmethod
    def _exc_to_error_resp(cls, type, exc):
        return cls._error_resp(type, str(exc))

    @staticmethod
    def _success_resp(res=0):
        return {"success": res}

    @staticmethod
    def _closed_resp(socket):
        return {"closed": str(socket["address"])}

    @staticmethod
    def _is_closed_resp(resp):
        return "closed" in resp

    def _init_supersocket(self, data, client):
        if data.get("type") in ["L2listen", "L2socket",
                                "L3socket", "L3socket6"]:
            args = data.get("args", {})
            iface = args.get("iface", conf.iface)
            if iface in self.iface_blacklist:
                return self._os_error_resp(errno.EPERM)
            try:
                supersocket = getattr(conf, data["type"])(**args)
            except TypeError as e:
                return self._exc_to_error_resp(UNKNOWN_TYPE, e)
            except OSError as e:
                return self._os_error_resp(e)
            else:
                client["supersocket"] = supersocket
                self.read_sockets[supersocket] = "supersocket.{}" \
                    .format(client["address"])
                return self._success_resp()
        else:
            return self._error_resp(
                UNKNOWN_TYPE,
                "Unknown socket type '{}'".format(data.get("type"))
            )

    def _send_via_supersocket(self, client, type, data):
        if "supersocket" not in client:
            return self._error_resp(
                UNINITILIZED,
                "Socket for '{}' is uninitialized".format(client["address"])
            )
        try:
            bytes = base64.b64decode(data.encode())
        except binascii.Error:
            return self._error_resp(
                INVALID_DATA, "data '{}' is not base64 encoded".format(data)
            )
        if not hasattr(layers, type):
            return self._error_resp(
                UNKNOWN_TYPE, "Unknown packet type {}".format(type)
            )
        try:
            res = client["supersocket"].send(getattr(layers, type)(bytes))
            return self._success_resp(res)
        except OSError as e:
            return self._os_error_resp(e)

    def _close_supersocket(self, client):
        if "supersocket" in client:
            try:
                client["supersocket"].close()
            except Exception as exc:
                self.logger.warning("Error on closing {} ({})"
                                    .format(client["supersocket"], exc))
        return self._closed_resp(client)

    def _eval_data(self, data, client):
        op = data.get("op")
        if op == "init":
            return self._init_supersocket(data, client)
        elif op == "send":
            return self._send_via_supersocket(client,
                                              data.get("type", "raw"),
                                              data.get("data", ""))
        elif op == "close":
            return self._close_supersocket(client)
        else:
            return self._error_resp(
                UNKNOWN_OP, "Operation '{}' unknown".format(data.get("op"))
            )

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
        self.read_sockets = {self.socket: "server_socket"}
        while True:
            sockets, _ = SuperSocket.select(self.read_sockets)
            for sock in sockets:
                if self.socket == sock:
                    connection, client_address = sock.accept()
                    self.read_sockets[connection] = client_address
                    self.clients[connection] = {
                        "address": client_address,
                    }
                elif sock in self.clients:
                    try:
                        b = sock.recv(DAEMON_MTU)
                        if len(b) == 0:
                            # don't bother trying to parse this
                            continue
                        try:
                            data = json.loads(b)
                        except json.decoder.JSONDecodeError:
                            # silently ignore JSON decode errors as empty
                            # messages are exchanged between UNIX domain stream
                            # sockets all the time
                            continue
                        res = self._eval_data(data, self.clients[sock])
                        sock.send(
                            json.dumps(res, separators=(",", ":")).encode()
                        )
                        if self._is_closed_resp(res):
                            self.read_sockets.pop(
                                self.clients[sock].get("supersocket"),
                                None
                            )
                            self.clients.pop(sock, None)
                            self.read_sockets.pop(sock, None)
                            sock.close()
                    except ConnectionError:
                        self.clients.pop(sock, None)
                        self.read_sockets.pop(sock, None)
                        sock.close()
                else:
                    try:
                        socket_found = False
                        for client in self.clients:
                            if sock == self.clients[client]["supersocket"]:
                                socket_found = True
                                ll, data_raw, ts = sock.recv_raw(MTU)
                                self.logger.info(
                                    "Sending {}({}) (ts={}) to {}"
                                    .format(ll.__name__, data_raw,
                                            ts, client.getpeername())
                                )
                                data = base64.b64encode(data_raw)
                                client.send(json.dumps({"recv": {
                                    "type": ll.__name__,
                                    "data": data.decode(),
                                    "ts": float(ts) if ts is not None
                                    else ts,
                                }}, separators=(",", ":")).encode())
                        if not socket_found:
                            self.logger.error("Unexpected socket selected {}"
                                              .format(sock))
                    except ConnectionError:
                        sock.close()
                        self.read_sockets.pop(sock, None)
                        for client in self.clients:
                            if sock == self.clients[client]["supersocket"]:
                                self.clients.pop(client, None)
                                break


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
