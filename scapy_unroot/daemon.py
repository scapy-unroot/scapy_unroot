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
Daemon to enable using scapy without root.
"""

import argparse
import atexit
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
OS = 4


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

    def _fork_as_daemon(self):
        """
        Does the UNIX double-fork magic to the calling process, see Stevens'
        "Advanced Programming in the UNIX Environment" for details
        (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as exc:
            self.logger.error("fork #1 failed: {exc.errno} ({exc.strerror})"
                              .format(exc=exc))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as exc:
            self.logger.error("fork #2 failed: {exc.errno} ({exc.strerror})"
                              .format(exc=exc))
            sys.exit(1)
        output_file = os.path.join(self.run_dir, "output.log")
        output = open(output_file, 'a+')
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(output.fileno(), sys.stdout.fileno())
        os.dup2(output.fileno(), sys.stderr.fileno())

        self.pidfile = os.path.join(self.run_dir, "pidfile")

        atexit.register(self.__del__)
        pid = os.getpid()
        # write pidfile
        with open(self.pidfile, "w+") as f:
            print("{}".format(pid), file=f)
        return pid

    def __del__(self):
        if hasattr(self, "pidfile") and self.pidfile and \
           os.path.exists(self.pidfile):
            os.remove(self.pidfile)
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

    def _eval_data(self, data, socket):
        op = data.get("op")
        if op == "init":
            if data.get("type") in ["L2listen", "L2socket",
                                    "L3socket", "L3socket6"]:
                args = data.get("args", {})
                iface = args.get("iface", conf.iface)
                if iface in self.iface_blacklist:
                    return {
                        "error": {
                            "type": OS,
                            "msg": os.strerror(errno.EPERM),
                            "errno": errno.EPERM,
                        }
                    }
                try:
                    socket["supersocket"] = getattr(conf, data["type"])(**args)
                    return {
                        "success": 0
                    }
                except OSError as e:
                    return {
                        "error": {
                            "type": OS,
                            "msg": e.strerror,
                            "errno": e.errno,
                        }
                    }
            else:
                return {
                    "error": {
                        "type": UNKNOWN_TYPE,
                        "msg": "Unknown socket type {}".format(
                            data.get("type")
                        ),
                    }
                }
        elif op == "write":
            if "supersocket" not in socket:
                return {
                    "error": {
                        "type": UNINITILIZED,
                        "msg": "Socket for '{}' is uninitialized".format(
                            socket["address"]
                        ),
                    }
                }
            type = data.get("type", "raw")
            bytes = base64.decode(data.get("data", ""))
            if not hasattr(layers, type):
                return {
                    "error": {
                        "type": UNKNOWN_TYPE,
                        "msg": "Unknown packet type {}".format(
                            data.get("type")
                        ),
                    }
                }
            try:
                res = socket["supersocket"].send(getattr(layers, type)(bytes))
                return {"success": res}
            except OSError as e:
                return {
                    "error": {
                        "type": OS,
                        "msg": e.strerror,
                        "errno": e.errno,
                    }
                }
        elif op == "close":
            if "supersocket" in socket:
                try:
                    socket["supersocket"].close()
                except Exception:
                    pass
            return {"closed": str(socket["address"])}
        else:
            return {
                "error": {
                    "type": UNKNOWN_OP,
                    "msg": "Operation '{}' unknown".format(
                        data.get("op")
                    ),
                }
            }

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
        read_sockets = {self.socket: "server_socket"}
        while True:
            sockets, _ = SuperSocket.select(read_sockets)
            for sock in sockets:
                if self.socket == sock:
                    connection, client_address = sock.accept()
                    read_sockets[connection] = client_address
                    self.clients[connection] = {
                        "address": client_address,
                    }
                elif sock in self.clients:
                    try:
                        try:
                            # MTU plus extra for JSON data
                            b = sock.recv(MTU + 128)
                            if len(b) == 0:
                                continue
                            data = json.loads(b)
                            res = self._eval_data(data, self.clients[sock])
                        except json.decoder.JSONDecodeError:
                            continue
                        if "closed" in res:
                            try:
                                del read_sockets[
                                    self.clients[sock].get("supersocket")
                                ]
                                del self.clients[sock]
                                del read_sockets[sock]
                            except KeyError:
                                pass
                            sock.close()
                        if "init" in res:
                            read_sockets[self.clients[sock]["supersocket"]] = \
                                "supersocket.{}".format(
                                    self.clients[sock]["address"]
                                )
                        sock.send(
                            json.dumps(res, separators=(",", ":")).encode()
                        )
                    except ConnectionError:
                        sock.close()
                        del self.clients[sock]
                        del read_sockets[sock]
                else:
                    try:
                        for client in self.clients:
                            if sock == self.clients[client]["supersocket"]:
                                ll, data_raw, ts = sock.recv(MTU)
                                data = base64.encode(data_raw)
                                sock.send(json.dumps({"recv": {
                                    "type": ll.__name__,
                                    "data": data_raw,
                                    "ts": float(ts) if ts is not None
                                    else ts,
                                }}, separators=(",", ":")))
                                continue
                        self.logger.error("Unexpected socket selected {}"
                                          .format(sock))
                    except ConnectionError:
                        sock.close()
                        del read_sockets[sock]
                        for client in self.clients:
                            if sock == self.clients[client]["supersocket"]:
                                del client[client]


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
