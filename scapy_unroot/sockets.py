# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright (C) 2020 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU General Public
# License v3.0. See the file LICENSE in the top level directory for more
# details.

"""
Sockets to communicate with the daemon to enable using scapy without root.
"""

import json
import socket

from scapy.all import MTU, SuperSocket

from . import daemon


ERR_EXCEPTIONS = {
    daemon.UNKNOWN_OP: lambda msg="", **args: AttributeError(msg),
    daemon.UNKNOWN_TYPE: lambda msg="", **args: TypeError(msg),
    daemon.OS: lambda errno=None, msg="", **args: OSError(errno, msg),
}


class ScapyUnrootSocket(SuperSocket):
    desc = "read/write packets via the scapy_unroot daemon"

    def _op(self, op, op_type=None, **args):
        req = {"op": op}
        if op_type is not None:
            req["type"] = op_type
        if len(args) > 0:
            req["args"] = args
        self.ins.send(json.dumps(req, separators=(",", ":")).encode())
        resp = json.loads(self.ins.recv(MTU))
        if "error" in resp:
            err_type = resp["error"].get("type")
            if err_type in ERR_EXCEPTIONS:
                raise ERR_EXCEPTIONS[err_type](**resp["error"])
            else:
                raise RuntimeError("Unexpected error code {} from daemon"
                                   .format(err_type))
        elif "success" in resp:
            return resp["success"]
        else:
            raise RuntimeError("Unexpected response from daemon '{}'"
                               .format(self.server_addr))

    def __init__(self, server_addr, scapy_conf_type, connection_timeout=0.01,
                 **kwargs):
        self.server_addr = server_addr
        self.scapy_conf_type = scapy_conf_type
        self.ins = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ins.settimeout(connection_timeout)
        if "listen" in scapy_conf_type:
            self.outs = None
        else:
            self.outs = self.ins
            self.outs.settimeout(connection_timeout)
        self.ins.connect(self.server_addr)
        self._op("init", op_type=scapy_conf_type, **kwargs)
