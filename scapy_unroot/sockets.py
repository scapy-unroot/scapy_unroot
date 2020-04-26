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

import base64
import functools
import json
import logging
import os
import socket

from scapy.all import conf, MTU, Scapy_Exception, SuperSocket
import scapy.layers.all

from . import daemon


ERR_EXCEPTIONS = {
    daemon.UNKNOWN_OP: lambda msg="", **args: AttributeError(msg),
    daemon.UNKNOWN_TYPE: lambda msg="", **args: TypeError(msg),
    daemon.UNINITILIZED: lambda msg="", **args: RuntimeError(msg),
    daemon.INVALID_DATA: lambda msg="", **args: ValueError(msg),
    daemon.OS: lambda errno=None, msg="", **args: OSError(errno, msg),
}
logger = logging.getLogger(__name__)


class ScapyUnrootSocket(SuperSocket):
    desc = "read/write packets via the scapy_unroot daemon"

    def _op(self, op, op_type=None, data=None, **args):
        req = {"op": op}
        if op_type is not None:
            req["type"] = op_type
        if data is not None:
            req["data"] = base64.b64encode(data).decode()
        if len(args) > 0:
            req["args"] = args
        self.ins.settimeout(self.connection_timeout)
        self.ins.send(json.dumps(req, separators=(",", ":")).encode())
        resp = json.loads(self.ins.recv(daemon.DAEMON_MTU))
        self.ins.settimeout(None)
        if "error" in resp:
            err_type = resp["error"].get("type")
            if err_type in ERR_EXCEPTIONS:
                raise ERR_EXCEPTIONS[err_type](**resp["error"])
            else:
                raise RuntimeError("Unexpected error code {} from daemon"
                                   .format(err_type))
        elif "success" in resp:
            return resp["success"]
        elif "closed" in resp:
            return 0
        else:
            raise RuntimeError("Unexpected response from daemon '{}'"
                               .format(self.server_addr))

    def __init__(self, server_addr, scapy_conf_type, connection_timeout=0.01,
                 **kwargs):
        self.server_addr = server_addr
        self.scapy_conf_type = scapy_conf_type
        self.connection_timeout = connection_timeout
        self.ins = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if "listen" in scapy_conf_type:
            self.outs = None
        else:
            self.outs = self.ins
        self.ins.connect(self.server_addr)
        self._op("init", op_type=scapy_conf_type, **kwargs)

    def close(self):
        if self.closed:
            return
        try:
            self._op("close")
        except Exception as e:
            logger.warning("Exception on sending close to daemon '{}'"
                           .format(e))
        super().close()

    def send(self, x):
        if self.outs is None:
            raise Scapy_Exception("Can't send anything with conf.{} socket"
                                  .format(self.scapy_conf_type))
        if isinstance(x, scapy.layers.all.Packet):
            op_type = type(x).__name__
            data = bytes(x)
        else:
            op_type = None
            data = x
        return self._op("send", op_type=op_type, data=data)

    def recv_raw(self, x=MTU):
        x = int(x)
        if x < 0:
            raise ValueError("negative buffersize in recv")
        res = {}
        while "recv" not in res:
            res = json.loads(self.ins.recv(daemon.DAEMON_MTU))
            if "recv" not in res:
                logger.error("Received unexpected JSON object {}".format(res))
        obj = res["recv"]
        if obj is None:
            return scapy.layers.all.raw, b"", None
        if "data" in obj:
            data = base64.b64decode(obj["data"])[:x]
        else:
            data = b""
        if "type" in obj:
            LL = getattr(scapy.layers.all, obj["type"])
        else:
            LL = scapy.layers.all.raw
        return LL, data, obj.get("ts")

    # for some reason this static method is used as bound method within scapy
    # so explicitly inherit from SuperSocket
    @staticmethod
    def select(*args, **kwargs):
        res = SuperSocket.select(*args, **kwargs)
        return res


def configure_sockets(server_addr=None, connection_timeout=0.1):
    if server_addr is None:
        server_addr = os.path.join(daemon.RUN_DIR_DEFAULT, "server-socket")
    for socket_conf in ["L2listen", "L2socket", "L3socket", "L3socket6"]:
        setattr(conf, socket_conf,
                functools.partial(ScapyUnrootSocket, server_addr,
                                  socket_conf, connection_timeout))
