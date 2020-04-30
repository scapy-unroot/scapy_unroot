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
Server script for the interaction tests. Run by scapy interaction test.
"""

import argparse
import functools
import grp
import os
import pwd
import logging
import socket
import sys
import tempfile

from scapy.all import conf, Ether, IP, IPv6, SimpleSocket, SuperSocket

from scapy_unroot.daemon import UnrootDaemon


logger = logging.getLogger("tests.interaction-server")


class UNIXSocket(SimpleSocket):
    count = 0

    def __init__(self, run_dir, test_remote, scapy_conf_type, *args, **kwargs):
        logger.info("Initializing {} with arguments {} {}"
                    .format(scapy_conf_type, args, kwargs))
        super().__init__(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
        self.scapy_conf_type = scapy_conf_type
        self.remote = test_remote
        self.address = os.path.join(
            run_dir,
            "{}.{}".format(type(self).__name__, type(self).count)
        )
        type(self).count += 1
        self.ins.bind(self.address)
        logger.info("Bound socket to '{}'".format(self.address))
        self.ins.connect(test_remote)

    def close(self, *args, **kwargs):
        logger.info("Closing {} with arguments {} {}"
                    .format(self.scapy_conf_type, args, kwargs))
        res = super().close(*args, **kwargs)
        if os.path.exists(self.address):
            os.remove(self.address)
        return res

    def recv_raw(self, x, *args, **kwargs):
        logger.info("Receiving on {} with arguments x={}, {} {}"
                    .format(self.scapy_conf_type, x, args, kwargs))
        pkt = self.ins.recv(x)
        if self.scapy_conf_type.startswith("L2"):
            layer = Ether
        elif (pkt[0] & 0xf0) == 0x40:
            layer = IP
        elif (pkt[0] & 0xf0) == 0x60:
            layer = IPv6
        else:
            layer = conf.rawlayer
        return layer, pkt, None

    def send(self, data, *args, **kwargs):
        logger.info("Sending from {} with data='{}' and arguments {} {}"
                    .format(self.scapy_conf_type, repr(data), args, kwargs))
        return super().send(data, *args, **kwargs)

    def select(sockets, *args, **kwargs):
        logger.info("Selecting sockets {} with arguments {} {}".
                    list(sockets), args, kwargs)
        return SuperSocket.select(*args, **kwargs)


def select_wrapper(orig_select):
    def _select(read_sockets, *args, **kwargs):
        logger.info("Starting to listen on {}".format(read_sockets))
        return orig_select(read_sockets, *args, **kwargs)
    return _select


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("remote",
                        help="A UNIX domain socket to provide a back-channel"
                             "to the client")
    args = parser.parse_args()

    # get group name for current user
    group = grp.getgrgid(pwd.getpwuid(os.getuid())[3])[0]

    with tempfile.TemporaryDirectory(prefix="scapy_unroot.tests.") as run_dir:
        for socket_conf in ["L2listen", "L2socket", "L3socket", "L3socket6"]:
            setattr(conf, socket_conf,
                    functools.partial(UNIXSocket, run_dir, args.remote,
                                      socket_conf))
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)
        logger.info("Starting server for group {} on run_dir {}"
                    .format(group, run_dir))
        # replace select with a version that logs the call
        SuperSocket.select = select_wrapper(SuperSocket.select)
        UnrootDaemon(group=group, run_dir=run_dir).run()


if __name__ == "__main__":
    main()
