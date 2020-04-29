[![Supported Python versions]](https://pypi.org/project/scapy-unroot)
[![PyPI version]](https://badge.fury.io/py/scapy-unroot)
[![Build Status]](https://travis-ci.com/miri64/scapy_unroot)
[![codecov]](https://codecov.io/gh/miri64/scapy_unroot)

[PyPI version]: https://badge.fury.io/py/scapy-unroot.svg
[Supported Python versions]: https://img.shields.io/pypi/pyversions/scapy-unroot.svg
[Build Status]: https://travis-ci.com/miri64/scapy_unroot.svg?branch=master
[codecov]: https://codecov.io/gh/miri64/scapy_unroot/branch/master/graph/badge.svg

# scapy-unroot
Daemon and tooling to enable using [scapy] without root permissions.

## Installation
`scapy_unroot` can be installed by just running

```sh
./setup.py install
```

The requirements also installed by this are listed in
[`requirements.txt`](./requirements.txt).

## Usage
### The `scapy-unroot` daemon
The daemon to allow usage of scapy without root permissions requires root
itself. You can start it with the following command:

```sh
sudo scapy-unroot scapy
```

The provided argument `scapy` should be a permission group, users who are
allowed to use scapy without root permissions should be in.

By default, all files related to `scapy_unroot` are managed in the directory
`/var/run/scapy-unroot`. You can change that directory using the `-r` /
`--run-dir` argument:

```sh
sudo scapy-unroot --run-dir /tmp scapy
```

The UNIX domain socket to communicate with the daemon will be created under the
name `server-socket` in that directory.

Network interfaces that users of `scapy_unroot` should not be able to send over
or sniff on can be blacklisted using the `-b` / `--interface-blacklist`
argument. Multiple interfaces can be provided:

```sh
sudo scapy-unroot scapy --interface-blacklist wlan0 eth0 lo
```

To run the daemon in background, use the `-d` / `--daemonize` parameter:

```sh
sudo scapy-unroot -d scapy
```

To get more information on the arguments of the `scapy-unroot` daemon, run

```sh
sudo scapy-unroot -h
```

All arguments described above can be combined.

### Configuring scapy to communicate with the daemon
Before sending or sniffing with scapy, just do

```py
from scapy_unroot import configure_sockets

configure_sockets()
```

You can provide a different server address by the _server_addr_ argument. The
default is `/var/run/scapy_unroot/server-socket`.

You can also configure the timeout for waiting for a reply from the server using
the _connection_timeout_ argument.

[scapy]: https://scapy.net/
