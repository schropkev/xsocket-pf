# `xsocket-pf`: xsocket Port forwarder.

`xsocket-pf` is a TCP/UDP port forwarder using zero-copy mechanism, and it uses [xsocket](https://github.com/koro666/xsocket). Perfect for forwarding host side ports into network namespaces with no `CAP_SYS_ADMIN` privilege.

You can use `xsocket-pf` to forward ports acrooss network namespaces, VRFs and cgroups (in which `xsocket-server` is running and sockets are processed/modified by iptables/nft).

## Build

This project has no external dependencies, just clone the repository and compile with `Go` as usual.

```
git clone https://github.com/schropkev/xsocket-pf
cd xsocket-pf
go build
```

If you wish to compile this program into a static binary:

`CGO_ENABLED=0 go build`

## Usage

Its usage is:

`./xsocket-pf protocol://listen/target?xsocket.in=SOCKET&xsocket.out=SOCKET[&timeout=SECONDS]`

`listen` is the listening point of this forwarder, `target` is the upstream port to send requests to, `xsocket.in` is the [xsocket-server](https://github.com/koro666/xsocket) Unix socket to connect when listening, `xsocket.out` `xsocket.in` is the [xsocket-server](https://github.com/koro666/xsocket) Unix socket to connect when connecting to upstream port.

**Examples:**

`./xsocket-pf protocol://127.0.0.1:1234/127.0.0.1:4321?xsocket.in=/path/to/xsocket-server/xsocket-socket&xsocket.out=/path/to/xsocket-server/another-xsocket-socket`

`./xsocket-pf protocol://[::1]:1234/127.0.0.1:4321?xsocket.in=@xsocket-abstract-socket&xsocket.out=/path/to/xsocket-server/xsocket-socket&timeout=10`

`./xsocket-pf protocol://127.0.0.1:1234/[::1]:4321?xsocket.in=/path/to/xsocket-server/xsocket-socket&xsocket.out=@xsocket-abstract-socket`

`./xsocket-pf protocol://[::1]:1234/[::1]:4321?xsocket.in=xsocket-abstract-socket&xsocket.out=/path/to/xsocket-server/xsocket-socket&timeout=5`

**Remembering:** `./xsocket-pf protocol://listen/target?xsocket.in=SOCKET&xsocket.out=SOCKET[&timeout=SECONDS]`

`listen` and `target` can have a IPv4 or a `[bracketed]` IPv6 (**[::1]** for example). `xsocket.in` and `xsocket.out` can accept `xsocket-server` Unix sockets as file paths (like `/path/to/xsocket-server/socket`) or abstract ones (like `@xsocket-server_socket`).

You must run a `xsocket-server` for each [xsocket](https://github.com/koro666/xsocket) socket if you want to cross-forward across network namespaces and VRFs, it doesn't matter if is inside a network namespace, VRF, cgroup or whatever shell it belongs to (except inside Virtual Machines).

**ALWAYS run `xsocket-server` as an unpriviled user for security reasons:**

`sudo -u someuser -- xsocket-server /path/to/xsocket-server/socket`

`sudo ip netns exec somenetns sudo -u someuser -- xsocket-server /path/to/xsocket-server/socket`

`sudo ip vrf exec sudo -u someuser -- vrf-blue xsocket-server @xsocket-server_socket`

--------------------

## Thanks

- [@koro666](https://github.com/koro666) for his awesome project [xsocket](https://github.com/koro666/xsocket).

--------------------

Created on June 1, 2026.
