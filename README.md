# LoopKB
Kernel Bypass for loopback communications.

Started as a toy project, after realising Kernel Bypass libraries have no loopback acceleration:
 * libvma - No support
 * exasock - No support
 * onload - Claims to have support, but never worked for me

Message passing powered by Erik Rigtorp's [nanomq](https://github.com/rigtorp/nanomq).

Whether you want the acceleration, or whether it is a resource to learn from - I don't mind. If this project is useful to you, please leave feedback
or a contribution.

## Build
```
$ (mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release ..  && cmake --build .)
```

## Example Usage
Server:
```
$ LD_PRELOAD=build/libloopkb.so sockperf server --addr 127.0.0.1 --tcp
```

Client:
```
$ LD_PRELOAD=build/libloopkb.so sockperf ping-pong --addr 127.0.0.1 --tcp --burst 2
```

## Performance
AMD Ryzen 7 PRO 8840U:
 * Without libloopkb: percentile 50.000 = 10.584us
 * With libloopkb: percentile 50.000 = 0.391us

# Environment Variables
| Name               | Default Value | Description                                   |
|--------------------|---------------|-----------------------------------------------|
| LOOPKB_DEBUG       | unset         | If set to 1, spews some debugging information |
| LOOPKB_RING_SIZE   | 15            | Number of items in each ring buffer           |
| LOOPKB_PACKET_SIZE | 1500          | Mam item size in each ring buffer             |

## TODO
Lots, to begin with. But here is a partial list:
 * Implement more system calls, notably:
   * poll()
   * recvmsg()/recvmmsg()
 * Allow for non-bound UDP sockets (sendto(), recvfrom())
 * Add more configuration via environment variables, like:
   * Directory to keep ring buffers files in
   * Sockets/endpoints to offload
 * Better cleanup of artifact files

# License
Free use of this software is granted under the terms of the GNU General Public License (GPL). For details see the file LICENSE included with the loopkb distribution.
