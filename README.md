# LoopKB
Kernel Bypass for loopback communications.

Started as a toy project, after realising Kernel Bypass libraries have no loopback acceleration:
 * libvma - No
 * exasock - No
 * onload - Claims to have, never got it to run

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
$ LD_PRELOAD=build/libloopkb.so sockperf ping-pong --addr 127.0.0.1 --tcp
```

## Performance
 * Without libloopkb: percentile 50.000 = 6.266
 * With libloopkb: percentile 50.000 = 1.993

## TODO
Lots, to begin with. But here is a partial list:
 * Implement more system calls, notably:
   * poll()
   * recvmsg()/recvmmsg()
 * Allow for non-bound UDP sockets (sendto(), recvfrom())
 * Add more configuration via environment variables, like:
   * Directory to keep ring buffers files in
   * Sizes of ring buffers
   * Sockets/endpoints to offload
 * Better cleanup of artifact files
 * Reduce footprint of various data structures
   * Use a more compact data structure for offloaded sockets

# License
Free use of this software is granted under the terms of the GNU General Public License (GPL). For details see the file LICENSE included with the loopkb distribution.
