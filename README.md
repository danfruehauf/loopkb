# LoopKB
Transparent Kernel Bypass library for loopback communications.

Started as a toy project, after realising Kernel Bypass libraries have no loopback acceleration:
 * libvma - No support
 * exasock - No support
 * onload - Claims to have support, but never worked for me

Message passing powered by Erik Rigtorp's [nanomq](https://github.com/rigtorp/nanomq).

Whether you want the acceleration, or whether it is a resource to learn from - I don't mind. If this project is useful to you, please leave feedback
or a contribution.

## Build
```
$ (mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release ..  && cmake --build . && ctest)
```

## Example Usage

### sockperf
Server:
```
$ LD_PRELOAD=build/libloopkb.so sockperf server --addr 127.0.0.1 --tcp
```

Client:
```
$ LD_PRELOAD=build/libloopkb.so sockperf ping-pong --addr 127.0.0.1 --client_addr 127.0.0.1 --tcp --burst 2
```

### nc
Server:
```
$ LD_PRELOAD=build/libloopkb.so nc -l 127.0.0.1 5000
```

Client:
```
$ LD_PRELOAD=build/libloopkb.so nc --source 127.0.0.1 127.0.0.1 5000
```

## Performance
AMD Ryzen 7 PRO 8840U:
 * Without libloopkb: percentile 50.000 = **8.450us**
```
sockperf: Total 46788 observations; each percentile contains 467.88 observations
sockperf: ---> <MAX> observation =  110.200
sockperf: ---> percentile 99.999 =  110.200
sockperf: ---> percentile 99.990 =   85.424
sockperf: ---> percentile 99.900 =   36.042
sockperf: ---> percentile 99.000 =   18.399
sockperf: ---> percentile 90.000 =    9.602
sockperf: ---> percentile 75.000 =    9.242
sockperf: ---> percentile 50.000 =    8.450
sockperf: ---> percentile 25.000 =    7.178
sockperf: ---> <MIN> observation =    5.289
```
 * With libloopkb: percentile 50.000 = **0.370us**
```
sockperf: Total 1084322 observations; each percentile contains 10843.22 observations
sockperf: ---> <MAX> observation =   19.125
sockperf: ---> percentile 99.999 =    5.139
sockperf: ---> percentile 99.990 =    3.516
sockperf: ---> percentile 99.900 =    1.803
sockperf: ---> percentile 99.000 =    0.485
sockperf: ---> percentile 90.000 =    0.410
sockperf: ---> percentile 75.000 =    0.395
sockperf: ---> percentile 50.000 =    0.370
sockperf: ---> percentile 25.000 =    0.305
sockperf: ---> <MIN> observation =    0.285
```

# Environment Variables
| Name               | Default Value     | Description                                   |
|--------------------|-------------------|-----------------------------------------------|
| LOOPKB_LOG_LEVEL   | warn              | Can be trace, debug, info, warn, error        |
| LOOPKB_RING_SIZE   | 15                | Number of items in each ring buffer           |
| LOOPKB_PACKET_SIZE | 1500              | Max item size in each ring buffer             |
| LOOPKB_MAX_SOCKETS | 128               | Max offloaded sockets                         |
| LOOPKB_SOCEKT_DIR  | nil (current dir) | Directory to keep socket/context files        |

## TODO
Lots, to begin with. But here is a partial list:
 * Implement more system calls, notably:
   * ~~poll()~~
   * epoll()
   * recvmsg()/recvmmsg()
   * ~~fcntl() (With `F_SETFL/SOCK_NONBLOCK`)~~
 * ~~Allow non-bound UDP sockets (sendto(), recvfrom())~~
   * ~~Allow "connected" UDP sockets~~
 * Add more configuration via environment variables, like:
   * ~~Directory to keep ring buffers files in~~
   * Sockets/endpoints to offload
 * Better cleanup of artifact files

# License
Free use of this software is granted under the terms of the GNU General Public License (GPL). For details see the file LICENSE included with the loopkb distribution.
