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

### Status
| Platform       | Status                                                                                                              |
|----------------|---------------------------------------------------------------------------------------------------------------------|
| Fedora Latest  | ![Fedora Latest Build](https://github.com/danfruehauf/loopkb/actions/workflows/build_fedora_latest.yml/badge.svg)   |
| Fedora Rawhide | ![Fedora Rawhide Build](https://github.com/danfruehauf/loopkb/actions/workflows/build_fedora_rawhide.yml/badge.svg) |
| Rocky 9        | ![Rocky 9 Build](https://github.com/danfruehauf/loopkb/actions/workflows/build_rocky_9.yml/badge.svg)               |
| Ubuntu Latest  | ![Ubuntu Latest Build](https://github.com/danfruehauf/loopkb/actions/workflows/build_ubuntu_latest.yml/badge.svg)   |

## Example Usage

### sockperf
Server:
```
$ LD_PRELOAD=build/libloopkb.so sockperf server --addr 127.0.0.1 --tcp
```

Client:
```
$ LD_PRELOAD=build/libloopkb.so sockperf ping-pong --addr 127.0.0.1 --client_addr 127.0.0.1 --tcp --mps 5000000
```

`--mps` must be passed, failure to do so can result in:
```
sockperf: ERROR: _seqN > m_maxSequenceNo (errno=2 No such file or directory)
```

This is due to libloopkb potentially breaking the maximum default packet rate sockperf is expected to have (600K/s).

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

### AMD Ryzen 7 PRO 8840U
 * Without libloopkb: percentile 50.000 = **6.436**
```
sockperf: Total 41210 observations; each percentile contains 412.10 observations
sockperf: ---> <MAX> observation =  119.949
sockperf: ---> percentile 99.999 =  119.949
sockperf: ---> percentile 99.990 =   58.579
sockperf: ---> percentile 99.900 =   20.027
sockperf: ---> percentile 99.000 =   11.491
sockperf: ---> percentile 90.000 =    6.667
sockperf: ---> percentile 75.000 =    6.537
sockperf: ---> percentile 50.000 =    6.436
sockperf: ---> percentile 25.000 =    6.311
sockperf: ---> <MIN> observation =    5.380
```
 * With libloopkb: percentile 50.000 = **0.165**
```
sockperf: Total 275270 observations; each percentile contains 2752.70 observations
sockperf: ---> <MAX> observation =   56.786
sockperf: ---> percentile 99.999 =   17.968
sockperf: ---> percentile 99.990 =    6.296
sockperf: ---> percentile 99.900 =    1.447
sockperf: ---> percentile 99.000 =    0.355
sockperf: ---> percentile 90.000 =    0.180
sockperf: ---> percentile 75.000 =    0.170
sockperf: ---> percentile 50.000 =    0.165
sockperf: ---> percentile 25.000 =    0.155
sockperf: ---> <MIN> observation =    0.105
```

<<<<<<< HEAD
| Name                      | Default Value               | Description                                     |
|---------------------------|-----------------------------|-------------------------------------------------|
| LOOPKB_LOG_LEVEL          | warn                        | Can be trace, debug, info, warn, error          |
| LOOPKB_RING_SIZE          | 15                          | Number of items in each ring buffer             |
| LOOPKB_RING_WARMUP_ROUNDS | 0                           | Warmup rounds for ring buffers (recommended: 1) |
| LOOPKB_PACKET_SIZE        | 1500                        | Max item size in each ring buffer               |
| LOOPKB_MAX_SOCKETS        | 128                         | Max offloaded sockets                           |
| LOOPKB_SOCEKT_DIR         | nil (current dir)           | Directory to keep socket/context files          |
| LOOPKB_OFFLOAD_ADDR       | 127.0.0.1/255.0.0.0,::1/128 | Addresses/masks to offload, comma separated     |

## TODO
Lots, to begin with. But here is a partial list:
 * Implement more system calls, notably:
   * ~~poll()~~
   * epoll()
   * ~~recvmsg()/recvmmsg()~~
   * ~~sendmsg()/sendmmsg()~~
   * ~~fcntl() (With `F_SETFL/SOCK_NONBLOCK`)~~
 * ~~Allow non-bound UDP sockets (sendto(), recvfrom())~~
   * ~~Allow "connected" UDP sockets~~
 * Add more configuration via environment variables, like:
   * ~~Directory to keep ring buffers files in~~
   * ~~Sockets/endpoints to offload~~
 * ~~Better cleanup of artifact files (UDP sockets)~~
 * ~~Multi-threading support - with direct indexing, this is guaranteed~~
 * Support sending of packets that are larger than buffer unit size

# License
Free use of this software is granted under the terms of the GNU General Public License (GPL). For details see the file LICENSE included with the loopkb distribution.
