# LoopKB
Kernel Bypass for loopback communications.

## Build
```
$ (mkdir -p build && cd build && cmake .. && make)
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
