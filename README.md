# LoopKB
Kernel Bypass for loopback communications.

## Example Usage
Server:
```
$ LD_PRELOAD=libloopkb.so sockperf server
```

Client:
```
$ LD_PRELOAD=libloopkb.so sockperf ping-pong
```
