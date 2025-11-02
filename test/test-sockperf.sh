#!/bin/bash

set -euo pipefail

SOCKPERF_PORT=11111
SOCKPERF_SERVER_LOG=$(mktemp /tmp/sockperf-server.XXXX.log)
SOCKPERF_CLIENT_LOG=$(mktemp /tmp/sockperf-client.XXXX.log)

main() {
	sockperf server --tcp --addr 127.0.0.1 --port $SOCKPERF_PORT > $SOCKPERF_SERVER_LOG 2>&1 &
	local sockperf_server_pid=$!

	sleep 1

	echo "Running sockperf client test..."
	sockperf ping-pong --tcp --addr 127.0.0.1 --client_addr 127.0.0.1 --port $SOCKPERF_PORT --mps 5000000 > $SOCKPERF_CLIENT_LOG 2>&1
	local -i retval=$?

	echo "Stopping sockperf server (PID $sockperf_server_pid)..."
	kill $sockperf_server_pid 2>/dev/null || true
	wait $sockperf_server_pid 2>/dev/null || true

	cat $SOCKPERF_CLIENT_LOG
	rm -f $SOCKPERF_SERVER_LOG $SOCKPERF_CLIENT_LOG
	return $retval
}

main "$@"
