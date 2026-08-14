#!/bin/bash

cleanup() {
    echo ""
    echo "Caught signal – tearing down lab..."
    /testbed/teardown.sh
    echo "Lab cleaned up. Exiting."
    exit 0
}

trap cleanup SIGINT SIGTERM
# Attack tooling and reset routines spray broad signals (pkill -HUP/-9,
# dhclient restarts). Ignore stray signals at PID 1 so a misfired kill
# never tears the whole container down — only an explicit docker stop
# (SIGTERM/SIGINT above) ends the lab.
trap '' SIGHUP SIGUSR1 SIGUSR2

echo "============================================"
echo "  DS-Lite Testbed (RFC 6333 / 6334)"
echo "  Running inside Docker container"
echo "============================================"
if [ -r /testbed/BUILD_INFO ]; then
    echo "  Image built: $(cat /testbed/BUILD_INFO)"
    echo "  (rebuild with: docker build -t ds-lite-lab testbed/ if sources changed)"
fi
echo ""

export PCAP_DIR="/testbed/pcaps"
/testbed/setup.sh

echo ""
echo "============================================"
echo "  Lab is running."
echo "  Pcap files: /testbed/pcaps/"
echo "============================================"
echo ""

# Wait forever. Do NOT break on a spurious wait return: if the backgrounded
# sleep is killed by a stray pkill or wait is interrupted by a non-fatal
# signal, just loop and wait again. Graceful shutdown happens only via the
# SIGINT/SIGTERM trap (cleanup), keeping the container alive through the
# attack corpus regardless of what the tools do to child processes.
while true; do
    sleep 86400 &
    wait $!
done
