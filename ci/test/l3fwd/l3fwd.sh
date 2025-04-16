#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

set -e

OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $OCTEONTESTPATH/common/vpp/vpp.env
source $OCTEONTESTPATH/common/testpmd/pktgen.env
source $OCTEONTESTPATH/common/pcap/pcap.env

NO_HP=${NO_HP:-}
HP=${HP:-8}

function mount_hugetlbfs() {
	# Mount hugetlbfs.
	if ! mount | grep -q hugepages; then
		mount -t hugetlbfs none /dev/hugepages/
	fi
}

function setup_hp() {
	if [[ -n $NO_HP ]]; then
		echo "Skipping huge page setup"
		return
	fi
	# Enable HP hugepages.
	echo $HP > /proc/sys/vm/nr_hugepages
}

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		vpp_stats_all l3fwd
		echo $status
		echo "$1 Handler"
	fi
	pktgen_quit
	pktgen_cleanup
	vpp_cleanup l3fwd
	exit $status
}

PKTGEN_PCAP="l3fwd.pcap"
PKTGEN_PORT="0002:01:00.1"
PKTGEN_COREMASK="0xf0"
L3FWD_PORT="0002:01:00.2"
L3FWD_MAINCORE="0x2"
L3FWD_WORKER_COREMASK="0x4"


trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

mount_hugetlbfs
setup_hp

PCAP_CNT=$(pcap_packet_count $PKTGEN_PCAP)
PCAP_LEN=$(pcap_length $PKTGEN_PCAP)

echo "Starting l3fwd with Port=$L3FWD_PORT, Worker_Coremask=$L3FWD_WORKER_COREMASK"
rm -rf /tmp/l3fwd
mkdir -p /tmp/l3fwd
cp l3fwd.exec /tmp/l3fwd/
vpp_launch l3fwd
vpp_start l3fwd
echo "Starting pktgen with Port=$PKTGEN_PORT, Coremask=$PKTGEN_COREMASK, Pcap=$PKTGEN_PCAP"
pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $PKTGEN_PCAP
echo "pktgen start"
pktgen_start
sleep 5
vpp_port_down l3fwd eth0

vpp_stats_all l3fwd > /dev/null
pktgen_stats > /dev/null

echo "-------------------- L3FWD LOGS ---------------------"
vpp_log l3fwd
echo "-------------------- PKTGEN LOGS --------------------"
pktgen_log

VPP_RX_COUNT=$(vpp_rx_count l3fwd eth0)
VPP_TX_COUNT=$(vpp_tx_count l3fwd eth0)
VPP_RX_BYTES=$(vpp_rx_bytes l3fwd eth0)
VPP_TX_BYTES=$(vpp_tx_bytes l3fwd eth0)

if [[ $VPP_RX_COUNT -ne $PCAP_CNT ]] ||
   [[ $VPP_TX_COUNT -ne $PCAP_CNT ]] ||
   [[ $VPP_RX_BYTES -ne $PCAP_LEN ]] ||
   [[ $VPP_TX_BYTES -ne $PCAP_LEN ]]; then
	echo "FAILURE: Error in l3fwd"
	exit 1
fi

echo "SUCCESS: l3fwd completed"

pktgen_quit
pktgen_cleanup
