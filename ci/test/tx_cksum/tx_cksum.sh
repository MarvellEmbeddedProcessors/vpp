#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

#set -e
set -euox pipefail

PRFX="tx_cksum"
OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $OCTEONTESTPATH/common/vpp/vpp.env
source $OCTEONTESTPATH/common/testpmd/pktgen.env
source $OCTEONTESTPATH/common/pcap/pcap.env

TX_PCAP="in.pcap"
EXPECTED_PCAP="out.pcap"
TX_MSEG_PCAP="in_mseg.pcap"
EXPECTED_MSEG_PCAP="out_mseg.pcap"
RECV_PCAP="recv.pcap"
PKTGEN_PORT="0002:01:00.1"
PKTGEN_COREMASK="0xf0"
PORT0="0002:01:00.2"
PORT1="0002:01:00.3"
MAINCORE="0x2"
WORKER_COREMASK="0x4"
CONF_FILE="tx_cksum.conf"
INLINE_CONF_FILE="tx_cksum_inline.conf"

TMP_DIR=/tmp/$PRFX
rm -rf $TMP_DIR
mkdir -p $TMP_DIR

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
		vpp_stats_all tx_cksum
		echo $status
		echo "$1 Handler"
	fi
	pktgen_quit
	pktgen_cleanup
	vpp_cleanup tx_cksum
	exit $status
}


trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

mount_hugetlbfs
setup_hp

run_tx_cksum_test() {
	local CONF_PRFX=$1
	CONF_FILE="${CONF_PRFX}.conf"
	echo "Starting VPP with Port0=$PORT0, Conf: $CONF_FILE"
	cp tx_cksum.exec /tmp/tx_cksum/
	vpp_launch $CONF_PRFX
	vpp_start $PRFX
	sleep 2

	echo "Starting pktgen with Port=$PKTGEN_PORT, Coremask=$PKTGEN_COREMASK, In-pcap=$TX_PCAP, received-pcap=$RECV_PCAP"
	pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $TX_PCAP -o $RECV_PCAP
	sleep 2
	testpmd_cmd "pktgen" "port stop all"
	testpmd_cmd "pktgen" "port config mtu 0 9000"
	testpmd_cmd "pktgen" "port start all"
	sleep 2
	echo "pktgen start"
	pktgen_start
	sleep 5

	vpp_port_down $PRFX eth0

	vpp_stats_all $PRFX > /dev/null
	pktgen_stats > /dev/null

	echo "-------------------- TX_CKSUM VPP LOGS ---------------------"
	vpp_log $PRFX
	echo "-------------------- TX_CKSUM PKTGEN LOGS --------------------"
	pktgen_log

	echo "Verifying tx_cksum test"

	VPP_RX_COUNT=$(vpp_rx_count $PRFX eth0)
	VPP_TX_COUNT=$(vpp_tx_count $PRFX eth0)
	VPP_RX_BYTES=$(vpp_rx_bytes $PRFX eth0)
	VPP_TX_BYTES=$(vpp_tx_bytes $PRFX eth0)

	if [[ $VPP_RX_COUNT -ne $PCAP_CNT ]] ||
	   [[ $VPP_TX_COUNT -ne $PCAP_CNT ]] ||
	   [[ $VPP_RX_BYTES -ne $PCAP_LEN ]] ||
	   [[ $VPP_TX_BYTES -ne $PCAP_LEN ]]; then
		echo "FAILURE: Error in tx_cksum"
		exit 1
	fi

	tcpdump -nr $EXPECTED_PCAP -xvve -t >$TMP_DIR/expect.txt
	tcpdump -nr $RECV_PCAP -xvve -t >$TMP_DIR/recv.txt

	# Compare received and expected
	diff -sqad $TMP_DIR/recv.txt $TMP_DIR/expect.txt

	pktgen_quit
	echo "########## SUCCESS: tx_cksum test completed ##########"
	echo "  Used TX_PCAP: $TX_PCAP"
	echo "  Used EXPECTED_PCAP: $EXPECTED_PCAP"
	echo "  Used CONF_FILE: $CONF_FILE"
	echo "######################################################"
}

run_all_tests() {
	local TX_PCAP=$1
	local EXPECTED_PCAP=$2

	PCAP_CNT=$(pcap_packet_count $TX_PCAP)
	PCAP_LEN=$(pcap_length $TX_PCAP)

	export TX_PCAP
	export EXPECTED_PCAP
	export PCAP_CNT
	export PCAP_LEN

	# TEST-1: Run without inline device in startup.conf
	if [[ -f "$CONF_FILE" ]]; then
		run_tx_cksum_test "tx_cksum"
		sleep 1
		vpp_cleanup tx_cksum
		sleep 1
		pktgen_cleanup
	else
		echo "Startup config file $CONF_FILE not found!"
	fi

	sleep 10

	# TEST-2: Run with inline device in startup.conf
	if [[ -f "$INLINE_CONF_FILE" ]]; then
		run_tx_cksum_test "tx_cksum_inline"
		sleep 1
		vpp_cleanup tx_cksum_inline
		sleep 1
		pktgen_cleanup
	else
		echo "Inline config file $INLINE_CONF_FILE not found!"
	fi
}

#Run with single-seg pcap
run_all_tests "$TX_PCAP" "$EXPECTED_PCAP"

sleep 10

#Run with multi-seg pcap
run_all_tests "$TX_MSEG_PCAP" "$EXPECTED_MSEG_PCAP"
