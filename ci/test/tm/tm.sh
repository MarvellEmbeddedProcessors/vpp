#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

#set -e
set -euox pipefail

OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $OCTEONTESTPATH/common/vpp/vpp.env
source $OCTEONTESTPATH/common/testpmd/common.env

TPMD_TX_PORT="${TPMD_TX_PORT:-0002:01:00.5}"  # LIF1
TPMD_RX_PORT="${TPMD_RX_PORT:-0002:01:01.0}"  # LIF4

TPMD_TX_PREFIX="tpmd_tx"
TPMD_RX_PREFIX="tpmd_rx"
VPP_PREFIX="tm"
TPMD_FLOWS=4
TPMD_TX_COREMASK="${TPMD_TX_COREMASK:-0xF0}"
TPMD_RX_COREMASK="${TPMD_RX_COREMASK:-0x700}"
TM_PORT0="0002:01:00.6"  # LIF2
TM_PORT1="0002:01:00.7"  # LIF3

VFIO_DEVBIND="$OCTEONTESTPATH/board/oxk-devbind-basic.sh"
NICVF="rvu_nicvf"

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

function get_device_rx_bytes() {
    device=$1
    rxq=$2
    rx_bytes=$(grep -A 100 "device 'pci/$device':" /tmp/tm/output.txt | grep -A 2 "RX queue $rxq:" | grep -o "total bytes received *[0-9]*" | awk '{print $4}')
    echo $rx_bytes
}

function get_device_rx_packets() {
    device=$1
    rxq=$2
    rx_packets=$(grep -A 100 "device 'pci/$device':" /tmp/tm/output.txt | grep -A 2 "RX queue $rxq:" | grep -o "total packets received *[0-9]*" | awk '{print $4}')
    echo $rx_packets
}

function get_device_tx_bytes() {
    device=$1
    txq=$2
    tx_bytes=$(grep -A 100 "device 'pci/$device':" /tmp/tm/output.txt | grep -A 2 "TX queue $txq:" | grep -o "total bytes transmitted *[0-9]*" | awk '{print $4}')
    echo $tx_bytes
}

function get_device_tx_packets() {
    device=$1
    txq=$2
    tx_packets=$(grep -A 100 "device 'pci/$device':" /tmp/tm/output.txt | grep -A 2 "TX queue $txq:" | grep -o "total packets transmitted *[0-9]*" | awk '{print $4}')
    echo $tx_packets
}

function get_testpmd_rx_bps() {
	local prefix=$1
	local out=testpmd.out.$prefix

	testpmd_cmd "$prefix" "show port stats 0"
	sleep 5
	testpmd_cmd "$prefix" "show port stats 0"

	# Find the last command line and first subsequent prompt
	local cmd_line=$(grep -n "^testpmd> show port stats 0" "$out" | tail -n1 | cut -d: -f1 || true)
	local prompt_line=""
	if [[ -n "$cmd_line" ]]; then
		prompt_line=$(grep -n "^testpmd> " "$out" | awk -F: -v c="$cmd_line" '$1 > c {print $1; exit}')
	fi

	local stats_block=""
	if [[ -n "$cmd_line" && -n "$prompt_line" ]]; then
		stats_block=$(sed -n "$((cmd_line+1)),$((prompt_line-1))p" "$out")
	fi

	local rx_bps=$(echo "$stats_block" | awk '/Rx-bps:/ { for (i=1; i<=NF; i++) if ($i=="Rx-bps:") { print $(i+1); break } }' | tr -d '\r')

	echo ${rx_bps:-0}
}

#Case 1: All 4 flows active , Q0 (priority 0) expects 100% traffic.
function verify_highest_priority_queue()
{
	sleep 1
	capture_device_logs
	sleep 2
	q0=$(get_device_tx_packets "$TM_PORT1" 1)
	q1=$(get_device_tx_packets "$TM_PORT1" 2)
	q2=$(get_device_tx_packets "$TM_PORT1" 3)
	q3=$(get_device_tx_packets "$TM_PORT1" 4)

	total=$((q0 + q1 + q2 + q3))
	if [[ $total -le 0 ]]; then
		echo "TM Case-1 Failed: total packet count zero"
		exit 1
	fi

	q0_pct=$((100 * q0 / total))
	q1_pct=$((100 * q1 / total))
	q2_pct=$((100 * q2 / total))
	q3_pct=$((100 * q3 / total))

	echo "Case-1 Queue distribution: q0=$q0(${q0_pct}%) q1=$q1(${q1_pct}%) q2=$q2(${q2_pct}%) q3=$q3(${q3_pct}%) total=$total"

	# Highest priority queue should get >= 99%
	if [[ $q0_pct -ge 99 ]]; then
		echo "TM Case-1 PASSED: Highest priority queue (q0) scheduled"
		return
	fi

	echo "TM Case-1 Failed: q0_pct=${q0_pct}% < threshold=99%"
	exit 1
}

#Case 2: Flow 0 disabled, Q1 (weight 8) and Q2 (weight 1) share, ratio ~90:10
function verify_weight_ratio_q1_q2()
{
	sleep 1
	capture_device_logs
	sleep 2
	q0=$(get_device_tx_packets "$TM_PORT1" 1)
	q1=$(get_device_tx_packets "$TM_PORT1" 2)
	q2=$(get_device_tx_packets "$TM_PORT1" 3)
	q3=$(get_device_tx_packets "$TM_PORT1" 4)

	total=$((q0 + q1 + q2 + q3))
	if [[ $total -le 0 ]]; then
		echo "TM Case-2 Failed: total packet count zero"
		exit 1
	fi

	# q1 and q2 have same priority (1), weights 8:1, so expected ~90% : ~10%
	# Verify q1 >= 85% and q2 >= 8% (with some tolerance)
	q0_pct=$((100 * q0 / total))
	q1_pct=$((100 * q1 / total))
	q2_pct=$((100 * q2 / total))
	q3_pct=$((100 * q3 / total))

	echo "Case-2 Queue distribution: q0=$q0(${q0_pct}%) q1=$q1(${q1_pct}%) q2=$q2(${q2_pct}%) q3=$q3(${q3_pct}%) total=$total"

	# Pass if q1 >= 85% and q2 >= 8%, q0 and q3 should be minimal
	if [[ $q1_pct -ge 85 ]] && [[ $q2_pct -ge 8 ]] && [[ $q0_pct -le 5 ]] && [[ $q3_pct -le 5 ]]; then
		echo "TM Case-2 PASSED: Weight ratio honored (q1~90%, q2~10%)"
		return
	fi

	echo "TM Case-2 Failed: q1_pct=${q1_pct}% (expected >=85%), q2_pct=${q2_pct}% (expected >=8%)"
	exit 1
}

#Case 3: Flows 0,2 disabled, Q1 (weight 8, priority 1) get scheduled with 100% traffic
function verify_single_midprio_queue()
{
	sleep 1
	capture_device_logs
	sleep 2
	q0=$(get_device_tx_packets "$TM_PORT1" 1)
	q1=$(get_device_tx_packets "$TM_PORT1" 2)
	q2=$(get_device_tx_packets "$TM_PORT1" 3)
	q3=$(get_device_tx_packets "$TM_PORT1" 4)

	total=$((q0 + q1 + q2 + q3))
	if [[ $total -le 0 ]]; then
		echo "TM Case-3 Failed: total packet count zero"
		exit 1
	fi

	q0_pct=$((100 * q0 / total))
	q1_pct=$((100 * q1 / total))
	q2_pct=$((100 * q2 / total))
	q3_pct=$((100 * q3 / total))

	echo "Case-3 Queue distribution: q0=$q0(${q0_pct}%) q1=$q1(${q1_pct}%) q2=$q2(${q2_pct}%) q3=$q3(${q3_pct}%) total=$total"

	# Only mid-priority queue active should get >= 99%
	if [[ $q1_pct -ge 99 ]]; then
		echo "TM Case-3 PASSED: Only mid-priority queue (q1) scheduled"
		return
	fi

	echo "TM Case-3 Failed: q1_pct=${q1_pct}% < threshold=99%"
	exit 1
}

#Case 4: Flows 0,1,2 disabled, Q3 (priority 2, lowest) gets scheduled with 100% traffic
function verify_lowest_priority_queue()
{
	sleep 1
	capture_device_logs
	sleep 2
	q0=$(get_device_tx_packets "$TM_PORT1" 1)
	q1=$(get_device_tx_packets "$TM_PORT1" 2)
	q2=$(get_device_tx_packets "$TM_PORT1" 3)
	q3=$(get_device_tx_packets "$TM_PORT1" 4)

	total=$((q0 + q1 + q2 + q3))
	if [[ $total -le 0 ]]; then
		echo "TM Case-4 Failed: total packet count zero"
		exit 1
	fi

	q0_pct=$((100 * q0 / total))
	q1_pct=$((100 * q1 / total))
	q2_pct=$((100 * q2 / total))
	q3_pct=$((100 * q3 / total))

	echo "Case-4 Queue distribution: q0=$q0(${q0_pct}%) q1=$q1(${q1_pct}%) q2=$q2(${q2_pct}%) q3=$q3(${q3_pct}%) total=$total"

	# Lowest priority queue should get >= 99% when it's the only one with traffic
	if [[ $q3_pct -ge 99 ]]; then
		echo "TM Case-4 PASSED: Lowest priority queue (q3) scheduled"
		return
	fi

	echo "TM Case-4 Failed: q3_pct=${q3_pct}% < threshold=99%"
	exit 1
}

function run_scheduler_tests()
{
	echo "=========================================="
	echo "Running TM Scheduler Test Cases"
	echo "=========================================="

	vpp_exec_cmd $VPP_PREFIX "clear trace"
	vpp_exec_cmd $VPP_PREFIX "trace add eth0-rx 2"

	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	echo "=============================================================="
	echo "VPP Packet Trace(Flow setup is based of the packets generated)"
	echo "=============================================================="
	vpp_exec_cmd $VPP_PREFIX "show trace"
	echo "=============================================================="
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"

	VPP_RX_COUNT=$(vpp_rx_count $VPP_PREFIX eth0)
	VPP_TX_COUNT=$(vpp_tx_count $VPP_PREFIX eth1)
	VPP_RX_BYTES=$(vpp_rx_bytes $VPP_PREFIX eth0)
	VPP_TX_BYTES=$(vpp_tx_bytes $VPP_PREFIX eth1)

	if [[ $VPP_RX_COUNT -le 0 ]] || [[ $VPP_TX_COUNT -le 0 ]]; then
		echo "FAILURE: No packets processed by VPP"
		exit 1
	fi

	# Case 1: All 4 flows active, highest priority queue (q0) gets scheduled
	echo "Running Case-1: Verify highest priority queue (q0) with all flows active"
	verify_highest_priority_queue

	# Case 2: Disable flow 0, q1 and q2 share based on weights (8:1)
	echo ""
	echo "Running Case-2: Drop flow-0 traffic, verify weight ratio (q1~90%, q2~10%)"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 0 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.0 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 0 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	verify_weight_ratio_q1_q2

	# Case 3: Disable flows 0,2. Q1 gets scheduled (only mid-priority queue with traffic)
	echo ""
	echo "Running Case-3: Drop flows 0,2, verify q1 gets scheduled"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.2 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	verify_single_midprio_queue

	# Case 4: Disable flows 0,1,2. Q3 gets scheduled (lowest priority)
	echo ""
	echo "Running Case-4: Drop flows 0,1,2, verify lowest priority queue (q3)"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 1 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.1 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 1 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	verify_lowest_priority_queue

	echo ""
	echo "=========================================="
	echo "SUCCESS: All TM scheduler test cases PASSED"
	echo "=========================================="
}

function run_shaper_tests()
{
	echo "=========================================="
	echo "Running TM Shaper Test Cases"
	echo "=========================================="

	# Case 1: All 4 queues active, total bandwidth limited to ~400 Mbps (5% tolerance: 380-420 Mbps)
	echo "Running Shaper Case-1: Verify total bandwidth limited to ~400 Mbps with all queues active"

	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_RX_PREFIX" "clear port stats all"

	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	rx_bps=$(get_testpmd_rx_bps "$TPMD_RX_PREFIX")
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"

	if [[ -z "$rx_bps" || "$rx_bps" -le 0 ]]; then
		echo "TM Shaper Case-1 Failed: Unable to get RX bandwidth"
		exit 1
	fi

	rx_mbps=$((rx_bps / 1000000))

	echo "Shaper Case-1: RX bandwidth = ${rx_mbps} Mbps"

	if [[ $rx_mbps -ge 380 && $rx_mbps -le 420 ]]; then
		echo "TM Shaper Case-1 PASSED: Bandwidth limited to ~400 Mbps (actual: ${rx_mbps} Mbps)"
	else
		echo "TM Shaper Case-1 Failed: Expected ~400 Mbps, got ${rx_mbps} Mbps"
		exit 1
	fi

	# Case 2: Flow 0,1,2 active, Flow 3 stopped, Total bandwidth ~400 Mbps
	echo ""
	echo "Running Shaper Case-2: Stop Flow-3 (txq-3), verify bandwidth ~400 Mbps"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 3 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.3 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 3 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_RX_PREFIX" "clear port stats all"

	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10
	rx_bps=$(get_testpmd_rx_bps "$TPMD_RX_PREFIX")
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"

	if [[ -z "$rx_bps" || "$rx_bps" -le 0 ]]; then
		echo "TM Shaper Case-2 Failed: Unable to get RX bandwidth"
		exit 1
	fi

	rx_mbps=$((rx_bps / 1000000))
	echo "Shaper Case-2: RX bandwidth = ${rx_mbps} Mbps"

	if [[ $rx_mbps -ge 380 && $rx_mbps -le 420 ]]; then
		echo "TM Shaper Case-2 PASSED: Bandwidth limited to ~400 Mbps (actual: ${rx_mbps} Mbps)"
	else
		echo "TM Shaper Case-2 Failed: Expected ~400 Mbps, got ${rx_mbps} Mbps"
		exit 1
	fi

	# Case 3: Only Flow 1 active (Flow 0,2,3 stopped), Total bandwidth ~200 Mbps (5% tolerance: 190-210 Mbps)
	echo ""
	echo "Running Shaper Case-3: Only Flow-1 active, verify bandwidth ~200 Mbps"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 0 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.0 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 0 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.2 proto udp drop"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_RX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10

	rx_bps=$(get_testpmd_rx_bps "$TPMD_RX_PREFIX")
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"

	if [[ -z "$rx_bps" || "$rx_bps" -le 0 ]]; then
		echo "TM Shaper Case-3 Failed: Unable to get RX bandwidth"
		exit 1
	fi

	rx_mbps=$((rx_bps / 1000000))
	echo "Shaper Case-3: RX bandwidth = ${rx_mbps} Mbps"

	if [[ $rx_mbps -ge 190 && $rx_mbps -le 210 ]]; then
		echo "TM Shaper Case-3 PASSED: Bandwidth limited to ~200 Mbps (actual: ${rx_mbps} Mbps)"
	else
		echo "TM Shaper Case-3 Failed: Expected ~200 Mbps, got ${rx_mbps} Mbps"
		exit 1
	fi

	# Case 4: Flow 1,2,3 active, Flow 0 stopped, Total bandwidth ~200 Mbps
	echo ""
	echo "Running Shaper Case-4: Flow-1,2,3 active (Flow-0 stopped), verify bandwidth ~200 Mbps"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.2 proto udp redirect-to-queue 2"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 2 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow del index 3 eth0"
	vpp_exec_cmd $VPP_PREFIX "test flow add dst-ip 10.253.0.3 proto udp redirect-to-queue 3"
	vpp_exec_cmd $VPP_PREFIX "test flow enable index 3 eth0"
	vpp_exec_cmd $VPP_PREFIX "show flow entry"
	sleep 2
	vpp_exec_cmd $VPP_PREFIX "clear hardware-interfaces"
	testpmd_cmd "$TPMD_TX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_RX_PREFIX" "clear port stats all"
	testpmd_cmd "$TPMD_TX_PREFIX" "start"
	sleep 10

	rx_bps=$(get_testpmd_rx_bps "$TPMD_RX_PREFIX")
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"

	if [[ -z "$rx_bps" || "$rx_bps" -le 0 ]]; then
		echo "TM Shaper Case-4 Failed: Unable to get RX bandwidth"
		exit 1
	fi

	rx_mbps=$((rx_bps / 1000000))
	echo "Shaper Case-4: RX bandwidth = ${rx_mbps} Mbps"

	if [[ $rx_mbps -ge 190 && $rx_mbps -le 210 ]]; then
		echo "TM Shaper Case-4 PASSED: Bandwidth limited to ~200 Mbps (actual: ${rx_mbps} Mbps)"
	else
		echo "TM Shaper Case-4 Failed: Expected ~200 Mbps, got ${rx_mbps} Mbps"
		exit 1
	fi

	echo ""
	echo "=========================================="
	echo "SUCCESS: All TM shaper test cases PASSED"
	echo "=========================================="
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
		vpp_stats_all $VPP_PREFIX
		echo $status
		echo "$1 Handler"
	fi
	testpmd_quit "$TPMD_TX_PREFIX" || true
	testpmd_quit "$TPMD_RX_PREFIX" || true
	# Restore interface drivers if we re-bound them
	#cleanup_interfaces || true
	testpmd_cleanup "$TPMD_TX_PREFIX"
	testpmd_cleanup "$TPMD_RX_PREFIX"
	vpp_cleanup $VPP_PREFIX
	exit $status
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "dev bind $TM_PORT0 $TM_PORT1 $TPMD_TX_PORT $TPMD_RX_PORT"

	$VFIO_DEVBIND -b vfio-pci $TM_PORT0
	$VFIO_DEVBIND -b vfio-pci $TM_PORT1
	$VFIO_DEVBIND -b vfio-pci $TPMD_TX_PORT
	$VFIO_DEVBIND -b vfio-pci $TPMD_RX_PORT
}

function cleanup_interfaces()
{
	# Bind the vfio-pci binded devices back to nicvf
	$VFIO_DEVBIND -b $NICVF $TM_PORT0
	$VFIO_DEVBIND -b $NICVF $TM_PORT1
	$VFIO_DEVBIND -b $NICVF $TPMD_TX_PORT
	$VFIO_DEVBIND -b $NICVF $TPMD_RX_PORT
}

function pmd_rx_launch()
{
	echo "Launching testpmd RX ($TPMD_RX_PREFIX) on $TPMD_RX_PORT"
	testpmd_launch "$TPMD_RX_PREFIX" \
		"-c $TPMD_RX_COREMASK -a $TPMD_RX_PORT,disable_xqe_drop=1" \
		"--nb-cores=1 --forward-mode=rxonly"
	testpmd_cmd "$TPMD_RX_PREFIX" "port stop 0"
	testpmd_cmd "$TPMD_RX_PREFIX" "set flow_ctrl rx off 0"
	testpmd_cmd "$TPMD_RX_PREFIX" "set flow_ctrl tx off 0"
	testpmd_cmd "$TPMD_RX_PREFIX" "port start 0"
}

function pmd_tx_launch()
{
	echo "Launching testpmd TX ($TPMD_TX_PREFIX) on $TPMD_TX_PORT generating $TPMD_FLOWS flows"
	testpmd_launch "$TPMD_TX_PREFIX" \
		"-c $TPMD_TX_COREMASK -a $TPMD_TX_PORT,disable_xqe_drop=1" \
		"--nb-cores=3 --forward-mode=flowgen --flowgen-flows=$TPMD_FLOWS --txq=4 --rxq=4"
	testpmd_cmd "$TPMD_TX_PREFIX" "port stop 0"
	testpmd_cmd "$TPMD_TX_PREFIX" "set flow_ctrl rx off 0"
	testpmd_cmd "$TPMD_TX_PREFIX" "set flow_ctrl tx off 0"
	testpmd_cmd "$TPMD_TX_PREFIX" "port start 0"
	testpmd_cmd "$TPMD_TX_PREFIX" "set port 0 queue 0 rate 50000"
	testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts 1400"
}

function vpp_create_interfaces()
{
	echo "Creating VPP interfaces at runtime"
	vpp_exec_cmd $VPP_PREFIX "device attach pci/$TM_PORT0 driver octeon"
	vpp_exec_cmd $VPP_PREFIX "device create-interface pci/$TM_PORT0 port 0 name eth0 num-rx-queues 4"
	vpp_exec_cmd $VPP_PREFIX "device attach pci/$TM_PORT1 driver octeon"
	vpp_exec_cmd $VPP_PREFIX "device create-interface pci/$TM_PORT1 port 0 name eth1 num-rx-queues 4"
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

mount_hugetlbfs
setup_hp

echo "=========================================="
echo "VPP Traffic Manager (TM) Test Suite"
echo "=========================================="

echo "Required devices for test:"
echo "  TM_PORT0=$TM_PORT0"
echo "  TM_PORT1=$TM_PORT1"
echo "  TPMD_TX_PORT=$TPMD_TX_PORT"
echo "  TPMD_RX_PORT=$TPMD_RX_PORT"
echo ""

setup_interfaces

echo "Launching VPP with Port0=$TM_PORT0 and Port1=$TM_PORT1"
rm -rf /tmp/tm
mkdir -p /tmp/tm
cp tm_scheduler.exec /tmp/tm/tm.exec
vpp_launch $VPP_PREFIX
vpp_create_interfaces
vpp_start $VPP_PREFIX

pmd_rx_launch
pmd_tx_launch

# Run scheduler test cases
run_scheduler_tests

echo ""
echo "=========================================="
echo "Stopping VPP for Shaper Tests"
echo "=========================================="

# Stop VPP
vpp_cleanup $VPP_PREFIX
sleep 3
echo ""
echo "=========================================="
echo "Relaunching VPP with Shaper Configuration"
echo "=========================================="

# Copy shaper exec file and relaunch VPP
cp tm_shaper.exec /tmp/tm/tm.exec
vpp_launch $VPP_PREFIX
vpp_create_interfaces
vpp_start $VPP_PREFIX

# Run shaper test cases
run_shaper_tests

echo ""
echo "=========================================="
echo "SUCCESS: All TM test cases completed"
echo "=========================================="

testpmd_quit "$TPMD_TX_PREFIX"
testpmd_quit "$TPMD_RX_PREFIX"
testpmd_cleanup "$TPMD_TX_PREFIX"
testpmd_cleanup "$TPMD_RX_PREFIX"
