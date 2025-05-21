#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html


set -e
#set -euox pipefail

GENERATOR_BOARD=${GENERATOR_BOARD:-}
PLAT=${PLAT:-}
OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
VFIO_DEVBIND="$OCTEONTESTPATH/board/oxk-devbind-basic.sh"

source $OCTEONTESTPATH/common/testpmd/common.env
source $OCTEONTESTPATH/common/vpp/vpp.env

# Find the dpdk-testpmd application

TESTPMD_BIN=$(which dpdk-testpmd)
if [[ -z $TESTPMD_BIN ]]; then
	echo "dpdk-testpmd not found !!"
	exit 1
fi
echo $TESTPMD_BIN
declare -i num_tests
declare -a test_name
declare -a test_lbk
SUDO="sudo"
remote_ssh="${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"} $GENERATOR_BOARD"
gen=$(realpath ./l3fwd_gen.sh)
MAX_RETRY=${MAX_RETRY:-5}
WITH_GEN_BOARD=0
GEN_ARG=
G_ENV=
TOLERANCE=${TOLERANCE:-6}

FWD_PERF_IN=fwd_perf.in
FWD_PERF_OUT=fwd_perf.out
FWD_PERF_OUT_FULL=fwd_perf.out.full
GEN_LOG_FULL=gen.out.full

START_STR=">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
END_STR="<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"

LIF0=0002:01:00.1
LIF1=0002:01:00.2

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

if [[ -z "$GENERATOR_BOARD" ]]; then
	echo "Generator board details missing!!"
	WITH_GEN_BOARD=0
else
	echo "Found Generator board details $GENERATOR_BOARD"
	if [[ $IS_CN10K -ne 0 ]]; then
		WITH_GEN_BOARD=1
	fi
fi

if [[ $WITH_GEN_BOARD -eq 0 ]]
then
	IF0=$LIF0
	IF1=$LIF1
	remote_ssh="sh -c "
	GEN_PORT=$IF1
	G_ENV="GEN_CORES=6"
	SUDO=""
	echo "Running locally without generator board"
else
	IF0=0002:02:00.0
	GEN_PORT=$IF0
	$VFIO_DEVBIND -b vfio-pci $IF0
	# Dummy whitelist device
	IF1=0008:08:08.0
	echo "Running with generator board"
fi

rm -rf $FWD_PERF_IN $FWD_PERF_OUT $FWD_PERF_OUT_FULL $GEN_LOG_FULL

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
	fi

	awk ' { print FILENAME": " $0 } ' $FWD_PERF_OUT_FULL
	awk ' { print FILENAME": " $0 } ' $FWD_PERF_OUT
	awk ' { print FILENAME": " $0 } ' $GEN_LOG_FULL

	killall -9 dpdk-testpmd
	$remote_ssh "sudo killall -9 dpdk-testpmd"
	vpp_log l3fwd_perf
	vpp_stats_all l3fwd_perf
	vpp_cleanup l3fwd_perf
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# Get CPU PART NUMBER
PARTNUM_106XX=0xd49
PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | awk -F': ' '{print $2}')
DTC=$(tr -d '\0' </proc/device-tree/model | awk '{print $2}')

if [[ $DTC == "CN103XX" ]]; then
	CORES=0x0000ff
else
	CORES=0xff0000
fi

if [[ $PARTNUM == $PARTNUM_106XX ]]; then
	if [[ $DTC == "CN103XX" ]]; then
		HW="cn103"
	else
		HW="cn106"
	fi
else
	HW="cn96"
fi

# get chip number and RCLK
function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
	if [[ $PARTNUM == $PARTNUM_106XX ]]; then
		fp_rclk="$sysclk_dir/coreclk/clk_rate"
	else
		fp_rclk="$sysclk_dir/rclk/clk_rate"
	fi

	fp_sclk="$sysclk_dir/sclk/clk_rate"

	if $SUDO test -f "$fp_rclk"; then
		RCLK=$(echo "`$SUDO cat $fp_rclk` / $div" | bc)
	else
		echo "$fp_rclk not available"
		exit 1
	fi

	if $SUDO test -f "$fp_sclk"; then
		SCLK=$(echo "`$SUDO cat $fp_sclk` / $div" | bc)
	else
		echo "$fp_sclk not available"
		exit 1
	fi

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
}

register_fwd_test() {
        test_name[$num_tests]=$1
        test_ncores[$num_tests]=$2
	test_lbk[$num_tests]=$3
        ((num_tests+=1))
}

expected_pps() {
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}"."l3fwd
	FPATH="$OCTEONTESTPATH/l3fwd_perf/ref_numbers/$FNAME"
	if [[ ! -f $FPATH ]]; then echo 'Err: ref file missing !!'; exit 1; fi

	pps_gold=$(grep "${test_name[$1]}" $FPATH \
			| tr -s ' ' | cut -d " " -f 2)
	echo "($pps_gold * (100 - $TOLERANCE)) / 100" | bc
}

ref_pps() {
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}"."l3fwd
	FPATH="$OCTEONTESTPATH/l3fwd_perf/ref_numbers/$FNAME"
	if [[ ! -f $FPATH ]]; then echo 'Err: ref file missing !!'; exit 1; fi

	pps_gold=$(grep "${test_name[$1]}" $FPATH \
			| tr -s ' ' | cut -d " " -f 2)
	echo $pps_gold
}

launch_gen() {
	echo $START_STR ${test_name[$1]} >>$GEN_LOG_FULL
	$remote_ssh "$SUDO PORT0=$GEN_PORT TEST_OP=launch $G_ENV GEN_FLOWS=$CORES $gen $GEN_ARG"
}

start_gen() {
	$remote_ssh "$SUDO PLAT=$PLAT PORT0=$GEN_PORT TEST_OP=start $gen"
}

stop_gen() {
	$remote_ssh "$SUDO PLAT=$PLAT PORT0=$GEN_PORT TEST_OP=stop $gen"
}

cleanup_gen() {
	$remote_ssh "$SUDO PLAT=$PLAT PORT0=$GEN_PORT TEST_OP=log $gen" >>$GEN_LOG_FULL
	echo $END_STR ${test_name[$idx]} >>$GEN_LOG_FULL

	$remote_ssh "$SUDO PLAT=$PLAT PORT0=$GEN_PORT TEST_OP=cleanup $gen"
}

testpmd_pps_local() {
	local rx_pps=0

	echo "show port stats all" >>$FWD_PERF_IN
	sleep 1
	echo "show port stats all" >>$FWD_PERF_IN
	sleep 1
	echo "show port stats all" >>$FWD_PERF_IN
	while ! (tail -n1 $FWD_PERF_OUT | grep -q "testpmd> $")
	do
		sleep 0.1
		continue;
	done

	pps=`cat $FWD_PERF_OUT | \
		grep "Rx-pps:" | awk '{print $2}' | tail -2`
	for i in $pps
	do
		rx_pps=$((rx_pps + i))
	done
	echo $rx_pps
}

check_pps() {
	idx=$1
	pass_pps=$(expected_pps $idx)
	ref_pps=$(ref_pps $idx)
	local retry=3

	while [[ retry -ne 0 ]]
	do

		rx_pps=$($remote_ssh "$SUDO TEST_OP=rx_pps $gen")

		if [[ rx_pps -lt pass_pps ]]; then
			echo -n "Low PPS for ${test_name[$idx]} ($rx_pps < $pass_pps)"
			echo " (Ref $ref_pps, tolerance $TOLERANCE%)"
		else
			echo -n "Rx PPS $rx_pps as expected $pass_pps"
			echo " (Ref $ref_pps, tolerance $TOLERANCE%)"
			return 0
		fi

		sleep 1
		((retry-=1))
	done

	return 1
}

cleanup_one() {
	local idx=$1

	vpp_log l3fwd_perf
	vpp_stats_all l3fwd_perf
	vpp_cleanup l3fwd_perf

	stop_gen
	cleanup_gen $idx

	cat $FWD_PERF_OUT >> $FWD_PERF_OUT_FULL
	echo $END_STR ${test_name[$idx]} >>$FWD_PERF_OUT_FULL
}

run_one() {
	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=
	local in=$FWD_PERF_IN
	local out=$FWD_PERF_OUT
	idx=$1

	echo $START_STR ${test_name[$idx]} >>$FWD_PERF_OUT_FULL

	rm -rf $in $out
	touch $in $out

	CORES=${test_ncores[$idx]}

	echo -n "Starting l3fwd with 'n_cores=$CORES  port=$IF0 "
	rm -rf /tmp/l3fwd_perf
	mkdir -p /tmp/l3fwd_perf
	cp l3fwd_perf_$CORES.conf /tmp/l3fwd_perf/
	cp l3fwd_perf.exec /tmp/l3fwd_perf
	vpp_launch l3fwd_perf_$CORES
	vpp_exec_cmd l3fwd_perf "device attach pci/$IF0 driver octeon"
	vpp_exec_cmd l3fwd_perf "device create-interface pci/$IF0 port 0 name eth0 num-rx-queues $CORES tx-queues-size 16384"
	vpp_start l3fwd_perf
	for (( i=0; i<$CORES; i++ ))
	do
		vpp_exec_cmd l3fwd_perf "set ip neighbor eth0 10.253.0.$i 00:01:02:03:04:00"
		vpp_exec_cmd l3fwd_perf "test flow add dst-ip 10.253.0.$i/255.255.255.255 proto 17 redirect-to-queue $i"
		vpp_exec_cmd l3fwd_perf "test flow enable index $i eth0"
	done

	launch_gen $idx
	start_gen
}

run_fwd_tests() {

	get_system_info

	idx=0
	ret=0
	REF_WITH_GEN_BOARD=$WITH_GEN_BOARD
	REF_IF0=$IF0
	REF_IF1=$IF1
	local retry_count=$MAX_RETRY
	while [[ idx -lt num_tests ]]; do

		if [[ ${test_lbk[$idx]} -eq 1 ]]; then
		# Forcing change to run on LBK interface only
			WITH_GEN_BOARD=0
			IF0=$LIF0
			IF1=$LIF1
		else
			# Restore for other cases
			WITH_GEN_BOARD=$REF_WITH_GEN_BOARD
			IF0=$REF_IF0
			IF1=$REF_IF1
		fi

		run_one $idx

		sleep 3

		set +e
		check_pps $idx
		local k=$?
		set -e

		if [[ k -eq 0 ]]; then
			cleanup_one $idx

			((idx+=1))
			retry_count=$MAX_RETRY
			continue
		fi
		((retry_count-=1)) || true

		if [[ retry_count -eq 0 ]]; then
			echo "FAIL: ${test_name[$idx]}"
			cleanup_one $idx

			((ret+=1))
			((idx+=1))
			retry_count=$MAX_RETRY
		else
			echo "Re-run ${test_name[$idx]} $retry_count"
			cleanup_one $idx
		fi
	done

	exit $ret
}

num_tests=0

# Register fwd performance tests.
# Format:	<test name>	<number of cores>     <test LBK-IFs>

register_fwd_test "L3FWD_1C" "1" "0"
register_fwd_test "L3FWD_2C" "2" "0"
register_fwd_test "L3FWD_4C" "4" "0"
register_fwd_test "L3FWD_8C" "8" "0"

run_fwd_tests

cleanup_gen
