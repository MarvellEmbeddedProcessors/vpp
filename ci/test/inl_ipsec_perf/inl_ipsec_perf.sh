#!/bin/bash
# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

#set -e
set -euox pipefail

GENERATOR_BOARD=${GENERATOR_BOARD:-}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}
OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
PKT_LIST="64 380 1410"
NUM_CAPTURE=3
MAX_TRY_CNT=5
CORES=(1 2 4)
COREMASK="0x10000"
TXWAIT=15
RXWAIT=5
WS=2
IS_RXPPS_TXTPMD=0

function core_index()
{
	local core=$1
	local idx=0
	local c

	for c in ${CORES[@]}
	do
		if [[ "$c" == "$core" ]]; then
			echo "$idx"
			return 0
		fi
		((++idx))
	done

	echo "ERROR: core_index: core '$core' not found in CORES='${CORES[*]}'" >&2
	return 1
}
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"}
TARGET_SSH_CMD="$TARGET_SSH_CMD -n"
GENERATOR_SCRIPT=${GENERATOR_SCRIPT:-inl_ipsec_gen.sh}
WITH_GEN_BOARD=0

source $OCTEONTESTPATH/common/testpmd/pktgen.env
source $OCTEONTESTPATH/common/testpmd/common.env
source $OCTEONTESTPATH/common/vpp/vpp.env

TPMD_RX_PREFIX="tpmd_rx"
TPMD_TX_PREFIX="tpmd_tx"

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_PPS_TABLE
SUDO="sudo"

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?
DTC=$(tr -d '\0' </proc/device-tree/model | awk '{print $2}')
CORE_NUM=16


if [[ $IS_CN10K -ne 0 ]]; then
	if [[ $DTC == "CN103XX" ]]; then
		HW="103xx"
		CORE_NUM=7
		COREMASK="0x80"
	else
		HW="106xx"
	fi
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk '{ print $1 }')
	INLINE_DEV=0002:1d:00.0
else
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		HW="98xx"
	else
		HW="96xx"
	fi
	CDEV_VF=$(lspci -d :a0fe | head -1 | awk '{ print $1 }')
fi

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

CFG=(
	# Inline protocol Outbound config files
	"aes_cbc_sha1_hmac.cfg"
	"aes_gcm.cfg"
)

#Inline Protocol inbound specific config files
IP_IB_CFG=(
	"aes_cbc_sha1_hmac_ib.cfg"
	"aes_gcm_ib.cfg"
)

TYPE=(
	"ip"
	"ip"
)

TN=(
	"Inline Protocol: "
	"Inline Protocol: "
)

NB_TYPES=${#TYPE[@]}

function assert_arr_len()
{
	local name=$1
	local -n arr=$name
	local arr_len=${#arr[@]}

	if [[ $arr_len -ne $NB_TYPES ]]; then
		echo "'$name' array($arr_len) should be same length as 'TYPE' array($NB_TYPES)"
		exit 1
	fi
}

assert_arr_len CFG
assert_arr_len IP_IB_CFG
assert_arr_len TN

Failed_tests=""

LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

VFIO_DEVBIND="$OCTEONTESTPATH/board/oxk-devbind-basic.sh"

if [[ -z "$GENERATOR_BOARD" ]]; then
	echo "Generator board details missing!!"
	WITH_GEN_BOARD=0
else
	echo "Found Generator board details $GENERATOR_BOARD"
	if [[ $IS_CN10K -ne 0 ]]; then
		WITH_GEN_BOARD=1
	fi
fi

if [[ $WITH_GEN_BOARD -eq 1 ]]
then
	IF0=0002:02:00.0
	IF1=0002:03:00.0
	echo "Inline Protocol tests will run with generator board"
	$VFIO_DEVBIND -b vfio-pci $IF0
	$VFIO_DEVBIND -b vfio-pci $IF1
else
	IF0=$LIF2
	IF1=$LIF3
	echo "All tests will run locally without generator board"
fi

function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local fp_cptclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
if [[ $IS_CN10K -ne 0 ]]; then
	fp_rclk="$sysclk_dir/coreclk/clk_rate"
else
	fp_rclk="$sysclk_dir/rclk/clk_rate"
	fp_cptclk="$sysclk_dir/cptclk/clk_rate"
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

if [[ $IS_CN10K -ne 0 ]]; then
	echo "CORECLK:   $RCLK Mhz"
	echo "SCLK:      $SCLK Mhz"
	return
fi
	if $SUDO test -f "$fp_cptclk"; then
		CPTCLK=$(echo "`$SUDO cat $fp_cptclk` / $div" | bc)
	else
		echo "$fp_cptclk not available"
		exit 1
	fi

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
	echo "CPTCLK: $CPTCLK Mhz"
}

function is_single_sa_test()
{
	local type=${TYPE[$Y]}
	local sa_tests=(ip)

	[[ " ${sa_tests[*]} " =~ " $type " ]]
}

function supported_by_9k()
{
	local type=$1
	local supported=(lc lp lp_e ip)

	[[ " ${supported[*]} " =~ " $type " ]]
}

function run_vpp_ipsec()
{
	local i
	local mode=${2:-"itf"}
	n_CORES=$1
	echo "vpp outb num_cores:$n_CORES mode:$mode"
	IS_RXPPS_TXTPMD=1
	rm -rf /tmp/inl_ipsec_perf
	mkdir -p /tmp/inl_ipsec_perf
	cp inl_ipsec_perf_$n_CORES.conf /tmp/inl_ipsec_perf/
	cp ${CFG[$Y]} /tmp/inl_ipsec_perf/

	# Inline Protocol
	vpp_launch inl_ipsec_perf_$n_CORES
	vpp_exec_cmd inl_ipsec_perf "device attach pci/$IF0 driver octeon"
	vpp_exec_cmd inl_ipsec_perf "device create-interface pci/$IF0 port 0 name eth0 num-rx-queues 8 tx-queues-size 16384"
	vpp_exec_cmd inl_ipsec_perf "device attach pci/$IF1 driver octeon"
	vpp_exec_cmd inl_ipsec_perf "device create-interface pci/$IF1 port 0 name eth1 num-rx-queues 8 tx-queues-size 16384"
	vpp_exec_file inl_ipsec_perf /tmp/inl_ipsec_perf/${CFG[$Y]}

	for (( i=0; i<$n_CORES; i++ ))
	do
		# Determine if transport mode
		local is_transport=0
		if [[ "$mode" == "policy_transport" ]]; then
			is_transport=1
		fi

		if [[ $Y == 0 ]]; then
			if [[ $is_transport -eq 1 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
			else
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 tunnel src $((i+1)).1.1.1 dst $((i+1)).1.1.2 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 tunnel src $((i+1)).1.1.2 dst $((i+1)).1.1.1"
			fi
		else
			if [[ $is_transport -eq 1 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128"
			else
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 tunnel src $((i+1)).1.1.1 dst $((i+1)).1.1.2 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 tunnel src $((i+1)).1.1.2 dst $((i+1)).1.1.1"
			fi
		fi

		if [[ "$mode" == "itf" ]]; then
			vpp_exec_cmd inl_ipsec_perf "ipsec itf create"
			vpp_exec_cmd inl_ipsec_perf "ipsec tunnel protect sa-out $((i+11)) sa-in $((i+1)) ipsec$i"
			vpp_exec_cmd inl_ipsec_perf "set int state ipsec$i up"
			vpp_exec_cmd inl_ipsec_perf "ip route add 10.253.0.$i/32 via ipsec$i"
		else
			if [[ $i -eq 0 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec spd add 1"
				vpp_exec_cmd inl_ipsec_perf "set interface ipsec spd eth0 1"
			fi
			# Flowgen uses a fixed/local src range across flows; keep local-ip wide
			# so multi-core flows still match on remote-ip.
			vpp_exec_cmd inl_ipsec_perf "ipsec policy add spd 1 outbound priority 100 action protect sa $((i+11)) local-ip-range 10.254.0.0-10.254.0.255 remote-ip-range 10.253.0.$i-10.253.0.$i"
			vpp_exec_cmd inl_ipsec_perf "ipsec policy add spd 1 outbound priority 100 action bypass sa 10 local-ip-range $((i+1)).1.1.2-$((i+1)).1.1.2 remote-ip-range $((i+1)).1.1.1-$((i+1)).1.1.1"
			vpp_exec_cmd inl_ipsec_perf "ip route add 10.253.0.$i/32 via eth0"
		fi

		vpp_exec_cmd inl_ipsec_perf "set ip neighbor eth0 10.253.0.$i 00:16:3e:7e:94:9a"
		vpp_exec_cmd inl_ipsec_perf "set ip neighbor eth0 $((i+1)).1.1.1 00:16:3e:7e:94:9a"
		vpp_exec_cmd inl_ipsec_perf "ip route add $((i+1)).1.1.0/24 via eth0"

		vpp_exec_cmd inl_ipsec_perf "test flow add dst-ip 10.253.0.$i/255.255.255.255 proto 17 redirect-to-queue $i"
		vpp_exec_cmd inl_ipsec_perf "test flow enable index $((i+2)) eth0"
	done

	sleep $WS
}

function run_vpp_ipsec_inb()
{
	local i
	local mode=${2:-"itf"}
	n_CORES=$1
	echo "vpp inb num_cores:$n_CORES mode:$mode"
	IS_RXPPS_TXTPMD=1
	rm -rf /tmp/inl_ipsec_perf
	mkdir -p /tmp/inl_ipsec_perf
	cp inl_ipsec_perf_$n_CORES.conf /tmp/inl_ipsec_perf/
	cp ${IP_IB_CFG[$Y]} /tmp/inl_ipsec_perf/

	# Inline Protocol
	vpp_launch inl_ipsec_perf_$n_CORES
	vpp_exec_cmd inl_ipsec_perf "device attach pci/$IF0 driver octeon"
	vpp_exec_cmd inl_ipsec_perf "device create-interface pci/$IF0 port 0 name eth0 num-rx-queues $n_CORES tx-queues-size 16384"
	vpp_exec_cmd inl_ipsec_perf "device attach pci/$IF1 driver octeon"
	vpp_exec_cmd inl_ipsec_perf "device create-interface pci/$IF1 port 0 name eth1 num-rx-queues $n_CORES tx-queues-size 16384"
	vpp_exec_file inl_ipsec_perf /tmp/inl_ipsec_perf/${IP_IB_CFG[$Y]}

	for (( i=0; i<$n_CORES; i++ ))
	do
		# Determine if transport mode
		local is_transport=0
		if [[ "$mode" == "policy_transport" ]]; then
			is_transport=1
		fi

		if [[ $Y == 0 ]]; then
			if [[ $is_transport -eq 1 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
			else
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 tunnel src $((i+1)).1.2.1 dst $((i+1)).1.2.2 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-cbc-128 integ-alg sha1-96 integ-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 tunnel src $((i+1)).1.2.2 dst $((i+1)).1.2.1"
			fi
		else
			if [[ $is_transport -eq 1 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128"
			else
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+1)) spi $((i+1)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 tunnel src $((i+1)).1.2.1 dst $((i+1)).1.2.2 inbound"
				vpp_exec_cmd inl_ipsec_perf "ipsec sa add $((i+11)) spi $((i+101)) esp crypto-key a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 crypto-alg aes-gcm-128 tunnel src $((i+1)).1.2.2 dst $((i+1)).1.2.1"
			fi
		fi

		if [[ "$mode" == "itf" ]]; then
			vpp_exec_cmd inl_ipsec_perf "ipsec itf create"
			vpp_exec_cmd inl_ipsec_perf "ipsec tunnel protect sa-in $((i+1)) sa-out $((i+11)) ipsec$i"
			vpp_exec_cmd inl_ipsec_perf "set int state ipsec$i up"
		else
			if [[ $i -eq 0 ]]; then
				vpp_exec_cmd inl_ipsec_perf "ipsec spd add 1"
				vpp_exec_cmd inl_ipsec_perf "set interface ipsec spd eth0 1"
				vpp_exec_cmd inl_ipsec_perf "ipsec policy add spd 1 outbound priority 1 action bypass"
			fi
			vpp_exec_cmd inl_ipsec_perf "ipsec policy add spd 1 inbound priority $((100+i)) action protect sa $((i+1)) local-ip-range $((i+1)).1.2.2-$((i+1)).1.2.2 remote-ip-range $((i+1)).1.2.1-$((i+1)).1.2.1"
		fi

		vpp_exec_cmd inl_ipsec_perf "test flow add dst-ip 192.168.2.$((i+2))/255.255.255.255 proto 17 redirect-to-queue $i"
		vpp_exec_cmd inl_ipsec_perf "test flow enable index $((i+2)) eth0"
		vpp_exec_cmd inl_ipsec_perf "ip route add 192.168.2.$((i+2))/32 via eth0"
		vpp_exec_cmd inl_ipsec_perf "set ip neighbor eth0 192.168.2.$((i+2)) 00:16:3e:7e:94:9a"
	done

	sleep $WS
}

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	vpp_log inl_ipsec_perf
	vpp_stats_all inl_ipsec_perf
	vpp_cleanup inl_ipsec_perf
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
	fi
	awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
	cleanup_interfaces
	exit $status
}

find_exec()
{
	local dut=$1
	local test_name=$2

	$TARGET_SSH_CMD $dut find $REMOTE_DIR -type f -executable -iname $test_name
}

function exec_genboard_cleanup()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		$TARGET_SSH_CMD $GENERATOR_BOARD "sudo pkill -f dpdk*;"
		echo "Gen board previous test processes cleanup up"
	fi
}

function exec_testpmd_cmd_gen()
{
	$TARGET_SSH_CMD $GENERATOR_BOARD "cd $REMOTE_DIR;" \
		"sudo TESTPMD_OP=$1 $(find_exec $GENERATOR_BOARD $GENERATOR_SCRIPT) $2 $3"
}

function pmd_tx_launch()
{
	if [[ $DTC == "CN103XX" ]]; then
		C_MSK="0x38"
	else
		C_MSK="0x3800"
	fi
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		exec_testpmd_cmd_gen "launch_tx_outb" $TPMD_TX_PREFIX $1
	else
		testpmd_launch "$TPMD_TX_PREFIX" \
			"-c $C_MSK -a $LIF1" \
			"--nb-cores=2 --forward-mode=flowgen --flowgen-flows=$1 --txq=3 --rxq=3 --eth-peer=0,00:01:02:03:04:01"
		testpmd_cmd $TPMD_TX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "port start 0"
		# Ratelimit Tx to 50Gbps on LBK
		testpmd_cmd $TPMD_TX_PREFIX "set port 0 queue 0 rate 50000"
	fi
}

function pmd_tx_launch_for_inb()
{
	if [[ $DTC == "CN103XX" ]]; then
		C_MSK_I="0xF8"
		C_MSK="0x38"
	else
		C_MSK_I="0xF800"
		C_MSK="0x3800"
	fi

	local pcap=$OCTEONTESTPATH/inl_ipsec_perf/pcap/enc_$1_$2_$3.pcap

	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		exec_testpmd_cmd_gen "launch_tx_inb" $TPMD_TX_PREFIX $pcap
	else
		if is_single_sa_test; then
			testpmd_launch "$TPMD_TX_PREFIX" \
			"-c $C_MSK_I --vdev net_pcap0,rx_pcap=$pcap,rx_pcap=$pcap,rx_pcap=$pcap,rx_pcap=$pcap,infinite_rx=1 -a $LIF1" \
			"--nb-cores=4 --txq=4 --rxq=4 --no-flush-rx"
		else
			testpmd_launch "$TPMD_TX_PREFIX" \
			"-c $C_MSK --vdev net_pcap0,rx_pcap=$pcap,infinite_rx=1 -a $LIF1" \
			"--nb-cores=2 --no-flush-rx"
		fi
		testpmd_cmd $TPMD_TX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "port start 0"
		# Ratelimit Tx to 50Gbps on LBK
		testpmd_cmd $TPMD_TX_PREFIX "set port 0 queue 0 rate 50000"
	fi
}

function pmd_rx_launch()
{
	if [[ $DTC == "CN103XX" ]]; then
		C_MSK_RX="0x70"
	else
		C_MSK_RX="0x700"
	fi
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then :
	else
		testpmd_launch "$TPMD_RX_PREFIX" \
			"-c $C_MSK_RX -a $LIF4" \
			"--nb-cores=2 --forward-mode=rxonly"
		testpmd_cmd $TPMD_RX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_RX_PREFIX "port start 0"
	fi
}

function pmd_rx_dry_run()
{
	local port="0"
	PREFIX=("$TPMD_RX_PREFIX" "$TPMD_TX_PREFIX")

	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		rxpps=$(exec_testpmd_cmd_gen "rx_pps" $TPMD_TX_PREFIX $port)
	else
		for prefix in "${PREFIX[@]}"
		do
			local in=testpmd.in.$prefix
			prev=$(testpmd_log_sz $prefix)
			curr=$prev
			echo "show port stats $port" >> $in

			while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $prefix); done
			testpmd_prompt $prefix
		done
	fi
}

function rx_stats()
{
	local prefix=$1
	local port=$2
	local in=testpmd.in.$prefix
	local out=testpmd.out.$prefix

	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		rxpps=$(exec_testpmd_cmd_gen "rx_pps" $prefix $port)
		echo $rxpps
	else
		prev=$(testpmd_log_sz $prefix)
		curr=$prev

		echo "show port stats $port" >> $in
		while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $prefix); done
		testpmd_prompt $prefix
		cat $out | tail -n4 | head -n1
	fi
}

function capture_rx_pps()
{
	local stats
	if [[ $IS_RXPPS_TXTPMD -ne 0 ]]; then
		# Specific case of Inline Protocol Single-SA configuration.
		# Packets are routed back to originating port.
		stats=$(rx_stats $TPMD_TX_PREFIX "0")
	else
		stats=$(rx_stats $TPMD_RX_PREFIX "0")
	fi

	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		echo $stats
	else
		echo $stats | awk '{print $2}'
	fi
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"

	$VFIO_DEVBIND -b vfio-pci $LIF1
	$VFIO_DEVBIND -b vfio-pci $LIF2
	$VFIO_DEVBIND -b vfio-pci $LIF3
	$VFIO_DEVBIND -b vfio-pci $LIF4
}

function cleanup_interfaces()
{
	# Bind the vfio-pci binded devices back to nicvf
	$VFIO_DEVBIND -b $NICVF $LIF1
	$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF3
	$VFIO_DEVBIND -b $NICVF $LIF4
}

function start_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		exec_testpmd_cmd_gen "start" $TPMD_TX_PREFIX "NOP"
	else
		testpmd_cmd "$TPMD_RX_PREFIX" "start"
		testpmd_cmd "$TPMD_TX_PREFIX" "start tx_first 64"
	fi
}

function stop_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		exec_testpmd_cmd_gen "stop" $TPMD_TX_PREFIX "NOP"
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "stop"
		testpmd_cmd "$TPMD_RX_PREFIX" "stop"
	fi
}

function set_pktsize_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		exec_testpmd_cmd_gen "pktsize" "$TPMD_TX_PREFIX" $1
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts $1"
	fi
}

function quit_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		if [[ $1 == $TPMD_TX_PREFIX ]]; then
			exec_testpmd_cmd_gen "log" $1 "NOP" >testpmd.out.$1
			exec_testpmd_cmd_gen "quit" $1 "NOP"
		fi
	else
		testpmd_quit $1
	fi
}

function outb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local algo
	local rn
	local i
	local mode=$4
	local cores=$3
	local cn=${5:-$(core_index "$cores")}

	[[ $X = 1 ]] && algo="aes-cbc_sha1-hmac" || algo="aes-gcm"

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		set_pktsize_testpmd $pktsz

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart vpp
				vpp_log inl_ipsec_perf
				vpp_stats_all inl_ipsec_perf
				vpp_cleanup inl_ipsec_perf
				echo "Restart vpp"
				run_vpp_ipsec $3 "$mode"
			fi
			start_testpmd
			pmd_rx_dry_run
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			p=${PASS_PPS_TABLE[$rn,$cn]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			Failed_tests="$Failed_tests \"${TN[$Y]} outbound $algo pktsize:$pktsz num_cores:$3 mode:$mode\""
		fi
		((++rn))
	done
}

function inb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local algo
	local rn
	local i
	local mode=$4
	local cores=$3
	local cn=${5:-$(core_index "$cores")}

	[[ $X = 1 ]] && algo="aes-cbc_sha1-hmac" || algo="aes-gcm"

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		sleep $WS
		pmd_tx_launch_for_inb $1 $pktsz $3

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart vpp
				vpp_log inl_ipsec_perf
				vpp_stats_all inl_ipsec_perf
				vpp_cleanup inl_ipsec_perf
				echo "Restart vpp"
				run_vpp_ipsec_inb $3 "$mode"
			fi
			start_testpmd
			pmd_rx_dry_run
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			p=${PASS_PPS_TABLE[$rn,$cn]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				quit_testpmd "$TPMD_TX_PREFIX"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			quit_testpmd "$TPMD_TX_PREFIX"
			Failed_tests="$Failed_tests \"${TN[$Y]} inbound $algo pktsize:$pktsz num_cores:$3 mode:$mode\""
		fi
		((++rn))
	done
}

function get_ref_mops()
{
	local ref_mops
	local ref_file="$FPATH.$3"

	ref_mops=$(awk -v pat="$1" '$0~pat','/end/' "$ref_file" \
		| grep "^$2:" | tr -s ' ' || true)
	if [[ -z "${ref_mops// /}" ]]; then
		echo "ERROR: no reference for algorithm '$1' packet size '$2' in $ref_file" >&2
		exit 1
	fi
	echo "$ref_mops"
}

function populate_pass_mops()
{
	local rn=0
	local cn
	local mode=$3
	local ref_suffix=$2

	# For policy mode, use policy-specific reference file
	if [[ "$mode" == "policy" ]] || [[ "$mode" == "policy_transport" ]]; then
		ref_suffix="${ref_suffix%.*}.policy.${ref_suffix##*.}"
	fi

	# Use 97% threshold for all modes
	local multiplier=".97"

	for i in ${PKT_LIST[@]}
	do
		cn=0
		ref_mops=$(get_ref_mops "$1" "$i" "$ref_suffix")
		for j in ${CORES[@]}
		do
			tmp=$(( $cn + 2 ))
			ref_n=$(echo "$ref_mops" | cut -d " " -f $tmp)
			PASS_PPS_TABLE[$rn,$cn]=$(echo "($ref_n * $multiplier)" | bc)
			((++cn))
		done
		((++rn))
	done
}

function aes_cbc_sha1_hmac_outb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local mode=$3
	local cn=${4:-$(core_index "$2")}

	echo "Outbound Perf Test: $algo_str mode:$mode"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb" "$mode"

	outb_perf $algo_str $1 $2 "$mode" $cn
}

function aes_cbc_sha1_hmac_inb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local mode=$3
	local cn=${4:-$(core_index "$2")}

	echo "Inbound Perf Test: $algo_str mode:$mode"
	populate_pass_mops $algo_str "${TYPE[$Y]}.inb" "$mode"

	inb_perf $algo_str $1 $2 "$mode" $cn
}

function aes_gcm_outb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local mode=$3
	local cn=${4:-$(core_index "$2")}

	echo "Outbound Perf Test: $algo_str mode:$mode"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb" "$mode"

	outb_perf $algo_str $1 $2 "$mode" $cn
}

function aes_gcm_inb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local mode=$3
	local cn=${4:-$(core_index "$2")}

	echo "Inbound Perf Test: $algo_str mode:$mode"
	populate_pass_mops $algo_str "${TYPE[$Y]}.inb" "$mode"

	inb_perf $algo_str $1 $2 "$mode" $cn
}

get_system_info

if [[ $IS_CN10K -ne 0 ]]; then
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}
	FPATH="$OCTEONTESTPATH/inl_ipsec_perf/ref_numbers/cn10k/$FNAME"
else
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${HW}
	FPATH="$OCTEONTESTPATH/inl_ipsec_perf/ref_numbers/cn9k/$FNAME"
fi

MODES=("itf" "policy")

function check_ref_files()
{
	local need_policy=0
	local type
	local m

	for m in "${MODES[@]}"; do
		if [[ "$m" == "policy" || "$m" == "policy_transport" ]]; then
			need_policy=1
			break
		fi
	done

	for type in "${TYPE[@]}"; do
		[[ $IS_CN10K -eq 0 ]] && ! supported_by_9k $type && continue

		[[ ! -f "$FPATH.$type.inb" ]] && { echo "File $FPATH.$type.inb not present"; exit 1; }
		[[ $type != "ip_p_msns" ]] && [[ ! -f "$FPATH.$type.outb" ]] && { echo "File $FPATH.$type.outb not present"; exit 1; }

		if [[ $need_policy -eq 1 ]] && [[ $type != "ip_p_msns" ]]; then
			if [[ ! -f "$FPATH.$type.policy.inb" ]]; then
				echo "File $FPATH.$type.policy.inb not present (required for policy mode)"
				echo "Expected policy refs alongside route refs; listing $(dirname "$FPATH"):"
				ls -la "$(dirname "$FPATH")" 2>&1 || true
				exit 1
			fi
			if [[ ! -f "$FPATH.$type.policy.outb" ]]; then
				echo "File $FPATH.$type.policy.outb not present (required for policy mode)"
				echo "Expected policy refs alongside route refs; listing $(dirname "$FPATH"):"
				ls -la "$(dirname "$FPATH")" 2>&1 || true
				exit 1
			fi
		fi
	done
}

check_ref_files

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk '{ print $1 }')}
EVENT_VF=$SSO_DEV

setup_interfaces
exec_genboard_cleanup

count=0

for mode in "${MODES[@]}"
do
	cn=0
	for c in ${CORES[@]}
	do
		Y=0
		echo ""
		echo "Test: ${TN[$Y]} Num_cores: $c Mode: $mode"
		echo "----------------------"
		sleep $WS

		# Outbound
		# aes-cbc sha1-hmac

		X=1
		Y=0
		run_vpp_ipsec "$c" "$mode"

		pmd_rx_launch
		pmd_tx_launch $c
		aes_cbc_sha1_hmac_outb $count $c "$mode" $cn
		quit_testpmd "$TPMD_TX_PREFIX"
		quit_testpmd "$TPMD_RX_PREFIX"
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		vpp_log inl_ipsec_perf
		vpp_stats_all inl_ipsec_perf
		vpp_cleanup inl_ipsec_perf
		sleep $WS

		echo ""
		# aes-gcm

		X=2
		Y=1
		run_vpp_ipsec "$c" "$mode"

		pmd_rx_launch
		pmd_tx_launch $c
		aes_gcm_outb $count $c "$mode" $cn
		quit_testpmd "$TPMD_TX_PREFIX"
		quit_testpmd "$TPMD_RX_PREFIX"
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		vpp_log inl_ipsec_perf
		vpp_stats_all inl_ipsec_perf
		vpp_cleanup inl_ipsec_perf
		sleep $WS

		#
		echo ""
		# Inbound
		X=1
		Y=0
		run_vpp_ipsec_inb $c "$mode"
		pmd_rx_launch
		aes_cbc_sha1_hmac_inb $count $c "$mode" $cn
		quit_testpmd "$TPMD_RX_PREFIX"
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		vpp_log inl_ipsec_perf
		vpp_stats_all inl_ipsec_perf
		vpp_cleanup inl_ipsec_perf

		sleep $WS

		echo ""
		X=2
		Y=1
		run_vpp_ipsec_inb $c "$mode"
		pmd_rx_launch
		aes_gcm_inb $count $c "$mode" $cn
		quit_testpmd "$TPMD_RX_PREFIX"
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		vpp_log inl_ipsec_perf
		vpp_stats_all inl_ipsec_perf
		vpp_cleanup inl_ipsec_perf
		((++count))
		((++cn))
	done
done

echo ""
if [[ -n $Failed_tests ]]; then
	echo "FAILURE: Test(s) [$Failed_tests] failed"
	exit 1
fi

exit 0
