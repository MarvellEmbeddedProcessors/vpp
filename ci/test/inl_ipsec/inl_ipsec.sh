#!/bin/bash
# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

#set -e
set -euox pipefail

OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $OCTEONTESTPATH/common/vpp/vpp.env

PKTLOSS_ALLOWED_P=0

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

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
		awk ' { print FILENAME": " $0 } ' $APP_FULL_LOG
		awk ' { print FILENAME": " $0 } ' $APP_LOG
		awk ' { print FILENAME": " $0 } ' $APP_RESULT
		awk ' { print FILENAME": " $0 } ' $PING_LOG
	fi
	vpp_log inl_ipsec
	vpp_cleanup inl_ipsec
	ip netns exec vm0 ip xfrm state
	ip netns exec vm0 ip xfrm state deleteall
	ip netns exec vm0 ip xfrm policy deleteall
	cleanup_interfaces
	ps -eo "pid,args" | grep tcpdump | awk ' { print $1 }' |  xargs -I[] -n1 kill -9 [] 2 >/dev/null || true
	exit $status
}

# Display results for ping test
function print_result()
{
	local na
	local passed
	local failed
	local partial

	if [[ "$1" == "0%" ]]; then
		echo -e "\tPASS: no packet loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\tNo packet loss ----- PASSED" >> $APP_RESULT
		#passed=$((passed + 1))
		set +e
	elif [[ "$1" == "100%" ]]; then
		echo -e "\t$1"" ERROR: packets loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\t""$1"" packets loss ----- FAILED" >> $APP_RESULT
		#failed=$((failed + 1))
	elif [[ -z "$1" ]]; then
		echo -e "\tERROR: Unable to capture Results"
		echo -e "\tcase "$2"\tunable to capture Results  ----- N/A" >> $APP_RESULT
		#na=$((na + 1))
	else
		echo -e "\t$1"" packets loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\t""$1"" packets loss ----- PARTIAL PASSED" >> $APP_RESULT
#		partial=$((partial + 1))
	fi
}

# Start ping packets from interfaces for all test cases.
# This would need reconfiguration of interfaces.
function start_ping_test()
{
	local errp

	echo -e "ping_pkts :-------updated ip: 192.168.$Y.2"
	while [ $Y -le $MAX_Y ]; do
		if [[ $1 == "1" ]]; then
			if [[ $Y -gt 4 && $Y -lt 8 ]]; then
				((++Y))
				((++X))
				continue
			fi
		fi
		if [[ $1 == "2" ]] || [[ $1 == "3" ]]; then
			if [[ $Y -gt 1 && $Y -lt 8 ]]; then
				((++Y))
				((++X))
				continue
			fi
		fi
		reconfigure_interfaces
	        ip netns exec vm0 ip xfrm state list
	        ip netns exec vm0 ip xfrm policy list
		ip netns exec vm0 tcpdump -nexi enP2p1s0v4 >/tmp/inl_ipsec/4 &
		ip netns exec vm0 tcpdump -nexi enP2p1s0v4:1 >/tmp/inl_ipsec/4.1 &
		ip netns exec vm2 tcpdump -nexi enP2p1s0v6 >/tmp/inl_ipsec/6 &
		for pkt_size in $PKT_LIST
		do
			local itr=0
			echo -e "ping_pkts :-------" "$pkt_size" "$Y"

			while [ $itr -le $PING_RETRY ]; do
				ip netns exec vm0 ping 192.168.$Y.2 \
					-i $PKT_GAP -c $PING_PKTS -s \
					$pkt_size $PING_ARGS | tee -a $PING_LOG

				RESULT=`tail -n 3 $PING_LOG | \
					grep -o "\w*\.\w*%\|\w*%"`

				print_result "$RESULT" "$Y" "$pkt_size"
				errp=$(echo $RESULT | cut -c 1)

				# Break if success
				check=$(echo "$errp <= $PKTLOSS_ALLOWED_P" | bc)
				if [ $check -eq 1 ]; then break; fi
				((++itr))
			done
			# Wait until the process is killed
#			while (ps -ef | grep ping); do
#				continue
#			done

			if (( $(echo "$errp > $PKTLOSS_ALLOWED_P" | bc) )); then
				echo -e "Test Failed as packets loss $RESULT > $PKTLOSS_ALLOWED_P%"
				vpp_cleanup inl_ipsec
				interfaces_cleanup
				exit 1
			fi
		done
		interfaces_cleanup
		((++Y))
		((++X))
	done
}

function run_test()
{
	echo "Starting ping test" | tee $PING_LOG
	start_ping_test $1
}

function run_inline_ipsec()
{
	X=101
	Y=1
	echo -e ""
	echo -e "Inline protocol IPsec"
	echo -e "---------------------"
	rm -rf /tmp/inl_ipsec
	mkdir -p /tmp/inl_ipsec
	cp inl_ipsec.exec /tmp/inl_ipsec
	vpp_launch inl_ipsec
	vpp_start inl_ipsec

	sleep 2
	run_test 2
}

#configure vm0
function configure_vm0()
{
	ip netns exec vm0 ip addr add 192.168.$X.2/24 dev $LBK1
	ip netns exec vm0 ip addr add 1.1.$Y.1/24 dev $LBK1:1
	ip netns exec vm0 ip link set $LBK1 up
	ip netns exec vm0 ip link set $LBK1 address $VM0_MAC
	ip netns exec vm0 ip route add 192.168.$Y.0/24 via 192.168.$X.1
	ip netns exec vm0 arp -s 192.168.$X.1 $VM0_MAC
	ip netns exec vm0 arp -s 1.1.$Y.2 $VM0_MAC
	ip netns exec vm0 ip xfrm state add src 1.1.$Y.1 dst 1.1.$Y.2 proto esp spi $Y reqid 0 mode tunnel ${CASE[$Y]}
	ip netns exec vm0 ip xfrm state add src 1.1.$Y.2 dst 1.1.$Y.1 proto esp spi $X reqid 0 mode tunnel ${CASE[$Y]}
	ip netns exec vm0 ip xfrm policy add src 192.168.$X.2 dst 192.168.$Y.2 dir out tmpl src 1.1.$Y.1 dst 1.1.$Y.2 proto esp spi $Y reqid 0 mode tunnel
	ip netns exec vm0 ip xfrm policy add src 192.168.$Y.2 dst 192.168.$X.2 dir in tmpl src 1.1.$Y.2 dst 1.1.$Y.1 proto esp spi $X reqid 0 mode tunnel
}

#configure vm2
function configure_vm2()
{
	ip netns exec vm2 ip addr add 192.168.$Y.2/24 dev $LBK3
	ip netns exec vm2 ip link set $LBK3 up
	ip netns exec vm2 ip link set lo up
	ip netns exec vm2 ip link set $LBK3 address $VM2_MAC
	ip netns exec vm2 ip route add 192.168.$X.0/24 via 192.168.$Y.1
	ip netns exec vm2 arp -s 192.168.$Y.1 $VM2_MAC
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "Create namespaces"
	ip netns add vm0
	ip netns add vm2

	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"
	$VFIO_DEVBIND -b $NICVF $LIF1
	#$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF3
	#$VFIO_DEVBIND -b $NICVF $LIF4

	echo -e "Bind LBK devices required to act as LBK pairs b/w VPP and Linux"
	$VFIO_DEVBIND -b vfio-pci $LIF2
	$VFIO_DEVBIND -b vfio-pci $LIF4

	$VFIO_DEVBIND -b vfio-pci $INLINE_DEV

	LBK1=`ls /sys/bus/pci/devices/$LIF1/net/`
	LBK3=`ls /sys/bus/pci/devices/$LIF3/net/`

	echo -e "Add devices in namespaces $LBK1 $LBK3"
	ip link set dev $LBK1 netns vm0
	ip link set dev $LBK3 netns vm2
}

function interfaces_cleanup()
{
	echo -e "\ninterfaces_cleanup"
	ip netns exec vm0 ip xfrm state
	ip netns exec vm0 ip xfrm state deleteall
	ip netns exec vm0 ip xfrm policy deleteall
	ip netns exec vm0 arp -d 192.168.$X.1
	ip netns exec vm0 arp -d 1.1.$Y.2
	ip netns exec vm0 ip route del 192.168.$Y.0/24
	ip netns exec vm0 ip addr del 192.168.$X.2/24 dev $LBK1
	ip netns exec vm0 ip addr del 1.1.$Y.1/24 dev $LBK1:1
	ip netns exec vm0 ip link set $LBK1 down

	ip netns exec vm2 ip route del 192.168.$X.0/24
	ip netns exec vm2 arp -d 192.168.$Y.1
	ip netns exec vm2 ip addr del 192.168.$Y.2/24 dev $LBK3
	ip netns exec vm2 ip link set $LBK3 down
	ip netns exec vm2 ip link set lo down
}

function reconfigure_interfaces()
{
	echo -e "\nreconfigure_interfaces"

	# Configure vm0
	configure_vm0
	# Configure vm2
	configure_vm2
}

function cleanup_interfaces()
{
	ip netns del vm0
	ip netns del vm2

	# Bind the LIF2 device back to nicvf
	$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF4
}

function main()
{
	setup_interfaces
	run_inline_ipsec
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# script's starting point
CASE=(
	""
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth    sha1    0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth-trunc    sha256  0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
)

PING_RETRY=1
PING_PKTS=320
PKT_LIST="64 380 1410"
PKT_GAP="0.001"
PING_ARGS=""

#VM0_MAC and VM2_MAC are taken from hard coded destination MAC addresses of ipsec-secgw app
VM0_MAC=00:16:3e:7e:94:9a
VM2_MAC=00:16:3e:22:a1:d9

LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

CDEV_PF=$(lspci -d :a0fd | head -1 | awk '{ print $1 }')
CDEV_VF=$(lspci -d :a0fe | head -1 | awk '{ print $1 }')
if [ -z "$CDEV_PF" ]
then
	CDEV_PF=$(lspci -d :a0f2 | head -1 | awk '{ print $1 }')
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk '{ print $1 }')
	if [ -z "$CDEV_PF" ]
	then
		echo "Error: CPTPF not found"
		exit 1;
	fi
fi

INLINE_DEV=0002:1d:00.0

LBK1=""
LBK3=""

APP_LOG=app.log
APP_FULL_LOG=app_full.log
APP_RESULT=app_result.log
PING_LOG=ping.log
VFIO_DEVBIND="$OCTEONTESTPATH/board/oxk-devbind-basic.sh"
if ! [[ -f $VFIO_DEVBIND ]]
then
VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
fi

rm -f $APP_LOG $APP_FULL_LOG $APP_RESULT $PING_LOG

MAX_X=110
MAX_Y=2

main
exit 0
