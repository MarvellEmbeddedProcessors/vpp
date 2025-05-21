#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

TEST_OP=${TEST_OP:-}
set -e

OCTEONTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $OCTEONTESTPATH/common/testpmd/common.env

PRFX="fwd-gen"
PORT0="${PORT0:-0002:02:00.0}"

VFIO_DEVBIND="$OCTEONTESTPATH/board/oxk-devbind-basic.sh"

function sig_handler()
{
        local status=$?
        set +e
        trap - ERR
        trap - INT
        if [[ $status -ne 0 ]]; then
                echo "$1 Handler"
                # Dump error logs
                testpmd_log $PRFX
        fi

        testpmd_cleanup $PRFX
        exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT

case $TEST_OP in
	launch)
		$VFIO_DEVBIND -b vfio-pci $PORT0
		num_cores=$(grep -c ^processor /proc/cpuinfo)
		((num_cores-=1))
		num_cores=${GEN_CORES:-$num_cores}
		((fwd_cores=num_cores-1))
		num_flows=${GEN_FLOWS}

		# Limit the number forwarding cores on cn10k.
		# Tx rate peaks (99 MPPS) after 10 cores and drop after 18.
			fwd_cores=$(( fwd_cores < 12 ? fwd_cores : 12 ))

		testpmd_launch $PRFX \
			"-l 1-$num_cores -a $PORT0" \
			"--no-flush-rx --nb-cores=$fwd_cores --forward-mode=flowgen \
			-i --txq=$fwd_cores --rxq=$fwd_cores \
			--flowgen-flows=$num_flows --eth-peer=0,00:01:02:03:04:01" </dev/null 2>/dev/null
		testpmd_cmd $PRFX "port stop 0"
		testpmd_cmd $PRFX "set flow_ctrl rx off 0"
		testpmd_cmd $PRFX "set flow_ctrl tx off 0"
		testpmd_cmd $PRFX "port start 0"
		;;
	start)
		testpmd_cmd $PRFX "start tx_first 256"
		testpmd_cmd $PRFX "show port stats all"
		;;
	stop)
		testpmd_cmd $PRFX "show port stats all"
		testpmd_cmd $PRFX "stop"
		;;
	rx_pps)
		testpmd_cmd $PRFX "show port stats all"
		val=`testpmd_log $PRFX | tail -4 | grep -ao 'Rx-pps: .*' | \
		    awk '{print $2}'`
		echo $val
		;;
	tx_pps)
		testpmd_cmd $PRFX "show port stats all"
			cut -f 2 -d ":"
		val=`testpmd_log $PRFX | tail -4 | grep -ao 'Tx-pps: .*' | \
		    awk '{print $2}'`
		echo $val
		;;
	cleanup)
		testpmd_cleanup $PRFX
		;;
	log)
		testpmd_log $PRFX
		;;
esac

exit 0
