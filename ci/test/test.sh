#!/bin/bash
# Marvell CONFIDENTIAL AND PROPRIETARY NOTE
#
# This software contains information confidential and proprietary to
# Marvell. It shall not be reproduced in whole or in
# part, or transferred to other documents, or disclosed to third
# parties, or used for any purpose other than that for which it was
# obtained, without the prior written consent of Marvell.
#
# Copyright (c) 2025 Marvell. If you received this file from Marvell
# and you have entered into a commercial license agreement (a "Commercial License")
# with Marvell, the file is licensed to you under the terms of the applicable Commercial
# License. In the absence of such license agreement the following file is subject to
# Marvell’s standard Limited Use License Agreement.

set -euox pipefail

function target_board_init() {
	echo "Setting up target board for running tests..."
	$REMOTE "sudo TEST_DIR=${TEST_DIR} DPDK_DEVBIND=${REMOTE_BUILD_DIR}/ci/test/board/dpdk-devbind.py python3 ${REMOTE_BUILD_DIR}/ci/test/board/ci_runner.py -bv"
}

function install_packages() {
	echo "Enabling internet on target board...."
	$REMOTE 'echo "DNS=10.28.116.24 10.31.116.251 10.68.76.63" | sudo tee -a /etc/systemd/resolved.conf'
	$REMOTE "sudo systemctl restart systemd-resolved"
	sleep 30
	echo "Installing essential packages..."
	$REMOTE "sudo apt-get update"
	$REMOTE "sudo apt-get install -y python3-venv python3-pip"
	$REMOTE	"sudo pip3 install --break-system-packages --no-input psutil syslog_rfc5424_parser parameterized noise"
}

function sync_files() {
	echo "Syncing build to target board..."
	$REMOTE "rm -rf $REMOTE_DIR"
	$REMOTE "mkdir -p $REMOTE_DIR"
	# Sync build directory
	rsync -e "$TARGET_SSH_CMD" -av $BUILD_DIR/* $TARGET_BOARD:$REMOTE_BUILD_DIR/
	# Sync deps build directory if required
	rsync -e "$TARGET_SSH_CMD" -r $DEPS_DIR/* $TARGET_BOARD:$REMOTE_DIR/deps_build
	# Sync dpdk-devbind.py
	$TARGET_SSH_CMD $TARGET_BOARD "sudo $TARGET_SCP_CMD $DPDK_DEVBIND_LOCATION ${REMOTE_BUILD_DIR}/ci/test/board/"
}

function run_tests() {
	echo "Running tests using run_tests.py..."
	$REMOTE "python3 ${REMOTE_BUILD_DIR}/test/run_tests.py -d ${TEST_DIR}"
}

PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
TARGET_BOARD=${TARGET_BOARD:-root@127.0.0.1}
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
TARGET_SCP_CMD=${TARGET_SCP_CMD:-"scp"}
REMOTE="$TARGET_SSH_CMD $TARGET_BOARD -n"
REMOTE_DIR=${REMOTE_DIR:-/tmp/vpp}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
DEPS_DIR=${DEPS_DIR:-${PROJECT_ROOT}/deps-prefix}
REMOTE_BUILD_DIR=${REMOTE_DIR}/build
PLAT=${PLAT:-cn10k}
DPDK_DEVBIND_LOCATION=${DPDK_DEVBIND_LOCATION:-ci@10.28.36.188:/home/ci/vpp/perf_stage_bins/$PLAT/dpdk-devbind.py}

TEST_DIR=${REMOTE_BUILD_DIR}/src/plugins/dev_octeon/test/

install_packages
sync_files
target_board_init
run_tests
