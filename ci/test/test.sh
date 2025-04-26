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

function help() {
	set +x
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root | -r            : Build root directory"
	echo "--test-env | -t              : Test Environment"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--run-dir | -d               : Run directory [Default=Build Root]"
	echo "--project-root | -p          : VPP Project root [Default: PWD]"
	echo "--help | -h                  : Print this help and exit"
	set -x
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:d:t:p:h" \
	-l "build-root:,run-dir:,test-env:,project-root:,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
TEST_ENV_CONF=
PROJECT_ROOT="$PWD"
TARGET_BOARD=${TARGET_BOARD:-root@127.0.0.1}
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
REMOTE="$TARGET_SSH_CMD $TARGET_BOARD -n"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-d|--run-dir) shift; RUN_DIR=$1;;
		-t|--test-env) shift; TEST_ENV_CONF=$(realpath $1);;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done

if [[ -z $BUILD_ROOT || -z $TEST_ENV_CONF ]]; then
	echo "Build root directory and test env should be given !!"
	help
	exit 1
fi

export PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
export BUILD_ROOT=$(realpath $BUILD_ROOT)
export BUILD_DIR=$BUILD_ROOT/build
export RUN_DIR=${RUN_DIR:-$BUILD_DIR}
mkdir -p $RUN_DIR

source $TEST_ENV_CONF

install_packages
# Run the tests
$TEST_RUN_CMD
