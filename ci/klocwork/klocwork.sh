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

set -euo pipefail

function help() {
	echo "Builds VPP libraries and applications with klocwork"
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root         | -r            : Build root directory"
	echo "--deps_dir           | -d            : Deps dir"
	echo "--octeon_sdk_sysroot   | -s          : OCTEON_SDK_SYSROOT path"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--octeon_version     | -o            : Version(cn10k, cn9k)"
	echo "--help               | -h            : Print this help and exit"
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:d:s:oh" \
	-l "build-root:,deps-dir:,cnxk_sdk_sysroot:,octeon_version,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
DEPS_DIR=
OCTEON_SYSROOT=
export CROSS="aarch64-marvell-linux-gnu-"
export OCTEON_VERSION="cn10k"
export PLATFORM="octeon"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build_root) shift; BUILD_ROOT=$(realpath $1);;
		-d|--deps-dir) shift; DEPS_DIR=$(realpath $1);;
		-s|--octeon_sdk_sysroot) shift; OCTEON_SYSROOT=$1;;
		-o|--octeon-version) shift; OCTEON_VERSION=$1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done

if [[ -z $DEPS_DIR || -z $BUILD_ROOT || -z $OCTEON_SYSROOT ]]; then
	echo "Deps directory, build root and octeon_sdk_sysroot should be passed as argument !!"
	help
	exit 1
fi

DEPS_PREFIX=${DEPS_DIR}/deps-prefix
export OCTEON_SDK_SYSROOT=$OCTEON_SYSROOT
export cnxk_c_flags="-I/${DEPS_PREFIX}/include/ -L/${DEPS_PREFIX}/lib"
export UNATTENDED=y
export DEBIAN_FRONTEND=noninteractive
rm -rf .kwlp .kwps
kwcheck create
kwcheck set license.host=llic5-01.marvell.com license.port=33138

# List of directories to ignore in klocwork checks
IGNORE_FILES=""

kwinject --ignore-files $IGNORE_FILES -w make build
kwcheck run -r -b kwinject.out -F detailed --report kwreport-detailed.txt
kwcheck list -F scriptable --report kwreport-scritpable.txt
CNXK_ISSUES=$(wc -l kwreport-scritpable.txt | awk '{print $1}')

echo "#########################################################################"
echo "Klocwork CNXK Issues: $CNXK_ISSUES"
echo "Klocwork Report : $PWD/kwreport-detailed.txt"
echo "#########################################################################"
