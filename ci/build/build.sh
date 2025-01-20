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
	echo "Builds VPP libraries and applications."
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-type         | -b            : Build type; release/debug"
	echo "--deps_dir           | -d            : Deps dir"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--octeon_version     | -o            : Version(cn10k, cn9k)"
	echo "--help               | -h            : Print this help and exit"
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "b:d:oh" \
	-l "build-type:,deps-dir:,octeon_version,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

DEPS_DIR=
BUILD=
export CROSS="aarch64-marvell-linux-gnu-"
export OCTEON_VERSION="cn10k"
export PLATFORM="cnxk"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-b|--build-type) shift; BUILD=$1;;
		-d|--deps-dir) shift; DEPS_DIR=$(realpath $1);;
		-o|--octeon-version) shift; OCTEON_VERSION=$1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done

if [[ -z $BUILD || -z $DEPS_DIR ]]; then
	echo "Build_type and Deps directory should be passed as argument !!"
	help
	exit 1
fi

if [[ $BUILD == "debug" ]]; then
	BUILD_TYPE=build
elif [[ $BUILD == "release" ]]; then
	BUILD_TYPE=build-release
else
	echo "Pass build-type (release/debug)"
	help
	exit 1
fi

DEPS_PREFIX=${DEPS_DIR}/deps-prefix
export cnxk_c_flags="-I/${DEPS_PREFIX}/include/ -L/${DEPS_PREFIX}/lib"
export UNATTENDED=y
export DEBIAN_FRONTEND=noninteractive
# FIXME: Remove install-dep command when these deps are installed in docker container.
make install-dep
make $BUILD_TYPE
