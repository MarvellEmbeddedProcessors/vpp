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

# Script syntax:
# build-deps.sh <deps-dir>
#
# Script will:
# 1. Create <deps-dir>
# 2. Fetch and build dependencies.

set -euo pipefail
shopt -s extglob

CROSS_COMPILE=${CROSS_COMPILE:-aarch64-marvell-linux-gnu}
BUILD_ROOT=$(realpath $1)
LIBUUID_DIR=${BUILD_ROOT}/libuuid
DEPS_DIR=${BUILD_ROOT}/deps-prefix

function build_libuuid {
	rm -rf ${LIBUUID_DIR}
	mkdir -p ${LIBUUID_DIR}
	cd ${LIBUUID_DIR}
	wget https://github.com/util-linux/util-linux/archive/refs/tags/v2.38.tar.gz
	tar -xvf v2.38.tar.gz
	cd util-linux-2.38
	./autogen.sh
	./configure --target=${CROSS_COMPILE} --host=${CROSS_COMPILE} \
		--build=x86_64-pc-linux-gnu --disable-all-programs --enable-libuuid \
		--prefix ${DEPS_DIR}
	make install
}

build_libuuid
