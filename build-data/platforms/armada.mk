# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

ifeq ($(PLATFORM), armada)
armada_arch                    = aarch64
armada_native_tools            = vppapigen
armada_root_packages           = vpp

armada_debug_TAG_BUILD_TYPE    = debug
armada_TAG_BUILD_TYPE          = release
armada_clang_TAG_BUILD_TYPE    = release
armada_gcov_TAG_BUILD_TYPE     = gcov
armada_coverity_TAG_BUILD_TYPE = coverity
armada_target                  = aarch64-marvell-linux-gnu

_CURDIR                        := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

VPP_EXTRA_CMAKE_ARGS           +=-DCMAKE_TOOLCHAIN_FILE=$(_CURDIR)/../../src/cmake/cross.cmake
VPP_EXTRA_CMAKE_ARGS           +=-DCMAKE_C_FLAGS="${armada_c_flags}"

ifeq ("$(ARMADA_DISABLE_CCACHE)","1")
VPP_EXTRA_CMAKE_ARGS           += -DVPP_USE_CCACHE:BOOL=OFF
endif

ifndef ARMADA_SDK_SYSROOT
 $(error ARMADA_SDK_SYSROOT is not set)
endif

export armada_sysroot            = $(ARMADA_SDK_SYSROOT)
export CROSS_TARGET            = $($(PLATFORM)_target)
export CROSS_ARCH              = $($(PLATFORM)_arch)
export CROSS_SDK_SYSROOT       = $($(PLATFORM)_sysroot)
endif
