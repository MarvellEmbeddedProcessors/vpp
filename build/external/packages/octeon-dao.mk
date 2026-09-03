# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Marvell.

DAO_DEBUG                   ?= n
octeon-dao_version             := dao-cn10k-26.02.0-ubuntu-24.04-26.02.0
octeon-dao_tarball             := $(octeon-dao_version).tar.gz
octeon-dao_tarball_sha256sum      := 0bd606591bd9d42d6b04d656da2ca4bbf4b5c66762e4acaf93664ad1a505f387

octeon-dao_tarball_strip_dirs  := 1
octeon-dao_url                 := https://github.com/MarvellEmbeddedProcessors/dao/archive/refs/tags/$(octeon-dao_tarball)

octeon_dao_cmake_args ?=

DAO_BUILD_TYPE:=release
ifeq ($(DAO_DEBUG), y)
DAO_BUILD_TYPE:=debug
endif

DAO_MESON_ARGS = \
	--default-library static \
	-Dprefer_static_build=true --prefer-static \
	-Denable_libs=virtio,virtio_net,vfio,pem,pal,common \
	--buildtype=$(DAO_BUILD_TYPE) \
        -Denable_kmods=false

PREFIX = $(OCTEON_SDK_SYSROOT)

ifeq (,$(findstring $(OCTEON_VERSION),cn10k cn9k))
  DAO_MESON_ARGS += -Dplatform=native
  DAO_MESON_ARGS += --prefix $(octeon-dao_install_dir)
  PREFIX = $(octeon-dao_install_dir)
else ifeq ($(OCTEON_VERSION), cn10k)
  DAO_MESON_ARGS += --cross-file=$(octeon-dao_src_dir)/config/arm64_cn10k_linux_gcc
  DAO_MESON_ARGS += --prefix $(OCTEON_SDK_SYSROOT)
else ifeq ($(OCTEON_VERSION), cn9k)
  DAO_MESON_ARGS += --cross-file=$(octeon-dao_src_dir)/config/arm64_cn9k_linux_gcc
  DAO_MESON_ARGS += --prefix $(OCTEON_SDK_SYSROOT)
endif

PIP_DOWNLOAD_DIR = $(CURDIR)/downloads/

define octeon-dao_config_cmds
	sed -i "s/^\(\s*\)subdir('doc')/\1# subdir('doc')/" $(octeon-dao_src_dir)/meson.build
	sed -i "s/^\(\s*\)subdir('app')/\1# subdir('app')/" $(octeon-dao_src_dir)/meson.build
	sed -i "s/^\(\s*\)subdir('tests')/\1# subdir('tests')/" $(octeon-dao_src_dir)/meson.build
	sed -i 's/aarch64-marvell-linux/aarch64-none-linux/g' $(octeon-dao_src_dir)/config/arm64_cn10k_linux_gcc
	sed -i 's/aarch64-marvell-linux/aarch64-none-linux/g' $(octeon-dao_src_dir)/config/arm64_cn9k_linux_gcc
	PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig meson setup $(octeon-dao_src_dir) \
		$(octeon-dao_build_dir) \
		$(DAO_MESON_ARGS) -Dc_args="-Wno-error" -Dc_link_args="-Wno-error"\
			| tee $(dao_config_log) && \
	echo "DAO post meson configuration"
endef

define  octeon-dao_build_cmds
	cd ${octeon-dao_build_dir} && rm -f $(octeon-dao_build_log) && \
	meson compile -C ${octeon-dao_build_dir} | tee $(octeon-dao_build_log)
endef

define  octeon-dao_install_cmds
	cd ${octeon-dao_build_dir} && \
	meson install &&\
	echo "meson installed directory ${octeon-dao_install_dir}"
endef

$(eval $(call package,octeon-dao))
