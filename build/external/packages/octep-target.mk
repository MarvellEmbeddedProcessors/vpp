# Copyright (c) 2024 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

octep-target_version             := 24.12.0
octep-target_tarball             := $(octep-target_version).tar.gz
octep-target_tarball_md5sum      := f91d480bb4ab12cb87400bfd061e3b07
octep-target_github              := https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_target

octep-target_tarball_strip_dirs  := 1
octep-target_url                 := $(octep-target_github)/archive/refs/tags/$(octep-target_tarball)
export CFLAGS                           := $(CFLAGS) -DUSE_PEM_AND_DPI_PF=1

define  octep-target_config_cmds
	@true
endef

define  octep-target_build_cmds
	@cd ${octep-target_src_dir} && rm -f $(octep-target_build_log)
	@make -C ${octep-target_src_dir}/target/libs/octep_cp_lib/ all INSTALL_PATH=$(octep-target_install_dir) >> $(octep-target_build_log)
endef

define  octep-target_install_cmds
	@$(MAKE) -C ${octep-target_src_dir}/target/libs/octep_cp_lib/ install INSTALL_PATH=$(octep-target_install_dir) >> $(octep-target_install_log)
endef

$(eval $(call package,octep-target))

