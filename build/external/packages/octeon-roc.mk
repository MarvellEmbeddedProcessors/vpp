# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

octeon-roc_version             := octeon-roc-SDK1X.25.05
octeon-roc_tarball             := $(octeon-roc_version).tar.gz
octeon-roc_tarball_md5sum      := 7ca465369902f9a6f5c1b78cff140331
octeon-roc_github              := https://github.com/MarvellEmbeddedProcessors/marvell-octeon-roc

octeon-roc_tarball_strip_dirs  := 1
octeon-roc_url                 := $(octeon-roc_github)/archive/refs/tags/$(octeon-roc_tarball)

define  octeon-roc_config_cmds
	@true
endef

define  octeon-roc_build_cmds
	@cd ${octeon-roc_src_dir} && rm -f $(octeon-roc_build_log) && $(CMAKE) ${octeon-roc_src_dir} -DCMAKE_INSTALL_PREFIX='$(octeon-roc_install_dir)' >> $(octeon-roc_build_log)
	@$(MAKE) -C ${octeon-roc_src_dir} >> $(octeon-roc_build_log)
endef

define  octeon-roc_install_cmds
	@$(MAKE) -C ${octeon-roc_src_dir} install >> $(octeon-roc_install_log)
endef

$(eval $(call package,octeon-roc))

