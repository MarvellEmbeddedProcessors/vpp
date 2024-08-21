# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2024 Marvell.

# Find OCTEON roc files
vpp_plugin_find_library(dev-octeon-virtio DAO_PAL_LIB "libdao_pal.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_VIRT_LIB "libdao_virtio.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_VIRT_NET_LIB "libdao_virtio_net.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_VFIO_LIB "libdao_vfio.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_PEM_LIB "libdao_pem.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_COMM_LIB "libdao_common.a")
vpp_plugin_find_library(dev-octeon-virtio DAO_DPDK_LIB "libdpdk.a")

vpp_find_path(DAO_NETDEV_INCLUDE_DIR NAMES dao_virtio_netdev.h)

if (NOT DAO_NETDEV_INCLUDE_DIR)
  message("OCTEON VIRTIO DAO files not found - Marvell OCTEON virtio device plugin disabled")
  return()
endif()

set(DAO_CONFG_INCLUDE_DIR "${DAO_NETDEV_INCLUDE_DIR}/..")

if (NOT DAO_PAL_LIB OR NOT DAO_VIRT_LIB OR NOT DAO_VIRT_NET_LIB OR NOT DAO_VFIO_LIB OR NOT DAO_PEM_LIB OR NOT DAO_COMM_LIB)
  message("OCTEON VIRTIO DAO LIBS are not found - Marvell OCTEON virtio device plugin disabled")
  return()
endif()

unset(DAO_LINK_FLAGS)

get_filename_component(DAO_DPDK_LIB_DIR ${DAO_DPDK_LIB} DIRECTORY)

link_directories(${DAO_DPDK_LIB_DIR})
string_append(DAO_LINK_FLAGS "-L${DAO_DPDK_LIB_DIR}")
string_append(DAO_LINK_FLAGS "-lnuma -lz -lelf -lpcap -ljansson")
if(OPENSSL_FOUND)
  string_append(DAO_LINK_FLAGS "-lssl")
  string_append(DAO_LINK_FLAGS "-lcrypto")
endif()

string_append(DAO_LINK_FLAGS "-Wl,--whole-archive,${DAO_PAL_LIB},${DAO_VIRT_LIB},${DAO_VIRT_NET_LIB},${DAO_VFIO_LIB},${DAO_PEM_LIB},${DAO_COMM_LIB},${DAO_DPDK_LIB},--no-whole-archive")

include_directories (${DAO_NETDEV_INCLUDE_DIR}/)
include_directories (${DAO_CONFG_INCLUDE_DIR}/)

add_vpp_plugin(dev_octeon_virtio
  SOURCES
  virtio.c
  virtio_bus.c
  virtio_port.c
  virtio_ctrl.c
  virtio_tx_node.c
  virtio_rx_node.c
  virtio_format.c

  LINK_FLAGS
  "${DAO_LINK_FLAGS}"
)
