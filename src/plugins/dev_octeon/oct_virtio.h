/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */
#ifndef _OCTEON_VIRTIO_H_
#define _OCTEON_VIRTIO_H_

#undef always_inline

#include <dev_octeon/virtio_bus.h>
#include <dao_dma.h>
#include <dao_virtio_netdev.h>
#include <dao_pal.h>
#include <spec/virtio.h>
#include <spec/virtio_net.h>

#define always_inline static inline __attribute__ ((__always_inline__))

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define VIRTIO_NET_RSS_RETA_SIZE 128
#define OCT_VIRTIO_DEVICE_ID	 0xa70d
#define MAX_JUMBO_PKT_LEN	 9600

#define foreach_oct_virt_tx_node_counter                                      \
  _ (ENQUE_FAIL, enque_fail, ERROR, "Virtio enqueue failed")

typedef enum
{
#define _(f, n, s, d) OCT_VIRT_TX_NODE_CTR_##f,
  foreach_oct_virt_tx_node_counter
#undef _
} oct_tx_node_counter_t;

typedef struct
{
  u32 sw_if_index;
  u16 virtio_id;
  u64 tx_q_map;
} oct_virt_tx_trace_t;

typedef struct
{
  u32 sw_if_index;
  u16 virtio_id;
  u16 queue_id;
  u64 rx_q_map;
} oct_virt_rx_trace_t;

always_inline vlib_buffer_t *
oct_virt_to_bp (void *b)
{
  return (vlib_buffer_t *) ((u8 *) b + sizeof (struct dao_virtio_net_hdr) -
			    sizeof (vlib_buffer_t));
}

always_inline void *
oct_bp_to_virt (vlib_buffer_t *b)
{
  return (void *) ((u8 *) vlib_buffer_get_current (b) -
		   sizeof (struct dao_virtio_net_hdr));
}

typedef struct
{
  u8 status : 1;
  u8 full_duplex : 1;
  u16 virtio_id;
  u32 pem_devid;
  u32 speed;
} oct_virtio_device_t;

typedef struct
{
  u16 reta_size;
  u16 vchan_id;
  u16 virtio_id;
} oct_virtio_port_t;

typedef struct
{
  u64 wrkr_cpu_mask;
  u64 netdev_map;
  u16 netdev_qp_count[DAO_VIRTIO_DEV_MAX];
  u8 dao_lib_initialized;
} oct_virtio_main_t;

typedef struct
{
  u8 state;
} oct_virtio_port_map_t;

typedef struct
{
  u64 qmap;
  u16 last_rx_q;
  u16 last_tx_q;
} oct_virtio_q_info_t;

typedef struct
{
  u8 initialized;
  u64 netdev_map;
  oct_virtio_q_info_t q_map[DAO_VIRTIO_DEV_MAX];
} oct_virtio_per_thread_data_t;

int oct_virtio_dev_status_cb (u16 virtio_devid, u8 status);
int oct_virito_rss_reta_configure (u16 virtio_devid,
				   struct virtio_net_ctrl_rss *rss);
int oct_virtio_configure_promisc (u16 virtio_devid, u8 enable);
int oct_virtio_configure_allmulti (u16 virtio_devid, u8 enabl);
int oct_virtio_mac_addr_set (u16 virtio_devid, u8 *mac);
int oct_virtio_mac_addr_add (u16 virtio_devid,
			     struct virtio_net_ctrl_mac *mac_tbl, u8 type);
int oct_virtio_mq_configure (u16 virtio_devid, bool qmap_set);
int oct_virtio_vlib_buffer_alloc (u16 devid, void *buffs[], u16 nb_buffs);
int oct_virtio_vlib_buffer_free (u16 devid, void *buffs[], u16 nb_buffs);

vnet_dev_rv_t oct_virtio_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
void oct_virtio_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port);

vnet_dev_rv_t oct_virtio_port_start (vlib_main_t *vm, vnet_dev_port_t *port);

void oct_virtio_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);

format_function_t format_oct_virt_rx_trace;
format_function_t format_oct_virt_tx_trace;
u8 *format_oct_virt_port_status (u8 *s, va_list *args);
void oct_virt_buffer_pool_dma_map (vlib_main_t *vm);

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (oct_virt_log.class, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)                                                    \
  vlib_log_info (oct_virt_log.class, fmt, ##__VA_ARGS__)
#define log_notice(fmt, ...)                                                  \
  vlib_log_info (oct_virt_log.class, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_info (oct_virt_log.class, fmt, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_info (oct_virt_log.class, fmt, ##__VA_ARGS__)

#endif /* _OCTEON_VIRTIO_H_ */
