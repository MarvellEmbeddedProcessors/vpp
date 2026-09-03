/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_octeon/oct_virtio.h>

u8 *
format_oct_virt_port_status (u8 *s, va_list *args)
{
  return s;
}

u8 *
format_oct_virt_rx_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  oct_virt_rx_trace_t *t = va_arg (*args, oct_virt_rx_trace_t *);

  s = format (s, "octeon-virt-rx: virtio_id %u sw_if_index %u rx_q_map %lu",
	      t->virtio_id, t->sw_if_index, t->rx_q_map);
  return s;
}

u8 *
format_oct_virt_tx_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  oct_virt_tx_trace_t *t = va_arg (*args, oct_virt_tx_trace_t *);

  s = format (s, "octeon-virt-tx: virtio_id %u sw_if_index %u tx_q_map %lu ",
	      t->virtio_id, t->sw_if_index, t->tx_q_map);
  return s;
}
