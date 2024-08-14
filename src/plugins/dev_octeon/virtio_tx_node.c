/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */
#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <dev_octeon/oct_virtio.h>
#define OCT_VIRT_MAX_FRAGS 6

extern oct_virtio_main_t *oct_virtio_main;
extern oct_virtio_per_thread_data_t *oct_virt_thread_data;

static_always_inline void
oct_virt_free_to_vlib (vlib_main_t *vm, vlib_node_runtime_t *node,
		       void *virt_b[], u16 nb_free, u16 hdr_len)
{
  u16 idx = 0;
  vlib_buffer_t *b;
  u32 b_index;

  while (idx < nb_free)
    {
      b = oct_virt_to_bp (virt_b[idx], hdr_len);
      b_index = vlib_get_buffer_index (vm, b);
      vlib_buffer_free_no_next (vm, &b_index, 1);
      idx++;
    }

  vlib_error_count (vm, node->node_index, OCT_VIRT_TX_NODE_CTR_ENQUE_FAIL,
		    nb_free);
}

static_always_inline u32
oct_virtio_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_buffer_t **b, u16 nb_pkts, u16 virtio_devid)
{
  vlib_buffer_t *bp;
  bool next_present;
  u64 tx_q_map, q_map;
  u16 idx = 0, nb_frags = 0;
  u32 cpu_id = vm->cpu_id;
  u16 nb_pkts_left = nb_pkts, hdr_len;
  u16 queue, virt_q, sent = 0, cur_sent = 0;
  void *virt_b[VLIB_FRAME_SIZE * OCT_VIRT_MAX_FRAGS];
  struct dao_virtio_net_hdr *v_hdr[4], *head;
  struct dao_virtio_net_hdr vhdr_init = { 0 };
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;

  tx_q_map = ptd[cpu_id].q_map[virtio_devid].qmap;
  q_map = ptd[cpu_id].q_map[virtio_devid].qmap;
  hdr_len = ptd[cpu_id].q_map[virtio_devid].virtio_hdr_sz;

  while (nb_pkts >= 8)
    {
      next_present = b[0]->flags & VLIB_BUFFER_NEXT_PRESENT ||
		     b[1]->flags & VLIB_BUFFER_NEXT_PRESENT ||
		     b[2]->flags & VLIB_BUFFER_NEXT_PRESENT ||
		     b[3]->flags & VLIB_BUFFER_NEXT_PRESENT;
      if (PREDICT_FALSE (next_present))
	break;

      v_hdr[0] = oct_bp_to_virt (b[0], hdr_len);
      v_hdr[1] = oct_bp_to_virt (b[1], hdr_len);
      v_hdr[2] = oct_bp_to_virt (b[2], hdr_len);
      v_hdr[3] = oct_bp_to_virt (b[3], hdr_len);

      *v_hdr[0] = vhdr_init;
      *v_hdr[1] = vhdr_init;
      *v_hdr[2] = vhdr_init;
      *v_hdr[3] = vhdr_init;

      virt_b[idx + 0] = (void *) v_hdr[0];
      virt_b[idx + 1] = (void *) v_hdr[1];
      virt_b[idx + 2] = (void *) v_hdr[2];
      virt_b[idx + 3] = (void *) v_hdr[3];

      clib_prefetch_store (oct_bp_to_virt (b[4], hdr_len));
      clib_prefetch_store (oct_bp_to_virt (b[5], hdr_len));
      clib_prefetch_store (oct_bp_to_virt (b[6], hdr_len));
      clib_prefetch_store (oct_bp_to_virt (b[7], hdr_len));

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      v_hdr[0]->desc_data[1] = b[0]->current_length;
      v_hdr[1]->desc_data[1] = b[1]->current_length;
      v_hdr[2]->desc_data[1] = b[2]->current_length;
      v_hdr[3]->desc_data[1] = b[3]->current_length;

      /* Number of bytes deviates (+/-) from vlib buffer current data */
      v_hdr[0]->desc_data[0] = ~b[0]->current_data + 1;
      v_hdr[1]->desc_data[0] = ~b[1]->current_data + 1;
      v_hdr[2]->desc_data[0] = ~b[2]->current_data + 1;
      v_hdr[3]->desc_data[0] = ~b[3]->current_data + 1;

      v_hdr[0]->hdr.num_buffers = 1;
      v_hdr[1]->hdr.num_buffers = 1;
      v_hdr[2]->hdr.num_buffers = 1;
      v_hdr[3]->hdr.num_buffers = 1;

      b += 4;
      idx += 4;
      nb_pkts -= 4;
    }

  while (nb_pkts)
    {
      bp = b[0];
      head = oct_bp_to_virt (bp, hdr_len);
      do
	{
	  v_hdr[0] = oct_bp_to_virt (bp, hdr_len);
	  *v_hdr[0] = vhdr_init;
	  virt_b[idx] = (void *) v_hdr[0];
	  v_hdr[0]->desc_data[1] = bp->current_length;
	  /* Number of bytes deviates (+/-) from vlib buffer current data */
	  v_hdr[0]->desc_data[0] = ~bp->current_data + 1;
	  next_present = bp->flags & VLIB_BUFFER_NEXT_PRESENT;
	  v_hdr[0]->hdr.num_buffers = 1;
	  idx++;
	  nb_frags++;
	}
      while (next_present && (bp = vlib_get_buffer (vm, bp->next_buffer)));

      head->hdr.num_buffers = nb_frags;
      b++;
      nb_pkts--;
      nb_frags = 0;
    }

  queue = ptd[cpu_id].q_map[virtio_devid].last_tx_q;
  nb_pkts_left = idx;

  while (tx_q_map && nb_pkts_left)
    {
      if (!(tx_q_map & DAO_BIT (queue)))
	goto next;

      tx_q_map &= ~(DAO_BIT (queue));
      virt_q = queue << 1;
      cur_sent = dao_virtio_net_enqueue_burst_ext (
	virtio_devid, virt_q, &virt_b[sent], nb_pkts_left);
      nb_pkts_left -= cur_sent;
      sent += cur_sent;

    next:
      queue = queue + 1;
      if (DAO_BIT (queue) > q_map)
	queue = 0;
    }

  ptd[cpu_id].q_map[virtio_devid].last_tx_q = queue;

  if (PREDICT_FALSE (nb_pkts_left))
    oct_virt_free_to_vlib (vm, node, &virt_b[sent], nb_pkts_left, hdr_len);

  /* Flush and submit DMA ops */
  dao_dma_flush_submit ();

  return sent;
}

static_always_inline void
oct_virtio_trace_buffers (vlib_main_t *vm, vlib_node_runtime_t *node,
			  oct_virtio_port_t *ovp, vlib_buffer_t **b,
			  u16 n_pkts, u16 virtio_id)
{
  u32 i;
  u64 tx_q_map;
  u32 cpu_id = clib_get_current_cpu_id ();
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;

  tx_q_map = ptd[cpu_id].q_map[virtio_id].qmap;

  for (i = 0; i < n_pkts; i++)
    {
      if (!(b[i]->flags & VLIB_BUFFER_IS_TRACED))
	continue;
      oct_virt_tx_trace_t *t = vlib_add_trace (vm, node, b[i], sizeof (*t));
      t->virtio_id = virtio_id;
      t->sw_if_index = vnet_buffer (b[i])->sw_if_index[VLIB_TX];
      t->tx_q_map = tx_q_map;
    }
}

VNET_DEV_NODE_FN (oct_virtio_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_tx_pkts;
  u16 virtio_id;
  oct_virtio_port_t *ovp;
  u32 *from = vlib_frame_vector_args (frame);
  u16 n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 8], **b = buffers;
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;

  if (!txq)
    return 0;

  ovp = vnet_dev_get_port_data (txq->port);
  virtio_id = ovp->virtio_id;

  vlib_get_buffers (vm, from, b, n_pkts);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    oct_virtio_trace_buffers (vm, node, ovp, b, n_pkts, virtio_id);

  n_tx_pkts = oct_virtio_enqueue (vm, node, b, n_pkts, virtio_id);

  return n_tx_pkts;
}
