/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_octeon/oct_virtio.h>

#define OCT_VIRT_LENGTH(h) (h->desc_data[1] & 0x00000000FFFFFFFF)
#define OCT_VIRT_NEXT_FLAG(h)                                                 \
  (h->desc_data[1] & DAO_BIT_ULL (VRING_DESC_F_NEXT))

extern oct_virtio_main_t *oct_virtio_main;
extern oct_virtio_per_thread_data_t *oct_virt_thread_data;

static_always_inline u32
oct_virt_trace_rx_buffers (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_buffer_t **b, u16 nb_pkts, u32 nb_trace,
			   u64 rx_q_map, u16 virtio_id, u16 next_index)
{
  int idx = 0;
  u32 n_traced = 0;
  for (idx = 0; idx < nb_pkts && idx < nb_trace; idx++)
    {
      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b[idx], 0)))
	{
	  oct_virt_rx_trace_t *tr =
	    vlib_add_trace (vm, node, b[idx], sizeof (*tr));
	  tr->rx_q_map = rx_q_map;
	  tr->virtio_id = virtio_id;
	  n_traced++;
	}
    }

  return n_traced;
}

static_always_inline vlib_buffer_t *
oct_virt_populate_inner_segments (vlib_main_t *vm, vlib_buffer_t *head,
				  void *p, u32 pool_idx, u16 hdr_len)
{
  vlib_buffer_t *prev, *b;
  struct dao_virtio_net_hdr *v_hdr;

  v_hdr = (struct dao_virtio_net_hdr *) p;
  b = oct_virt_to_bp (p, hdr_len);
  head->total_length_not_including_first_buffer += b->current_length;
  prev = b;
  while (v_hdr->desc_data[0])
    {
      v_hdr = (struct dao_virtio_net_hdr *) v_hdr->desc_data[0];
      b = oct_virt_to_bp ((void *) v_hdr->desc_data[0], hdr_len);
      b->current_length = OCT_VIRT_LENGTH (v_hdr) - hdr_len;
      b->current_data = 0;
      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
      head->total_length_not_including_first_buffer += b->current_length;
      prev->buffer_pool_index = pool_idx;
      prev->next_buffer = vlib_get_buffer_index (vm, b);
      prev = b;
    }
  head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

  return b;
}

static_always_inline vlib_buffer_t *
oct_virt_process_chained_packets (vlib_main_t *vm, void **pkts,
				  u32 *nb_pkts_chain, u32 *n_rx_bytes,
				  u16 hdr_len)
{
  u32 vhdr_len = sizeof (struct virtio_net_hdr);
  struct dao_virtio_net_hdr *v_hdr;
  vlib_buffer_t *b, *head, *prev = NULL;
  u32 buffer_index = 0, len;
  u8 pool_idx = 0;
  int idx = 0;

  pool_idx = vlib_buffer_pool_get_default_for_numa (vm, 0);
  v_hdr = (struct dao_virtio_net_hdr *) pkts[idx];
  len = OCT_VIRT_LENGTH (v_hdr) - hdr_len;
  head = oct_virt_to_bp (pkts[idx], hdr_len);

  /**
   * If Host uses linux virtio interface skip first buffer as it contains
   * only virtio header details
   */
  if (len == vhdr_len)
    {
      buffer_index = vlib_get_buffer_index (vm, head);
      vlib_buffer_free_no_next (vm, &buffer_index, 1);

      idx++;
      head = oct_virt_to_bp (pkts[idx], hdr_len);
      head->buffer_pool_index = pool_idx;
    }

  do
    {
      v_hdr = (struct dao_virtio_net_hdr *) pkts[idx];
      b = oct_virt_to_bp (pkts[idx], hdr_len);
      b->current_length = OCT_VIRT_LENGTH (v_hdr) - hdr_len;
      b->current_data = 0;
      /* Check for DPU side segmentation */
      if (PREDICT_FALSE ((v_hdr->desc_data[0])))
	b = oct_virt_populate_inner_segments (vm, head, pkts[idx], pool_idx,
					      hdr_len);

      if (prev)
	{
	  prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  head->total_length_not_including_first_buffer += b->current_length;
	  prev->buffer_pool_index = pool_idx;
	  prev->next_buffer = vlib_get_buffer_index (vm, b);
	  prev = b;
	}
      prev = b;
      idx++;
    }
  while (OCT_VIRT_NEXT_FLAG (v_hdr));

  *nb_pkts_chain = idx;
  *n_rx_bytes =
    head->current_length + head->total_length_not_including_first_buffer;

  return head;
}

static_always_inline u32
oct_virtio_process_virtio_packets (vlib_main_t *vm, void **pkts,
				   vlib_buffer_t **b, u32 *n_rx_pkts,
				   u32 *to_next, vnet_dev_rx_queue_t *rxq,
				   u16 hdr_len)
{
  u8 flags = 0;
  int idx = 0;
  u32 nb_pkts = *n_rx_pkts, next_nb_pkts = 0;
  u32 n_rx_bytes = 0, nb_pkts_chain = 0;
  struct dao_virtio_net_hdr *v_hdr[4];
  vlib_buffer_template_t bt = rxq->buffer_template;

  while (nb_pkts >= 8)
    {
      v_hdr[0] = (struct dao_virtio_net_hdr *) pkts[idx + 0];
      v_hdr[1] = (struct dao_virtio_net_hdr *) pkts[idx + 1];
      v_hdr[2] = (struct dao_virtio_net_hdr *) pkts[idx + 2];
      v_hdr[3] = (struct dao_virtio_net_hdr *) pkts[idx + 3];

      flags |= OCT_VIRT_NEXT_FLAG (v_hdr[0]);
      flags |= OCT_VIRT_NEXT_FLAG (v_hdr[1]);
      flags |= OCT_VIRT_NEXT_FLAG (v_hdr[2]);
      flags |= OCT_VIRT_NEXT_FLAG (v_hdr[3]);

      if (PREDICT_FALSE (flags))
	break;

      b[0] = oct_virt_to_bp (pkts[idx + 0], hdr_len);
      b[1] = oct_virt_to_bp (pkts[idx + 1], hdr_len);
      b[2] = oct_virt_to_bp (pkts[idx + 2], hdr_len);
      b[3] = oct_virt_to_bp (pkts[idx + 3], hdr_len);

      clib_prefetch_store (oct_virt_to_bp (pkts[idx + 4], hdr_len));
      clib_prefetch_store (oct_virt_to_bp (pkts[idx + 5], hdr_len));
      clib_prefetch_store (oct_virt_to_bp (pkts[idx + 6], hdr_len));
      clib_prefetch_store (oct_virt_to_bp (pkts[idx + 7], hdr_len));

      b[0]->template = bt;
      b[1]->template = bt;
      b[2]->template = bt;
      b[3]->template = bt;

      b[0]->current_length = OCT_VIRT_LENGTH (v_hdr[0]) - hdr_len;
      b[1]->current_length = OCT_VIRT_LENGTH (v_hdr[1]) - hdr_len;
      b[2]->current_length = OCT_VIRT_LENGTH (v_hdr[2]) - hdr_len;
      b[3]->current_length = OCT_VIRT_LENGTH (v_hdr[3]) - hdr_len;

      n_rx_bytes += b[0]->current_length;
      n_rx_bytes += b[1]->current_length;
      n_rx_bytes += b[2]->current_length;
      n_rx_bytes += b[3]->current_length;

      to_next[0] = vlib_get_buffer_index (vm, b[0]);
      to_next[1] = vlib_get_buffer_index (vm, b[1]);
      to_next[2] = vlib_get_buffer_index (vm, b[2]);
      to_next[3] = vlib_get_buffer_index (vm, b[3]);

      b += 4;
      idx += 4;
      to_next += 4;
      nb_pkts -= 4;
      next_nb_pkts += 4;
    }

  while (nb_pkts)
    {
      nb_pkts_chain = 1;
      v_hdr[0] = (struct dao_virtio_net_hdr *) pkts[idx];
      b[0] = oct_virt_to_bp (pkts[idx], hdr_len);
      b[0]->template = bt;

      if (OCT_VIRT_NEXT_FLAG (v_hdr[0]))
	b[0] = oct_virt_process_chained_packets (
	  vm, &pkts[idx], &nb_pkts_chain, &n_rx_bytes, hdr_len);
      else
	{
	  b[0]->current_length = OCT_VIRT_LENGTH (v_hdr[0]) - hdr_len;
	  n_rx_bytes += b[0]->current_length;
	  b[0]->current_data = 0;
	}

      to_next[0] = vlib_get_buffer_index (vm, b[0]);
      b++;
      idx += nb_pkts_chain;
      to_next++;
      nb_pkts -= nb_pkts_chain;
      next_nb_pkts++;
    }

  *n_rx_pkts = next_nb_pkts;

  return n_rx_bytes;
}

static_always_inline uword
oct_virtio_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame, vnet_dev_port_t *port,
			   vnet_dev_rx_queue_t *rxq)
{
  u64 q_map;
  u64 rx_q_map;
  u32 trace_count;
  u32 trace_enabled;
  oct_virtio_port_t *ovp;
  u32 cpu_id = vm->cpu_id;
  void *pkts[VLIB_FRAME_SIZE];
  u32 *to_next, n_left_to_next;
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  vnet_main_t *vnm = vnet_get_main ();
  u16 queue, virt_q, virtio_id, hdr_len;
  u32 thr_idx = vlib_get_thread_index ();
  oct_virtio_main_t *ovm = oct_virtio_main;
  u32 n_rx_pkts, n_rx_bytes = 0, rx_pkts_total = 0;
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;

  trace_enabled = trace_count = vlib_get_trace_count (vm, node);
  ovp = vnet_dev_get_port_data (port);
  virtio_id = ovp->virtio_id;

  if (PREDICT_FALSE (!ovm || !ovm->dao_lib_initialized))
    return 0;
  /* Assign DMA devices per lcore */
  if (PREDICT_FALSE (!ptd[cpu_id].initialized))
    {
      dao_pal_thread_init (cpu_id);
      dao_pal_dma_lcore_mem2dev_autofree_set (cpu_id, false);
      ptd[cpu_id].initialized = 1;
    }

  rx_q_map = ptd[cpu_id].q_map[virtio_id].qmap;
  q_map = ptd[cpu_id].q_map[virtio_id].qmap;

  if (!(ptd[cpu_id].netdev_map & (DAO_BIT (virtio_id))) || !q_map)
    return 0;

  /* Flush and submit DMA ops */
  dao_dma_flush_submit ();

  queue = ptd[cpu_id].q_map[virtio_id].last_rx_q;
  hdr_len = ptd[cpu_id].q_map[virtio_id].virtio_hdr_sz;

  while (rx_q_map)
    {
      if (!(rx_q_map & DAO_BIT (queue)))
	goto next;

      rx_q_map &= ~DAO_BIT (queue);
      virt_q = (queue << 1) + 1;

      n_rx_pkts = dao_virtio_net_dequeue_burst_ext (virtio_id, virt_q, pkts,
						    VLIB_FRAME_SIZE);

      if (!n_rx_pkts)
	goto next;

      vlib_get_new_next_frame (vm, node, rxq->next_index, to_next,
			       n_left_to_next);

      n_rx_bytes += oct_virtio_process_virtio_packets (vm, pkts, b, &n_rx_pkts,
						       to_next, rxq, hdr_len);

      if (PREDICT_FALSE (trace_count))
	trace_count -=
	  oct_virt_trace_rx_buffers (vm, node, b, n_rx_pkts, trace_count,
				     q_map, virtio_id, rxq->next_index);

      if (PREDICT_TRUE (rxq->next_index ==
			VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf = vlib_node_runtime_get_next_frame (vm, node, rxq->next_index);
	  f = vlib_get_frame (vm, nf->frame);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
	  /**
	   * We can set the checksum as OK because, in the host checksum
	   * offload case, OCTEON Tx will perform the checksum computation. In
	   * the host non-checksum offload case, the host computes the checksum
	   * and provides it to OCTEON.
	   */
	  f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = port->intf.sw_if_index;
	  ef->hw_if_index = port->intf.hw_if_index;

	  vlib_frame_no_append (f);
	}

      n_left_to_next -= n_rx_pkts;

      vlib_put_next_frame (vm, node, rxq->next_index, n_left_to_next);
      rx_pkts_total += n_rx_pkts;

      if (rx_pkts_total == VLIB_FRAME_SIZE)
	break;
    next:
      queue = queue + 1;
      if (DAO_BIT (queue) > q_map)
	queue = 0;
    }

  ptd[cpu_id].q_map[virtio_id].last_rx_q = queue;

  if (PREDICT_FALSE (trace_enabled))
    vlib_set_trace_count (vm, node, trace_count);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, port->intf.hw_if_index, rx_pkts_total, n_rx_bytes);

  return rx_pkts_total;
}

VNET_DEV_NODE_FN (oct_virtio_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;
      n_rx += oct_virtio_rx_node_inline (vm, node, frame, port, rxq);
    }

  return n_rx;
}
