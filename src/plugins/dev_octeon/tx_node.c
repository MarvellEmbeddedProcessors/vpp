/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
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

#include <dev_octeon/octeon.h>
#include <dev_octeon/ipsec.h>

#define OCT_TX_NODE	     (1 << 0)
#define OCT_TX_IPSEC_TM_NODE (1 << 1)

#define OCT_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                              \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

#define OCT_SEND_HDR_DWORDS 1

/*
 * Encoded number of segments to number of dwords macro,
 * each value of nb_segs is encoded as 4bits.
 */
#define NIX_SEGDW_MAGIC		0x76654432210ULL
#define NIX_NB_SEGS_TO_SEGDW(x) ((NIX_SEGDW_MAGIC >> ((x) << 2)) & 0xF)

typedef struct
{
  union nix_send_hdr_w0_u hdr_w0_teplate;
  vlib_node_runtime_t *node;
  u32 n_tx_bytes;
  u32 n_drop;
  vlib_buffer_t *drop[VLIB_FRAME_SIZE];
  u32 n_exd_mtu;
  vlib_buffer_t *exd_mtu[VLIB_FRAME_SIZE];
  u32 batch_alloc_not_ready;
  u32 batch_alloc_issue_fail;
  int max_pkt_len;
  u16 lmt_id;
  u64 lmt_ioaddr;
  lmt_line_t *lmt_lines;
} oct_tx_ctx_t;

#ifdef PLATFORM_OCTEON9
static_always_inline u32
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
		const u64 flags)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u16 off = ctq->hdr_off;
  u64 ah = ctq->aura_handle;
  u32 n_freed = 0, n;

  ah = ctq->aura_handle;

  if ((n = roc_npa_aura_op_available (ah)) >= 32)
    {
      u64 buffers[n];
      u32 bi[n];

      if (flags & OCT_TX_NODE)
	n = clib_min (n, ctq->n_enq);
      n_freed = roc_npa_aura_op_bulk_alloc (ah, buffers, n, 0, 1);
      vlib_get_buffer_indices_with_offset (vm, (void **) &buffers, bi, n_freed,
					   off);
      vlib_buffer_free_no_next (vm, bi, n_freed);
    }

  return n_freed;
}

static_always_inline void
oct_lmt_copy (void *lmt_addr, u64 io_addr, void *desc, u64 dwords)
{
  u64 lmt_status;

  do
    {
      roc_lmt_mov_seg (lmt_addr, desc, dwords);
      lmt_status = roc_lmt_submit_ldeor (io_addr);
    }
  while (lmt_status == 0);
}
#else
static_always_inline u32
oct_batch_free (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
		const u64 flags)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  oct_npa_batch_alloc_cl128_t *cl;
  u32 n_freed = 0, n, n_alloc;
  u8 num_cl;
  u64 ah;

  if (flags & OCT_TX_NODE)
    n_alloc = clib_min (ctq->n_enq, ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);
  else
    n_alloc = ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS;

  num_cl = ctq->ba_num_cl;
  if (num_cl)
    {
      u16 off = ctq->hdr_off;
      u32 *bi = (u32 *) ctq->ba_buffer;

      for (cl = ctq->ba_buffer + ctq->ba_first_cl; num_cl > 0; num_cl--, cl++)
	{
	  oct_npa_batch_alloc_status_t st;

	  if ((st.as_u64 = __atomic_load_n (cl->iova, __ATOMIC_RELAXED)) ==
	      OCT_BATCH_ALLOC_IOVA0_MASK + ALLOC_CCODE_INVAL)
	    {
	    cl_not_ready:
	      ctx->batch_alloc_not_ready++;
	      n_freed = bi - (u32 *) ctq->ba_buffer;
	      if (n_freed > 0)
		{
		  vlib_buffer_free_no_next (vm, (u32 *) ctq->ba_buffer,
					    n_freed);
		  ctq->ba_num_cl = num_cl;
		  ctq->ba_first_cl = cl - ctq->ba_buffer;
		  return n_freed;
		}

	      return 0;
	    }

	  if (st.status.count > 8 &&
	      __atomic_load_n (cl->iova + 8, __ATOMIC_RELAXED) ==
		OCT_BATCH_ALLOC_IOVA0_MASK)
	    goto cl_not_ready;

#if (CLIB_DEBUG > 0)
	  cl->iova[0] &= OCT_BATCH_ALLOC_IOVA0_MASK;
#endif
	  if (PREDICT_TRUE (st.status.count == 16))
	    {
	      /* optimize for likely case where cacheline is full */
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi, 16,
						   off);
	      bi += 16;
	    }
	  else
	    {
	      vlib_get_buffer_indices_with_offset (vm, (void **) cl, bi,
						   st.status.count, off);
	      bi += st.status.count;
	    }
	}

      n_freed = bi - (u32 *) ctq->ba_buffer;
      if (n_freed > 0)
	vlib_buffer_free_no_next (vm, (u32 *) ctq->ba_buffer, n_freed);

      /* clear status bits in each cacheline */
      n = cl - ctq->ba_buffer;
      for (u32 i = 0; i < n; i++)
	ctq->ba_buffer[i].iova[0] = ctq->ba_buffer[i].iova[8] =
	  OCT_BATCH_ALLOC_IOVA0_MASK;

      ctq->ba_num_cl = ctq->ba_first_cl = 0;
    }

  ah = ctq->aura_handle;

  if ((n = roc_npa_aura_op_available (ah)) >= 32)
    {
      u64 addr, res;

      n = clib_min (n, n_alloc);

      oct_npa_batch_alloc_compare_t cmp = {
	.compare_s = { .aura = roc_npa_aura_handle_to_aura (ah),
		       .stype = ALLOC_STYPE_STF,
		       .count = n }
      };

      addr = roc_npa_aura_handle_to_base (ah) + NPA_LF_AURA_BATCH_ALLOC;
      res = roc_atomic64_casl (cmp.as_u64, (uint64_t) ctq->ba_buffer,
			       (i64 *) addr);
      if (res == ALLOC_RESULT_ACCEPTED || res == ALLOC_RESULT_NOCORE)
	{
	  ctq->ba_num_cl = (n + 15) / 16;
	  ctq->ba_first_cl = 0;
	}
      else
	ctx->batch_alloc_issue_fail++;
    }

  return n_freed;
}
#endif

static_always_inline u8
oct_tx_enq1 (vlib_main_t *vm, oct_tx_ctx_t *ctx, vlib_buffer_t *b,
	     lmt_line_t *line, u32 flags, int simple, int trace, u32 *n,
	     u8 *dpl)
{
  u8 n_dwords = 2;
  u32 total_len = 0;
  oct_tx_desc_t d = {
    .hdr_w0 = ctx->hdr_w0_teplate,
    .sg[0] = {
      .segs = 1,
      .subdc = NIX_SUBDC_SG,
    },
    .sg[4] = {
      .subdc = NIX_SUBDC_SG,
    },
  };

  if (PREDICT_FALSE (vlib_buffer_length_in_chain (vm, b) > ctx->max_pkt_len))
    {
      ctx->exd_mtu[ctx->n_exd_mtu++] = b;
      return 0;
    }

#ifdef PLATFORM_OCTEON9
  /* Override line for Octeon9 */
  line = ctx->lmt_lines;
#endif

  if (!simple && flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u8 n_tail_segs = 0;
      vlib_buffer_t *tail_segs[5], *t = b;

      while (t->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  t = vlib_get_buffer (vm, t->next_buffer);
	  tail_segs[n_tail_segs++] = t;
	  if (n_tail_segs > 5)
	    {
	      ctx->drop[ctx->n_drop++] = b;
	      return 0;
	    }
	}

      switch (n_tail_segs)
	{
	case 5:
	  d.sg[7].u = (u64) vlib_buffer_get_current (tail_segs[4]);
	  total_len += d.sg[4].seg3_size = tail_segs[4]->current_length;
	  d.sg[4].segs++;
	case 4:
	  d.sg[6].u = (u64) vlib_buffer_get_current (tail_segs[3]);
	  total_len += d.sg[4].seg2_size = tail_segs[3]->current_length;
	  d.sg[4].segs++;
	  n_dwords++;
	case 3:
	  d.sg[5].u = (u64) vlib_buffer_get_current (tail_segs[2]);
	  total_len += d.sg[4].seg1_size = tail_segs[2]->current_length;
	  d.sg[4].segs++;
	  n_dwords++;
	case 2:
	  d.sg[3].u = (u64) vlib_buffer_get_current (tail_segs[1]);
	  total_len += d.sg[0].seg3_size = tail_segs[1]->current_length;
	  d.sg[0].segs++;
	case 1:
	  d.sg[2].u = (u64) vlib_buffer_get_current (tail_segs[0]);
	  total_len += d.sg[0].seg2_size = tail_segs[0]->current_length;
	  d.sg[0].segs++;
	  n_dwords++;
	default:
	  break;
	};
      d.hdr_w0.sizem1 = n_dwords - 1;
    }

  if (!simple && flags & VNET_BUFFER_F_OFFLOAD)
    {
      vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  d.hdr_w1.ol3type = NIX_SENDL3TYPE_IP4_CKSUM;
	  d.hdr_w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset - b->current_data;
	  d.hdr_w1.ol4ptr = d.hdr_w1.ol3ptr + sizeof (ip4_header_t);
	}
      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  d.hdr_w1.ol4type = NIX_SENDL4TYPE_UDP_CKSUM;
	  d.hdr_w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  d.hdr_w1.ol4type = NIX_SENDL4TYPE_TCP_CKSUM;
	  d.hdr_w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
    }

  total_len += d.sg[0].seg1_size = b->current_length;
  d.hdr_w0.total = total_len;
  d.sg[1].u = (u64) vlib_buffer_get_current (b);

  if (trace && flags & VLIB_BUFFER_IS_TRACED)
    {
      oct_tx_trace_t *t = vlib_add_trace (vm, ctx->node, b, sizeof (*t));
      t->desc = d;
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
    }

#ifdef PLATFORM_OCTEON9
  oct_lmt_copy (line, ctx->lmt_ioaddr, &d, n_dwords);
#else
  for (u32 i = 0; i < n_dwords; i++)
    line->dwords[i] = d.as_u128[i];
#endif

  *dpl = n_dwords;
  *n = *n + 1;

  return n_dwords;
}

static_always_inline u32
oct_tx_enq16 (vlib_main_t *vm, oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
	      vlib_buffer_t **b, u32 n_pkts, int trace)
{
  u8 dwords_per_line[16], *dpl = dwords_per_line;
  u64 __attribute__ ((unused)) lmt_arg, ioaddr, n_lines;
  u32 __attribute__ ((unused)) or_flags_16 = 0;
  u32 n_left, n = 0;
  const u32 not_simple_flags =
    VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD;
  lmt_line_t *l = ctx->lmt_lines;

  /* Data Store Memory Barrier - outer shareable domain */
  asm volatile("dmb oshst" ::: "memory");

  for (n_left = n_pkts; n_left >= 8; n_left -= 8, b += 8)
    {
      u32 f0, f1, f2, f3, f4, f5, f6, f7, or_f = 0;
      vlib_prefetch_buffer_header (b[8], LOAD);
      or_f |= f0 = b[0]->flags;
      or_f |= f1 = b[1]->flags;
      vlib_prefetch_buffer_header (b[9], LOAD);
      or_f |= f2 = b[2]->flags;
      or_f |= f3 = b[3]->flags;
      vlib_prefetch_buffer_header (b[10], LOAD);
      or_f |= f4 = b[4]->flags;
      or_f |= f5 = b[5]->flags;
      vlib_prefetch_buffer_header (b[11], LOAD);
      or_f |= f6 = b[6]->flags;
      or_f |= f7 = b[7]->flags;
      vlib_prefetch_buffer_header (b[12], LOAD);
      or_flags_16 |= or_f;

      if ((or_f & not_simple_flags) == 0)
	{
	  int simple = 1;
	  oct_tx_enq1 (vm, ctx, b[0], l, f0, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[1], l + n, f1, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  oct_tx_enq1 (vm, ctx, b[2], l + n, f2, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[3], l + n, f3, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  oct_tx_enq1 (vm, ctx, b[4], l + n, f4, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[5], l + n, f5, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	  oct_tx_enq1 (vm, ctx, b[6], l + n, f6, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[7], l + n, f7, simple, trace, &n, &dpl[n]);
	}
      else
	{
	  int simple = 0;
	  oct_tx_enq1 (vm, ctx, b[0], l, f0, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[1], l + n, f1, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  oct_tx_enq1 (vm, ctx, b[2], l + n, f2, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[3], l + n, f3, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  oct_tx_enq1 (vm, ctx, b[4], l + n, f4, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[5], l + n, f5, simple, trace, &n, &dpl[n]);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	  oct_tx_enq1 (vm, ctx, b[6], l + n, f6, simple, trace, &n, &dpl[n]);
	  oct_tx_enq1 (vm, ctx, b[7], l + n, f7, simple, trace, &n, &dpl[n]);
	}
      dpl += n;
      l += n;
      n = 0;
    }

  for (; n_left > 0; n_left -= 1, b += 1)
    {
      u32 f0 = b[0]->flags;
      oct_tx_enq1 (vm, ctx, b[0], l, f0, 0, trace, &n, &dpl[n]);
      or_flags_16 |= f0;
      dpl += n;
      l += n;
      n = 0;
    }

  lmt_arg = ctx->lmt_id;
  ioaddr = ctx->lmt_ioaddr;
  n_lines = dpl - dwords_per_line;

  if (PREDICT_FALSE (!n_lines))
    return n_pkts;

#ifndef PLATFORM_OCTEON9
  if (PREDICT_FALSE (or_flags_16 & VLIB_BUFFER_NEXT_PRESENT))
    {
      dpl = dwords_per_line;
      ioaddr |= (dpl[0] - 1) << 4;

      if (n_lines > 1)
	{
	  lmt_arg |= (--n_lines) << 12;

	  for (u8 bit_off = 19; n_lines; n_lines--, bit_off += 3, dpl++)
	    lmt_arg |= ((u64) dpl[1] - 1) << bit_off;
	}
    }
  else
    {
      const u64 n_dwords = 2;
      ioaddr |= (n_dwords - 1) << 4;

      if (n_lines > 1)
	{
	  lmt_arg |= (--n_lines) << 12;

	  for (u8 bit_off = 19; n_lines; n_lines--, bit_off += 3)
	    lmt_arg |= (n_dwords - 1) << bit_off;
	}
    }

  roc_lmt_submit_steorl (lmt_arg, ioaddr);
#endif

  return n_pkts;
}

static inline u16
oct_check_fc_nix (struct roc_nix_sq *sq, i32 *fc_cache, u16 pkts)
{
  i32 val, new_val, depth;
  u8 retry_count = 32;

  do
    {
      /* Reduce the cached count */
      val = (i32) __atomic_sub_fetch (fc_cache, pkts, __ATOMIC_RELAXED);
      if (val >= 0)
	return pkts;

      depth = sq->nb_sqb_bufs_adj -
	      __atomic_load_n ((u64 *) sq->fc, __ATOMIC_RELAXED);

      if (depth <= 0)
	return 0;

      /* Update cached value (fc_cache) when lower than `pkts` */
      new_val = (depth << sq->sqes_per_sqb_log2) - pkts;
      if (PREDICT_FALSE (new_val < 0))
	return 0;

      /* Update fc_cache if there is no update done by other cores */
      if (__atomic_compare_exchange_n (fc_cache, &val, new_val, false,
				       __ATOMIC_RELAXED, __ATOMIC_RELAXED))
	return pkts;
    }
  while (retry_count--);

  return 0;
}

static inline u16
oct_check_fc_cpt (struct roc_cpt_lf *cpt_lf, u32 *fc_cache, u16 pkts)
{
  i32 val, new_val, depth;
  u8 retry_count = 32;

  do
    {
      /* Reduce the cached count */
      val = (i32) __atomic_sub_fetch (fc_cache, pkts, __ATOMIC_RELAXED);
      if (val >= 0)
	return pkts;

      depth = cpt_lf->nb_desc - clib_atomic_load_relax_n (cpt_lf->fc_addr);

      if (depth <= 0)
	return 0;
      new_val = depth - pkts;
      if (PREDICT_FALSE (new_val < 0))
	return 0;

      /* Update fc_cache if there is no update done by other cores */
      if (__atomic_compare_exchange_n (fc_cache, (u32 *) &val, new_val, false,
				       __ATOMIC_RELAXED, __ATOMIC_RELAXED))
	return pkts;
    }
  while (retry_count--);
  return 0;
}

static_always_inline u64
oct_add_sg_desc (union nix_send_sg_s *sg, int n_segs, vlib_buffer_t *seg1,
		 vlib_buffer_t *seg2, vlib_buffer_t *seg3)
{
  sg[0].u = 0;
  sg[0].segs = n_segs;
  sg[0].subdc = NIX_SUBDC_SG;

  switch (n_segs)
    {
    case 3:
      sg[0].seg3_size = seg3->current_length;
      sg[3].u = (u64) vlib_buffer_get_current (seg3);
      /* Fall through */
    case 2:
      sg[0].seg2_size = seg2->current_length;
      sg[2].u = (u64) vlib_buffer_get_current (seg2);
      /* Fall through */
    case 1:
      sg[0].seg1_size = seg1->current_length;
      sg[1].u = (u64) vlib_buffer_get_current (seg1);
      break;
    default:
      ASSERT (0);
      return 0;
    }

  /* Return number of dwords in sub-descriptor */
  return n_segs == 1 ? 1 : 2;
}

static_always_inline u64
oct_add_sg_list (union nix_send_sg_s *sg, vlib_buffer_t *b, u64 n_segs)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *seg1, *seg2, *seg3;
  u64 n_dwords;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return oct_add_sg_desc (sg, 1, b, NULL, NULL);

  seg1 = b;
  n_dwords = 0;
  while (n_segs > 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      seg3 = vlib_get_buffer (vm, seg2->next_buffer);

      n_dwords += oct_add_sg_desc (sg, 3, seg1, seg2, seg3);

      if (seg3->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  seg1 = vlib_get_buffer (vm, seg3->next_buffer);
	  sg += 4;
	}
      n_segs -= 3;
    }

  if (n_segs == 1)
    n_dwords += oct_add_sg_desc (sg, 1, seg1, NULL, NULL);
  else if (n_segs == 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      n_dwords += oct_add_sg_desc (sg, 2, seg1, seg2, NULL);
    }

  return n_dwords;
}

static_always_inline u64
oct_add_send_hdr (struct nix_send_hdr_s *hdr, vlib_buffer_t *b,
		  u64 aura_handle, u64 sq, u64 n_dwords)
{
  vnet_buffer_oflags_t oflags;

  hdr->w0.u = 0;
  hdr->w1.u = 0;
  hdr->w0.sq = sq;
  hdr->w0.aura = roc_npa_aura_handle_to_aura (aura_handle);
  hdr->w0.total = b->current_length;
  hdr->w0.sizem1 = n_dwords + OCT_SEND_HDR_DWORDS - 1;

  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    hdr->w0.total = vlib_buffer_length_in_chain (vlib_get_main (), b);

  if (!(b->flags & VNET_BUFFER_F_OFFLOAD))
    return OCT_SEND_HDR_DWORDS;

  if (b->flags & VNET_BUFFER_F_OFFLOAD)
    {
      oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  hdr->w1.ol3type = NIX_SENDL3TYPE_IP4_CKSUM;
	  hdr->w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset - b->current_data;
	  hdr->w1.ol4ptr = hdr->w1.ol3ptr + sizeof (ip4_header_t);
	}

      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  hdr->w1.ol4type = NIX_SENDL4TYPE_UDP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  hdr->w1.ol4type = NIX_SENDL4TYPE_TCP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset - b->current_data;
	}
    }
  return OCT_SEND_HDR_DWORDS;
}

static_always_inline void
oct_ipsec_append_next_buffer (vlib_main_t *vm, vlib_buffer_t *buffer,
			      uint16_t bytes_to_append)
{
  u32 buffer_index = 0;
  vlib_buffer_t *tmp;

  if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return;
    }

  tmp = vlib_get_buffer (vm, buffer_index);
  buffer->next_buffer = buffer_index;
  buffer->flags |= VLIB_BUFFER_NEXT_PRESENT;
  buffer->total_length_not_including_first_buffer = 0;
  tmp->current_length += bytes_to_append;
}

static_always_inline uint32_t
oct_ipsec_fill_sg2_buf (vlib_main_t *vm, struct roc_sg2list_comp *list, int i,
			vlib_buffer_t **lb)
{
  struct roc_sg2list_comp *to;

  to = &list[i / 3];
  to->u.s.len[i % 3] = lb[0]->current_length;
  to->ptr[i % 3] = (u64) vlib_buffer_get_current (lb[0]);
  to->u.s.valid_segs = (i % 3) + 1;
  i++;

  while (lb[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      to = &list[i / 3];
      lb[0] = vlib_get_buffer (vm, lb[0]->next_buffer);
      to->ptr[i % 3] = (u64) vlib_buffer_get_current (lb[0]);
      to->u.s.len[i % 3] = lb[0]->current_length;
      to->u.s.valid_segs = (i % 3) + 1;
      i++;
    }

  return i;
}

static_always_inline int
oct_ipsec_outb_prepare_sg2_list (vlib_main_t *vm, vlib_buffer_t *b,
				 struct cpt_inst_s *inst, u32 bytes_to_append,
				 u32 dlen,
				 oct_ipsec_outbound_pkt_meta_t **pkt_meta,
				 u64 *n_dwords, oct_ipsec_session_t *sess)
{
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  struct roc_sg2list_comp *scatter_comp, *gather_comp;
  void *m_data = (void *) pkt_meta[0]->sg_buffer;
  union nix_send_sg_s *sg;
  union cpt_inst_w5 cpt_inst_w5;
  union cpt_inst_w6 cpt_inst_w6;
  vlib_buffer_t *last_buf = b;
  int n_segs;

  /* Input Gather List */
  n_segs = 0;
  gather_comp = (struct roc_sg2list_comp *) ((uint8_t *) m_data + 64);

  n_segs = oct_ipsec_fill_sg2_buf (vm, gather_comp, n_segs, &last_buf);

  cpt_inst_w5.s.gather_sz = ((n_segs + 2) / 3);

  if ((bytes_to_append + last_buf->current_length) > buffer_data_size)
    {
      /* Need an extra buffer */
      oct_ipsec_append_next_buffer (vm, last_buf, bytes_to_append);
    }
  else
    {
      vlib_buffer_put_uninit (last_buf, bytes_to_append);
    }

  last_buf = b;

  /* Output Gather List */
  n_segs = 0;
  scatter_comp = (struct roc_sg2list_comp *) ((uint8_t *) m_data);

  n_segs = oct_ipsec_fill_sg2_buf (vm, scatter_comp, n_segs, &last_buf);

  cpt_inst_w6.s.scatter_sz = ((n_segs + 2) / 3);
  cpt_inst_w5.s.dptr = (uint64_t) gather_comp;

  cpt_inst_w6.s.rptr = (uint64_t) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;
  inst->w4.s.dlen = dlen;
  inst->w4.s.opcode_major &= (~(ROC_IE_OT_INPLACE_BIT));

  b->total_length_not_including_first_buffer += bytes_to_append;

  sg = (union nix_send_sg_s *) (pkt_meta[0]->nixtx + 2);
  inst->w0.u64 = (uint64_t) vnet_buffer (b)->l3_hdr_offset << 16;
  inst->w0.u64 |= NIX_NB_SEGS_TO_SEGDW (n_segs);
  inst->w0.u64 |=
    (((int64_t) pkt_meta[0]->nixtx - (int64_t) inst->dptr) & 0xFFFFF) << 32;
  n_dwords[0] = (n_segs % 3) + (n_segs / 3) * 2;
  sg[0].subdc = NIX_SUBDC_SG;
  sg[4].subdc = NIX_SUBDC_SG;

  return n_segs;
}

static_always_inline u32
oct_get_tx_vlib_buf_segs (vlib_main_t *vm, vlib_buffer_t *b)
{
  /* Each buffer will have atleast 1 segment */
  u32 n_segs = 1;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return n_segs;

  do
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      n_segs++;
    }
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);

  return n_segs;
}

static_always_inline i32
oct_ipsec_rlen_get (oct_ipsec_encap_len_t *encap, uint32_t plen)
{
  uint32_t enc_payload_len;

  enc_payload_len = round_pow2 (plen + encap->roundup_len - encap->adj_len,
				encap->roundup_byte);

  return encap->partial_len + enc_payload_len + encap->adj_len;
}

static_always_inline u32
oct_ipsec_esp_add_footer_and_icv (oct_ipsec_encap_len_t *encap, u32 rlen)
{
  /* plain_text len + pad_bytes + ESP_footer size + icv_len */
  return rlen + encap->icv_len - encap->partial_len;
}

void static_always_inline
oct_prepare_ipsec_inst (vlib_main_t *vm, vlib_buffer_t *b, u64 sq_handle,
			u64 aura_handle,
			oct_ipsec_outbound_pkt_meta_t **pkt_meta,
			struct cpt_inst_s *inst, u64 *n_dwords,
			oct_ipsec_session_t *sess)
{
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  struct nix_send_hdr_s *send_hdr;
  union nix_send_sg_s *sg;
  u64 n_segs;
  u16 total_length, dlen_adj;
  u16 l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
  u32 dlen, rlen, sa_bytes;

  send_hdr = (struct nix_send_hdr_s *) pkt_meta[0]->nixtx;

  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      total_length =
	b->current_length + b->total_length_not_including_first_buffer;
      dlen = total_length - l3_hdr_offset;
      rlen = oct_ipsec_rlen_get (&sess->encap, dlen);
      dlen_adj = rlen - dlen;

      inst->w4.u64 = sess->inst.w4.u64;

      n_segs = oct_ipsec_outb_prepare_sg2_list (
	vm, b, inst, dlen_adj, total_length, pkt_meta, n_dwords, sess);
    }
  else
    {
      dlen = b->current_length - l3_hdr_offset;

      rlen = oct_ipsec_rlen_get (&sess->encap, dlen);
      dlen_adj = rlen - dlen;

      if (rlen > buffer_data_size)
	{
	  inst->w4.u64 = sess->inst.w4.u64;

	  n_segs = oct_ipsec_outb_prepare_sg2_list (vm, b, inst, dlen_adj,
						    b->current_length,
						    pkt_meta, n_dwords, sess);
	}
      else
	{
	  sg = (union nix_send_sg_s *) (pkt_meta[0]->nixtx + 2);

	  inst->dptr =
	    (u64) ((u8 *) vlib_buffer_get_current (b) + l3_hdr_offset);
	  inst->rptr = inst->dptr;
	  /* Set w0 nixtx_offset */
	  inst->w0.u64 |=
	    (((int64_t) pkt_meta[0]->nixtx - (int64_t) inst->dptr) & 0xFFFFF)
	    << 32;
	  inst->w0.u64 |= 1;
	  inst->w4.u64 = sess->inst.w4.u64 | dlen;

	  b->current_length += dlen_adj;
	  n_segs = oct_get_tx_vlib_buf_segs (vm, b);
	  n_dwords[0] = oct_add_sg_list (sg, b, n_segs);
	}
    }

  oct_add_send_hdr (send_hdr, b, aura_handle, sq_handle, n_dwords[0]);

  sa_bytes = oct_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
  vlib_increment_combined_counter (
    &ipsec_sa_counters, vlib_get_thread_index (),
    vnet_buffer (b)->ipsec.sad_index, 1, sa_bytes);
}

void static_always_inline
oct_submit_quad_packets (u64 lmt_arg, oct_device_t *cd,
			 struct cpt_inst_s *inst0, struct cpt_inst_s *inst1,
			 struct cpt_inst_s *inst2, struct cpt_inst_s *inst3,
			 u64 *n_dwords, u64 **lmt_line)
{
  roc_lmt_mov_seg ((void *) lmt_line[0], inst0, 4);
  roc_lmt_mov_seg ((void *) lmt_line[1], inst1, 4);
  roc_lmt_mov_seg ((void *) lmt_line[2], inst2, 4);
  roc_lmt_mov_seg ((void *) lmt_line[3], inst3, 4);

  /* Count minus one of LMTSTs in the burst */
  lmt_arg |= 3 << 12;

  /*
   * Vector of sizes of each LMTST in the burst. Every 3 bits
   * represents size - 1 of one LMTST, except first.
   */
  lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
  lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
  lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));

  roc_lmt_submit_steorl (lmt_arg, cd->cpt_io_addr);

  asm volatile ("dmb oshst" ::: "memory");
}

i32 static_always_inline
oct_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node, oct_tx_ctx_t *ctx,
	       vnet_dev_tx_queue_t *txq, u16 tx_pkts, vlib_buffer_t **bufs)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u32 desc_sz = 10 /* Worst case - Send hdr + Two SG with 3 segs each */;
  union nix_send_sg_s *sg8, *sg9, *sg10, *sg11, *sg12, *sg13, *sg14, *sg15;
  struct nix_send_hdr_s *send_hdr12, *send_hdr13, *send_hdr14, *send_hdr15;
  struct nix_send_hdr_s *send_hdr8, *send_hdr9, *send_hdr10, *send_hdr11;
  u64 desc12[desc_sz], desc13[desc_sz], desc14[desc_sz], desc15[desc_sz];
  u64 desc8[desc_sz], desc9[desc_sz], desc10[desc_sz], desc11[desc_sz];
  struct nix_send_hdr_s *send_hdr4, *send_hdr5, *send_hdr6, *send_hdr7;
  struct nix_send_hdr_s *send_hdr0, *send_hdr1, *send_hdr2, *send_hdr3;
  union nix_send_sg_s *sg0, *sg1, *sg2, *sg3, *sg4, *sg5, *sg6, *sg7;
  u64 desc0[desc_sz], desc1[desc_sz], desc2[desc_sz], desc3[desc_sz];
  u64 desc4[desc_sz], desc5[desc_sz], desc6[desc_sz], desc7[desc_sz];
  u64 io_addr, sq_handle, n_dwords[16], n_packets;
  void *lmt_line12, *lmt_line13, *lmt_line14, *lmt_line15;
  void *lmt_line8, *lmt_line9, *lmt_line10, *lmt_line11;
  void *lmt_line0, *lmt_line1, *lmt_line2, *lmt_line3;
  void *lmt_line4, *lmt_line5, *lmt_line6, *lmt_line7;
  u64 n_segs[16], aura_handle;
  u64 lmt_arg, core_lmt_base_addr, core_lmt_id;
  u16 n_drop = 0;
  u32 from[VLIB_FRAME_SIZE];
  struct roc_nix_sq *sq;
  vlib_buffer_t **b;

  sq = &ctq->sq;
  b = bufs;
  io_addr = sq->io_addr;
  sq_handle = sq->qid;
  aura_handle = ctq->aura_handle;

  if (PREDICT_FALSE (ctq->cached_pkts < tx_pkts))
    {
      ctq->cached_pkts = (sq->nb_sqb_bufs_adj - *((u64 *) sq->fc))
			 << sq->sqes_per_sqb_log2;

      if (PREDICT_FALSE (ctq->cached_pkts < tx_pkts))
	{
	  if (ctq->cached_pkts < 0)
	    {
	      n_drop = tx_pkts;
	      tx_pkts = 0;
	      goto free_pkts;
	    }
	  n_drop = tx_pkts - ctq->cached_pkts;
	  tx_pkts = ctq->cached_pkts;
	}
    }

  send_hdr0 = (struct nix_send_hdr_s *) &desc0[0];
  send_hdr1 = (struct nix_send_hdr_s *) &desc1[0];
  send_hdr2 = (struct nix_send_hdr_s *) &desc2[0];
  send_hdr3 = (struct nix_send_hdr_s *) &desc3[0];
  send_hdr4 = (struct nix_send_hdr_s *) &desc4[0];
  send_hdr5 = (struct nix_send_hdr_s *) &desc5[0];
  send_hdr6 = (struct nix_send_hdr_s *) &desc6[0];
  send_hdr7 = (struct nix_send_hdr_s *) &desc7[0];
  send_hdr8 = (struct nix_send_hdr_s *) &desc8[0];
  send_hdr9 = (struct nix_send_hdr_s *) &desc9[0];
  send_hdr10 = (struct nix_send_hdr_s *) &desc10[0];
  send_hdr11 = (struct nix_send_hdr_s *) &desc11[0];
  send_hdr12 = (struct nix_send_hdr_s *) &desc12[0];
  send_hdr13 = (struct nix_send_hdr_s *) &desc13[0];
  send_hdr14 = (struct nix_send_hdr_s *) &desc14[0];
  send_hdr15 = (struct nix_send_hdr_s *) &desc15[0];

  sg0 = (union nix_send_sg_s *) &desc0[2];
  sg1 = (union nix_send_sg_s *) &desc1[2];
  sg2 = (union nix_send_sg_s *) &desc2[2];
  sg3 = (union nix_send_sg_s *) &desc3[2];
  sg4 = (union nix_send_sg_s *) &desc4[2];
  sg5 = (union nix_send_sg_s *) &desc5[2];
  sg6 = (union nix_send_sg_s *) &desc6[2];
  sg7 = (union nix_send_sg_s *) &desc7[2];
  sg8 = (union nix_send_sg_s *) &desc8[2];
  sg9 = (union nix_send_sg_s *) &desc9[2];
  sg10 = (union nix_send_sg_s *) &desc10[2];
  sg11 = (union nix_send_sg_s *) &desc11[2];
  sg12 = (union nix_send_sg_s *) &desc12[2];
  sg13 = (union nix_send_sg_s *) &desc13[2];
  sg14 = (union nix_send_sg_s *) &desc14[2];
  sg15 = (union nix_send_sg_s *) &desc15[2];

  core_lmt_base_addr = (u64) sq->lmt_addr;
  ROC_LMT_BASE_ID_GET (core_lmt_base_addr, core_lmt_id);

  lmt_line0 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 0);
  lmt_line1 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 1);
  lmt_line2 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 2);
  lmt_line3 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 3);
  lmt_line4 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 4);
  lmt_line5 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 5);
  lmt_line6 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 6);
  lmt_line7 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 7);
  lmt_line8 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 8);
  lmt_line9 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 9);
  lmt_line10 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 10);
  lmt_line11 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 11);
  lmt_line12 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 12);
  lmt_line13 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 13);
  lmt_line14 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 14);
  lmt_line15 = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 15);

  n_packets = tx_pkts;

  while (n_packets > 16)
    {
      n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b[0]);
      n_segs[1] = oct_get_tx_vlib_buf_segs (vm, b[1]);
      n_segs[2] = oct_get_tx_vlib_buf_segs (vm, b[2]);
      n_segs[3] = oct_get_tx_vlib_buf_segs (vm, b[3]);
      n_segs[4] = oct_get_tx_vlib_buf_segs (vm, b[4]);
      n_segs[5] = oct_get_tx_vlib_buf_segs (vm, b[5]);
      n_segs[6] = oct_get_tx_vlib_buf_segs (vm, b[6]);
      n_segs[7] = oct_get_tx_vlib_buf_segs (vm, b[7]);
      n_segs[8] = oct_get_tx_vlib_buf_segs (vm, b[8]);
      n_segs[9] = oct_get_tx_vlib_buf_segs (vm, b[9]);
      n_segs[10] = oct_get_tx_vlib_buf_segs (vm, b[10]);
      n_segs[11] = oct_get_tx_vlib_buf_segs (vm, b[11]);
      n_segs[12] = oct_get_tx_vlib_buf_segs (vm, b[12]);
      n_segs[13] = oct_get_tx_vlib_buf_segs (vm, b[13]);
      n_segs[14] = oct_get_tx_vlib_buf_segs (vm, b[14]);
      n_segs[15] = oct_get_tx_vlib_buf_segs (vm, b[15]);

      n_dwords[0] = oct_add_sg_list (sg0, b[0], n_segs[0]);
      n_dwords[1] = oct_add_sg_list (sg1, b[1], n_segs[1]);
      n_dwords[2] = oct_add_sg_list (sg2, b[2], n_segs[2]);
      n_dwords[3] = oct_add_sg_list (sg3, b[3], n_segs[3]);
      n_dwords[4] = oct_add_sg_list (sg4, b[4], n_segs[4]);
      n_dwords[5] = oct_add_sg_list (sg5, b[5], n_segs[5]);
      n_dwords[6] = oct_add_sg_list (sg6, b[6], n_segs[6]);
      n_dwords[7] = oct_add_sg_list (sg7, b[7], n_segs[7]);
      n_dwords[8] = oct_add_sg_list (sg8, b[8], n_segs[8]);
      n_dwords[9] = oct_add_sg_list (sg9, b[9], n_segs[9]);
      n_dwords[10] = oct_add_sg_list (sg10, b[10], n_segs[10]);
      n_dwords[11] = oct_add_sg_list (sg11, b[11], n_segs[11]);
      n_dwords[12] = oct_add_sg_list (sg12, b[12], n_segs[12]);
      n_dwords[13] = oct_add_sg_list (sg13, b[13], n_segs[13]);
      n_dwords[14] = oct_add_sg_list (sg14, b[14], n_segs[14]);
      n_dwords[15] = oct_add_sg_list (sg15, b[15], n_segs[15]);

      n_dwords[0] += oct_add_send_hdr (send_hdr0, b[0], aura_handle, sq_handle,
				       n_dwords[0]);
      n_dwords[1] += oct_add_send_hdr (send_hdr1, b[1], aura_handle, sq_handle,
				       n_dwords[1]);
      n_dwords[2] += oct_add_send_hdr (send_hdr2, b[2], aura_handle, sq_handle,
				       n_dwords[2]);
      n_dwords[3] += oct_add_send_hdr (send_hdr3, b[3], aura_handle, sq_handle,
				       n_dwords[3]);
      n_dwords[4] += oct_add_send_hdr (send_hdr4, b[4], aura_handle, sq_handle,
				       n_dwords[4]);
      n_dwords[5] += oct_add_send_hdr (send_hdr5, b[5], aura_handle, sq_handle,
				       n_dwords[5]);
      n_dwords[6] += oct_add_send_hdr (send_hdr6, b[6], aura_handle, sq_handle,
				       n_dwords[6]);
      n_dwords[7] += oct_add_send_hdr (send_hdr7, b[7], aura_handle, sq_handle,
				       n_dwords[7]);

      n_dwords[8] += oct_add_send_hdr (send_hdr8, b[8], aura_handle, sq_handle,
				       n_dwords[8]);
      n_dwords[9] += oct_add_send_hdr (send_hdr9, b[9], aura_handle, sq_handle,
				       n_dwords[9]);
      n_dwords[10] += oct_add_send_hdr (send_hdr10, b[10], aura_handle,
					sq_handle, n_dwords[10]);
      n_dwords[11] += oct_add_send_hdr (send_hdr11, b[11], aura_handle,
					sq_handle, n_dwords[11]);
      n_dwords[12] += oct_add_send_hdr (send_hdr12, b[12], aura_handle,
					sq_handle, n_dwords[12]);
      n_dwords[13] += oct_add_send_hdr (send_hdr13, b[13], aura_handle,
					sq_handle, n_dwords[13]);
      n_dwords[14] += oct_add_send_hdr (send_hdr14, b[14], aura_handle,
					sq_handle, n_dwords[14]);
      n_dwords[15] += oct_add_send_hdr (send_hdr15, b[15], aura_handle,
					sq_handle, n_dwords[15]);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);
      roc_lmt_mov_seg (lmt_line4, desc4, n_dwords[4]);
      roc_lmt_mov_seg (lmt_line5, desc5, n_dwords[5]);
      roc_lmt_mov_seg (lmt_line6, desc6, n_dwords[6]);
      roc_lmt_mov_seg (lmt_line7, desc7, n_dwords[7]);
      roc_lmt_mov_seg (lmt_line8, desc8, n_dwords[8]);
      roc_lmt_mov_seg (lmt_line9, desc9, n_dwords[9]);
      roc_lmt_mov_seg (lmt_line10, desc10, n_dwords[10]);
      roc_lmt_mov_seg (lmt_line11, desc11, n_dwords[11]);
      roc_lmt_mov_seg (lmt_line12, desc12, n_dwords[12]);
      roc_lmt_mov_seg (lmt_line13, desc13, n_dwords[13]);
      roc_lmt_mov_seg (lmt_line14, desc14, n_dwords[14]);
      roc_lmt_mov_seg (lmt_line15, desc15, n_dwords[15]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (16 - 1) << 12;

      /*
       * Set vector of sizes of next 15 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));
      lmt_arg |= (n_dwords[4] - 1) << (19 + (3 * 3));
      lmt_arg |= (n_dwords[5] - 1) << (19 + (3 * 4));
      lmt_arg |= (n_dwords[6] - 1) << (19 + (3 * 5));
      lmt_arg |= (n_dwords[7] - 1) << (19 + (3 * 6));
      lmt_arg |= (n_dwords[8] - 1) << (19 + (3 * 7));
      lmt_arg |= (n_dwords[9] - 1) << (19 + (3 * 8));
      lmt_arg |= (n_dwords[10] - 1) << (19 + (3 * 9));
      lmt_arg |= (n_dwords[11] - 1) << (19 + (3 * 10));
      lmt_arg |= (n_dwords[12] - 1) << (19 + (3 * 11));
      lmt_arg |= (n_dwords[13] - 1) << (19 + (3 * 12));
      lmt_arg |= (n_dwords[14] - 1) << (19 + (3 * 13));
      lmt_arg |= (n_dwords[15] - 1) << (19 + (3 * 14));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_packets -= 16;
      b += 16;
    }

  while (n_packets > 8)
    {
      n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b[0]);
      n_segs[1] = oct_get_tx_vlib_buf_segs (vm, b[1]);
      n_segs[2] = oct_get_tx_vlib_buf_segs (vm, b[2]);
      n_segs[3] = oct_get_tx_vlib_buf_segs (vm, b[3]);
      n_segs[4] = oct_get_tx_vlib_buf_segs (vm, b[4]);
      n_segs[5] = oct_get_tx_vlib_buf_segs (vm, b[5]);
      n_segs[6] = oct_get_tx_vlib_buf_segs (vm, b[6]);
      n_segs[7] = oct_get_tx_vlib_buf_segs (vm, b[7]);

      n_dwords[0] = oct_add_sg_list (sg0, b[0], n_segs[0]);
      n_dwords[1] = oct_add_sg_list (sg1, b[1], n_segs[1]);
      n_dwords[2] = oct_add_sg_list (sg2, b[2], n_segs[2]);
      n_dwords[3] = oct_add_sg_list (sg3, b[3], n_segs[3]);
      n_dwords[4] = oct_add_sg_list (sg4, b[4], n_segs[4]);
      n_dwords[5] = oct_add_sg_list (sg5, b[5], n_segs[5]);
      n_dwords[6] = oct_add_sg_list (sg6, b[6], n_segs[6]);
      n_dwords[7] = oct_add_sg_list (sg7, b[7], n_segs[7]);

      n_dwords[0] += oct_add_send_hdr (send_hdr0, b[0], aura_handle, sq_handle,
				       n_dwords[0]);
      n_dwords[1] += oct_add_send_hdr (send_hdr1, b[1], aura_handle, sq_handle,
				       n_dwords[1]);
      n_dwords[2] += oct_add_send_hdr (send_hdr2, b[2], aura_handle, sq_handle,
				       n_dwords[2]);
      n_dwords[3] += oct_add_send_hdr (send_hdr3, b[3], aura_handle, sq_handle,
				       n_dwords[3]);
      n_dwords[4] += oct_add_send_hdr (send_hdr4, b[4], aura_handle, sq_handle,
				       n_dwords[4]);
      n_dwords[5] += oct_add_send_hdr (send_hdr5, b[5], aura_handle, sq_handle,
				       n_dwords[5]);
      n_dwords[6] += oct_add_send_hdr (send_hdr6, b[6], aura_handle, sq_handle,
				       n_dwords[6]);
      n_dwords[7] += oct_add_send_hdr (send_hdr7, b[7], aura_handle, sq_handle,
				       n_dwords[7]);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);
      roc_lmt_mov_seg (lmt_line4, desc4, n_dwords[4]);
      roc_lmt_mov_seg (lmt_line5, desc5, n_dwords[5]);
      roc_lmt_mov_seg (lmt_line6, desc6, n_dwords[6]);
      roc_lmt_mov_seg (lmt_line7, desc7, n_dwords[7]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (8 - 1) << 12;

      /*
       * Set vector of sizes of next 7 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));
      lmt_arg |= (n_dwords[4] - 1) << (19 + (3 * 3));
      lmt_arg |= (n_dwords[5] - 1) << (19 + (3 * 4));
      lmt_arg |= (n_dwords[6] - 1) << (19 + (3 * 5));
      lmt_arg |= (n_dwords[7] - 1) << (19 + (3 * 6));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_packets -= 8;
      b += 8;
    }

  while (n_packets > 4)
    {
      n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b[0]);
      n_segs[1] = oct_get_tx_vlib_buf_segs (vm, b[1]);
      n_segs[2] = oct_get_tx_vlib_buf_segs (vm, b[2]);
      n_segs[3] = oct_get_tx_vlib_buf_segs (vm, b[3]);

      n_dwords[0] = oct_add_sg_list (sg0, b[0], n_segs[0]);
      n_dwords[1] = oct_add_sg_list (sg1, b[1], n_segs[1]);
      n_dwords[2] = oct_add_sg_list (sg2, b[2], n_segs[2]);
      n_dwords[3] = oct_add_sg_list (sg3, b[3], n_segs[3]);

      n_dwords[0] += oct_add_send_hdr (send_hdr0, b[0], aura_handle, sq_handle,
				       n_dwords[0]);
      n_dwords[1] += oct_add_send_hdr (send_hdr1, b[1], aura_handle, sq_handle,
				       n_dwords[1]);
      n_dwords[2] += oct_add_send_hdr (send_hdr2, b[2], aura_handle, sq_handle,
				       n_dwords[2]);
      n_dwords[3] += oct_add_send_hdr (send_hdr3, b[3], aura_handle, sq_handle,
				       n_dwords[3]);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (4 - 1) << 12;

      /*
       * Set vector of sizes of next 3 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_packets -= 4;
      b += 4;
    }

  while (n_packets)
    {
      lmt_arg = core_lmt_id;

      if (n_packets > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      n_segs[0] = oct_get_tx_vlib_buf_segs (vm, b[0]);

      n_dwords[0] = oct_add_sg_list (sg0, b[0], n_segs[0]);
      n_dwords[0] += oct_add_send_hdr (send_hdr0, b[0], aura_handle, sq_handle,
				       n_dwords[0]);

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_packets -= 1;
      b += 1;
    }

  ctq->cached_pkts -= tx_pkts;

free_pkts:
  if (PREDICT_FALSE (n_drop))
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) b, from, n_drop, 0);
      vlib_buffer_free (vm, from, n_drop);
    }

  return tx_pkts;
}

i32 static_always_inline
oct_pkts_send_ipsec (vlib_main_t *vm, vlib_node_runtime_t *node,
		     oct_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq, u16 tx_pkts,
		     vlib_buffer_t **bufs)
{
  oct_ipsec_main_t *im = &oct_ipsec_main;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_interfaces_t *ifs = txq->port->interfaces;
  u16 num_tx_queues = ifs->num_tx_queues;
  u64 aura_handle = ctq->aura_handle;
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u32 current_sq0, current_sq1, current_sq2, current_sq3;
  u64 sq_handle0, sq_handle1, sq_handle2, sq_handle3;
  u32 sa0_index, sa1_index, sa2_index, sa3_index;
  u32 current_sa0_index = ~0, current_sa1_index = ~0;
  u32 current_sa2_index = ~0, current_sa3_index = ~0;
  oct_ipsec_session_t *sess0 = NULL, *sess1 = NULL;
  oct_ipsec_session_t *sess2 = NULL, *sess3 = NULL;
  struct cpt_inst_s inst0 = { 0 }, inst1 = { 0 }, inst2 = { 0 }, inst3 = { 0 };
  u64 core_lmt_base_addr, lmt_arg, core_lmt_id;
  oct_ipsec_outbound_pkt_meta_t *pkt_meta[4];
  u16 n_cpt_fc_drop = 0, n_nix_fc_drop = 0;
  u16 n_left0, n_left1, n_left2, n_left3;
  u16 n_packets;
  struct roc_cpt_lf *cpt_lf = NULL;
  u32 failed_buff[VLIB_FRAME_SIZE];
  u32 from[VLIB_FRAME_SIZE];
  u16 sq0, sq1, sq2, sq3;
  struct roc_nix_sq *sq;
  u32 quad_bit, count;
  vlib_buffer_t **b;
  u64 *lmt_line[4];
  u64 n_dwords[4];

  b = bufs;

  sq_handle0 = 0;
  sq_handle1 = 0;
  sq_handle2 = 0;
  sq_handle3 = 0;

  current_sq0 = ~0;
  current_sq1 = ~0;
  current_sq2 = ~0;
  current_sq3 = ~0;

  core_lmt_base_addr = (uintptr_t) ctq->lmt_addr;
  ROC_LMT_BASE_ID_GET (core_lmt_base_addr, core_lmt_id);

  lmt_line[0] = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 0);
  lmt_line[1] = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 1);
  lmt_line[2] = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 2);
  lmt_line[3] = OCT_LMT_GET_LINE_ADDR (core_lmt_base_addr, 3);

  /* Check CPT flow control */
  cpt_lf = roc_nix_inl_outb_lf_base_get (cd->nix);
  n_left0 = oct_check_fc_cpt (cpt_lf, (u32 *) &cd->cached_cpt_pkts, tx_pkts);
  n_cpt_fc_drop = tx_pkts - n_left0;

  if (!n_left0)
    goto cpt_fc_drop;

  /* Process packets up to CPT queue depth */
  n_packets = n_left0;

  n_left0 = 0;
  n_left1 = 0;
  n_left2 = 0;
  n_left3 = 0;

  while (n_packets > 3)
    {
      pkt_meta[0] =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[0]);
      pkt_meta[1] =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[1]);
      pkt_meta[2] =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[2]);
      pkt_meta[3] =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[3]);

      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;
      if (sa0_index != current_sa0_index)
	{
	  sess0 = pool_elt_at_index (im->inline_ipsec_sessions, sa0_index);
	  if (!sess0->inst.w7.s.cptr)
	    {
	      sess0->inst.w7.s.cptr = (u64) sess0->out_sa[cd->nix_idx];
	      sess0->sq =
		((sa0_index % vlib_num_workers ()) + 1) % num_tx_queues;
	    }
	  current_sa0_index = sa0_index;
	  ALWAYS_ASSERT (current_sa0_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      sa1_index = vnet_buffer (b[1])->ipsec.sad_index;
      if (sa1_index != current_sa1_index)
	{
	  sess1 = pool_elt_at_index (im->inline_ipsec_sessions, sa1_index);
	  if (!sess1->inst.w7.s.cptr)
	    {
	      sess1->sq =
		((sa1_index % vlib_num_workers ()) + 1) % num_tx_queues;
	      sess1->inst.w7.s.cptr = (u64) sess1->out_sa[cd->nix_idx];
	    }
	  current_sa1_index = sa1_index;
	  ALWAYS_ASSERT (current_sa0_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      sa2_index = vnet_buffer (b[2])->ipsec.sad_index;
      if (sa2_index != current_sa2_index)
	{
	  sess2 = pool_elt_at_index (im->inline_ipsec_sessions, sa2_index);
	  if (!sess2->inst.w7.s.cptr)
	    {
	      sess2->sq =
		((sa2_index % vlib_num_workers ()) + 1) % num_tx_queues;
	      sess2->inst.w7.s.cptr = (u64) sess2->out_sa[cd->nix_idx];
	    }
	  current_sa2_index = sa2_index;
	  ALWAYS_ASSERT (current_sa2_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      sa3_index = vnet_buffer (b[3])->ipsec.sad_index;
      if (sa3_index != current_sa3_index)
	{
	  sess3 = pool_elt_at_index (im->inline_ipsec_sessions, sa3_index);
	  if (!sess3->inst.w7.s.cptr)
	    {
	      sess3->sq =
		((sa3_index % vlib_num_workers ()) + 1) % num_tx_queues;
	      sess3->inst.w7.s.cptr = (u64) sess3->out_sa[cd->nix_idx];
	    }
	  current_sa3_index = sa3_index;
	  ALWAYS_ASSERT (current_sa3_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      oct_ipsec_outb_data (b[0])->res.cn10k.compcode = CPT_COMP_NOT_DONE;
      oct_ipsec_outb_data (b[1])->res.cn10k.compcode = CPT_COMP_NOT_DONE;
      oct_ipsec_outb_data (b[2])->res.cn10k.compcode = CPT_COMP_NOT_DONE;
      oct_ipsec_outb_data (b[3])->res.cn10k.compcode = CPT_COMP_NOT_DONE;

      inst0.res_addr = (u64) &oct_ipsec_outb_data (b[0])->res;
      inst1.res_addr = (u64) &oct_ipsec_outb_data (b[1])->res;
      inst2.res_addr = (u64) &oct_ipsec_outb_data (b[2])->res;
      inst3.res_addr = (u64) &oct_ipsec_outb_data (b[3])->res;

      inst0.w2.u64 = sess0->inst.w2.u64;
      inst1.w2.u64 = sess1->inst.w2.u64;
      inst2.w2.u64 = sess2->inst.w2.u64;
      inst3.w2.u64 = sess3->inst.w2.u64;

      inst0.w3.u64 = (uintptr_t) (b[0]);
      inst1.w3.u64 = (uintptr_t) (b[1]);
      inst2.w3.u64 = (uintptr_t) (b[2]);
      inst3.w3.u64 = (uintptr_t) (b[3]);

      inst0.w3.u64 |= 0x1ULL;
      inst1.w3.u64 |= 0x1ULL;
      inst2.w3.u64 |= 0x1ULL;
      inst3.w3.u64 |= 0x1ULL;

      inst0.w7.u64 = sess0->inst.w7.u64;
      inst1.w7.u64 = sess1->inst.w7.u64;
      inst2.w7.u64 = sess2->inst.w7.u64;
      inst3.w7.u64 = sess3->inst.w7.u64;

      sq0 = sess0->sq;
      sq1 = sess1->sq;
      sq2 = sess2->sq;
      sq3 = sess3->sq;

      quad_bit = 0;
      count = 0;

      if (current_sq0 != sq0)
	{
	  ctq = cd->ctqs[sq0];
	  sq = &ctq->sq;
	  sq_handle0 = sq->qid;
	  n_left0 = oct_check_fc_nix (sq, &ctq->cached_pkts, n_packets >> 2);
	  current_sq0 = sq0;
	}
      if (current_sq1 != sq1)
	{
	  ctq = cd->ctqs[sq1];
	  sq = &ctq->sq;
	  sq_handle1 = sq->qid;
	  n_left1 = oct_check_fc_nix (sq, &ctq->cached_pkts, n_packets >> 2);
	  current_sq1 = sq1;
	}
      if (current_sq2 != sq2)
	{
	  ctq = cd->ctqs[sq2];
	  sq = &ctq->sq;
	  sq_handle2 = sq->qid;
	  n_left2 = oct_check_fc_nix (sq, &ctq->cached_pkts, n_packets >> 2);
	  current_sq2 = sq2;
	}
      if (current_sq3 != sq3)
	{
	  ctq = cd->ctqs[sq3];
	  sq = &ctq->sq;
	  sq_handle3 = sq->qid;
	  n_left3 = oct_check_fc_nix (sq, &ctq->cached_pkts, n_packets >> 2);
	  current_sq3 = sq3;
	}
      quad_bit |= !(!n_left0) << 0;
      quad_bit |= !(!n_left1) << 1;
      quad_bit |= !(!n_left2) << 2;
      quad_bit |= !(!n_left3) << 3;

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | (uint64_t) core_lmt_id;
      if (quad_bit == 0x0F)
	{
	  oct_prepare_ipsec_inst (vm, b[0], sq_handle0, aura_handle,
				  &pkt_meta[0], &inst0, &n_dwords[0], sess0);
	  oct_prepare_ipsec_inst (vm, b[1], sq_handle1, aura_handle,
				  &pkt_meta[1], &inst1, &n_dwords[1], sess1);
	  oct_prepare_ipsec_inst (vm, b[2], sq_handle2, aura_handle,
				  &pkt_meta[2], &inst2, &n_dwords[2], sess2);
	  oct_prepare_ipsec_inst (vm, b[3], sq_handle3, aura_handle,
				  &pkt_meta[3], &inst3, &n_dwords[3], sess3);

	  oct_submit_quad_packets (lmt_arg, cd, &inst0, &inst1, &inst2, &inst3,
				   n_dwords, lmt_line);

	  n_left0 -= 1;
	  n_left1 -= 1;
	  n_left2 -= 1;
	  n_left3 -= 1;
	  count += 4;
	}
      else if (quad_bit != 0x0)
	{
	  if (n_left0)
	    {
	      oct_prepare_ipsec_inst (vm, b[0], sq_handle0, aura_handle,
				      &pkt_meta[0], &inst0, &n_dwords[0],
				      sess0),
		roc_lmt_mov_seg ((void *) lmt_line[count], &inst0, 4);
	      count++;
	      n_left0 -= 1;
	    }
	  else
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[0]);
	      n_nix_fc_drop++;
	    }
	  if (n_left1)
	    {
	      oct_prepare_ipsec_inst (vm, b[1], sq_handle1, aura_handle,
				      &pkt_meta[1], &inst1, &n_dwords[1],
				      sess1);
	      roc_lmt_mov_seg ((void *) lmt_line[count], &inst1, 4);
	      if (count)
		lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * (count - 1)));
	      count++;
	      n_left1 -= 1;
	    }
	  else
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[1]);
	      n_nix_fc_drop++;
	    }
	  if (n_left2)
	    {
	      oct_prepare_ipsec_inst (vm, b[2], sq_handle2, aura_handle,
				      &pkt_meta[2], &inst2, &n_dwords[2],
				      sess2);
	      roc_lmt_mov_seg ((void *) lmt_line[count], &inst2, 4);
	      if (count)
		lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * (count - 1)));
	      count++;
	      n_left2 -= 1;
	    }
	  else
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[2]);
	      n_nix_fc_drop++;
	    }
	  if (n_left3)
	    {
	      oct_prepare_ipsec_inst (vm, b[3], sq_handle3, aura_handle,
				      &pkt_meta[3], &inst3, &n_dwords[3],
				      sess3);
	      roc_lmt_mov_seg ((void *) lmt_line[count], &inst3, 4);
	      if (count)
		lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * (count - 1)));
	      count++;
	      n_left3 -= 1;
	    }
	  else
	    {
	      failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[3]);
	      n_nix_fc_drop++;
	    }
	  if (count == 1)
	    lmt_arg = ROC_CN10K_CPT_LMT_ARG | core_lmt_id;
	  else
	    lmt_arg |= (count - 1) << 12;
	  roc_lmt_submit_steorl (lmt_arg, cd->cpt_io_addr);
	  asm volatile ("dmb oshst" ::: "memory");
	}
      else if (quad_bit == 0x0)
	{
	  failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[0]);
	  failed_buff[n_nix_fc_drop + 1] = vlib_get_buffer_index (vm, b[1]);
	  failed_buff[n_nix_fc_drop + 2] = vlib_get_buffer_index (vm, b[2]);
	  failed_buff[n_nix_fc_drop + 3] = vlib_get_buffer_index (vm, b[3]);
	  n_nix_fc_drop += 4;
	}

      b += 4;
      n_packets -= 4;
    }

  current_sq0 = ~0;
  sq_handle0 = 0;
  n_left0 = 0;

  while (n_packets)
    {
      pkt_meta[0] =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[0]);
      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;
      if (sa0_index != current_sa0_index)
	{
	  sess0 = pool_elt_at_index (im->inline_ipsec_sessions, sa0_index);
	  if (!sess0->inst.w7.s.cptr)
	    {
	      sess0->sq =
		((sa0_index % vlib_num_workers ()) + 1) % num_tx_queues;
	      sess0->inst.w7.s.cptr = (u64) sess0->out_sa[cd->nix_idx];
	    }
	  current_sa0_index = sa0_index;
	  ALWAYS_ASSERT (current_sa0_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      oct_ipsec_outb_data (b[0])->res.cn10k.compcode = CPT_COMP_NOT_DONE;
      inst0.res_addr = (u64) &oct_ipsec_outb_data (b[0])->res;
      inst0.w2.u64 = sess0->inst.w2.u64;
      inst0.w3.u64 = (uintptr_t) (b[0]);
      inst0.w3.u64 |= 0x1ULL;
      inst0.w7.u64 = sess0->inst.w7.u64;

      sq0 = sess0->sq;

      if (current_sq0 != sq0)
	{
	  ctq = cd->ctqs[sq0];
	  sq = &ctq->sq;
	  sq_handle0 = sq->qid;
	  n_left0 = oct_check_fc_nix (sq, &ctq->cached_pkts, n_packets);
	  current_sq0 = sq0;
	}
      if (!n_left0)
	{
	  failed_buff[n_nix_fc_drop] = vlib_get_buffer_index (vm, b[0]);
	  n_nix_fc_drop++;
	  goto next;
	}

      oct_prepare_ipsec_inst (vm, b[0], sq_handle0, aura_handle, &pkt_meta[0],
			      &inst0, &n_dwords[0], sess0);

      roc_lmt_mov_seg ((void *) lmt_line[0], &inst0, 4);

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | core_lmt_id;

      roc_lmt_submit_steorl (lmt_arg, cd->cpt_io_addr);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      asm volatile ("dmb oshst" ::: "memory");

      n_left0 -= 1;
    next:
      n_packets -= 1;
      b += 1;
    }

  /*
   * Free packets which failed in nix_fc_check.
   * These packet indices are stored in failed_buff,
   * as they may not be contiguous when received.
   */
  if (PREDICT_FALSE (n_nix_fc_drop))
    vlib_buffer_free (vm, failed_buff, n_nix_fc_drop);

cpt_fc_drop:
  if (PREDICT_FALSE (n_cpt_fc_drop))
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) b, from,
					   n_cpt_fc_drop, 0);
      vlib_buffer_free (vm, from, n_cpt_fc_drop);
    }

  return tx_pkts - n_cpt_fc_drop - n_nix_fc_drop;
}

VNET_DEV_NODE_FN (oct_tx_ipsec_tm_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u32 node_index = node->node_index;
  u32 n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 8], **b = buffers;
  vlib_buffer_t *ipsec_buff[VLIB_FRAME_SIZE + 8];
  vlib_buffer_t *buff[VLIB_FRAME_SIZE + 8];
  int ipsec_cnt = 0, pkt_cnt = 0;
#ifdef PLATFORM_OCTEON9
  u64 lmt_id = 0;
#else
  u64 lmt_id = vm->thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
#endif

  oct_tx_ctx_t ctx = {
    .node = node,
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (cd->ctqs[0]->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .max_pkt_len = roc_nix_max_pkt_len (cd->nix),
    .lmt_id = lmt_id,
    .lmt_ioaddr = ctq->io_addr,
    .lmt_lines = ctq->lmt_addr + (lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };

  oct_batch_free (vm, &ctx, txq, OCT_TX_IPSEC_TM_NODE);

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  n_left = n_pkts;
  while (n_pkts)
    {
      if (vnet_buffer (b[0])->oflags & VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD)
	ipsec_buff[ipsec_cnt++] = b[0];
      else
	buff[pkt_cnt++] = b[0];

      b++;
      n_pkts--;
    }

  if (ipsec_cnt)
    ipsec_cnt =
      oct_pkts_send_ipsec (vm, node, &ctx, txq, ipsec_cnt, ipsec_buff);

  if (pkt_cnt)
    pkt_cnt = oct_pkts_send (vm, node, &ctx, txq, pkt_cnt, buff);

  if (PREDICT_FALSE (n_left != (ipsec_cnt + pkt_cnt)))
    {
      vlib_error_count (vm, node_index, OCT_TX_NODE_CTR_NO_FREE_SLOTS,
			(n_left - ipsec_cnt - pkt_cnt));
    }

  return (ipsec_cnt + pkt_cnt);
}

VNET_DEV_NODE_FN (oct_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  u32 node_index = node->node_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n, n_enq, n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 8], **b = buffers;
#ifdef PLATFORM_OCTEON9
  u64 lmt_id = 0;
#else
  u64 lmt_id = vm->thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
#endif

  oct_tx_ctx_t ctx = {
    .node = node,
    .hdr_w0_teplate = {
      .aura = roc_npa_aura_handle_to_aura (ctq->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .max_pkt_len = roc_nix_max_pkt_len (cd->nix),
    .lmt_id = lmt_id,
    .lmt_ioaddr = ctq->io_addr,
    .lmt_lines = ctq->lmt_addr + (lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  for (int i = 0; i < 8; i++)
    b[n_pkts + i] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  n_enq = ctq->n_enq;
  n_enq -= oct_batch_free (vm, &ctx, txq, OCT_TX_NODE);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
	   n_left -= 16, b += 16)
	n += oct_tx_enq16 (vm, &ctx, txq, b, 16, /* trace */ 1);

      if (n_left)
	n += oct_tx_enq16 (vm, &ctx, txq, b, n_left, /* trace */ 1);
    }
  else
    {
      for (n_left = clib_min (n_pkts, txq->size - n_enq), n = 0; n_left >= 16;
	   n_left -= 16, b += 16)
	n += oct_tx_enq16 (vm, &ctx, txq, b, 16, /* trace */ 0);

      if (n_left)
	n += oct_tx_enq16 (vm, &ctx, txq, b, n_left, /* trace */ 0);
    }

  ctq->n_enq = n_enq + n - ctx.n_drop - ctx.n_exd_mtu;

  if (n < n_pkts)
    {
      u32 n_free = n_pkts - n;
      vlib_buffer_free (vm, from + n, n_free);
      vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_NO_FREE_SLOTS,
			n_free);
      n_pkts -= n_free;
    }

  if (ctx.n_drop)
    vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_CHAIN_TOO_LONG,
		      ctx.n_drop);

  if (PREDICT_FALSE (ctx.n_exd_mtu))
    vlib_error_count (vm, node->node_index, OCT_TX_NODE_CTR_MTU_EXCEEDED,
		      ctx.n_exd_mtu);

  if (ctx.batch_alloc_not_ready)
    vlib_error_count (vm, node_index,
		      OCT_TX_NODE_CTR_AURA_BATCH_ALLOC_NOT_READY,
		      ctx.batch_alloc_not_ready);

  if (ctx.batch_alloc_issue_fail)
    vlib_error_count (vm, node_index,
		      OCT_TX_NODE_CTR_AURA_BATCH_ALLOC_ISSUE_FAIL,
		      ctx.batch_alloc_issue_fail);

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (ctx.n_drop)
    {
      u32 bi[VLIB_FRAME_SIZE];
      vlib_get_buffer_indices (vm, ctx.drop, bi, ctx.n_drop);
      vlib_buffer_free (vm, bi, ctx.n_drop);
      n_pkts -= ctx.n_drop;
    }

  if (PREDICT_FALSE (ctx.n_exd_mtu))
    {
      u32 bi[VLIB_FRAME_SIZE];
      vlib_get_buffer_indices (vm, ctx.exd_mtu, bi, ctx.n_exd_mtu);
      vlib_buffer_free (vm, bi, ctx.n_exd_mtu);
      n_pkts -= ctx.n_exd_mtu;
    }

  return n_pkts;
}
