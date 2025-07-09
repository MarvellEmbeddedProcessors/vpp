/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/hw_defs.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 trace_count;
  u32 n_traced;
  oct_nix_rx_cqe_desc_t *next_desc;
  u64 parse_w0_or;
  u32 n_left_to_next;
  u32 *to_next;
  u16 *next;
  u32 n_rx_pkts;
  u32 n_rx_bytes;
  u32 n_segs;
  u16 buffer_start_index;
} oct_rx_node_ctx_t;

static_always_inline u64
oct_get_wqe_from_cpt_hdr (union cpt_parse_hdr_u *cpt_hdr, const u64 fp_flags)
{
  if (fp_flags & OCT_FP_FLAG_O20)
    return cpt_hdr->u64[1];
  return clib_net_to_host_u64 (cpt_hdr->u64[1]);
}

static_always_inline void *
oct_ipsec_inb_sa_priv (u32 idx, const u64 fp_flags)
{
  oct_inl_dev_main_t *oidm = &oct_inl_dev_main;
  struct roc_ot_ipsec_inb_sa *roc_sa;

  if (fp_flags & OCT_FP_FLAG_O20)
    {
      struct roc_ow_ipsec_inb_sa *roc_sa;
      roc_sa = roc_nix_inl_ow_ipsec_inb_sa (oidm->inb_sa_base, idx);
      return roc_nix_inl_ow_ipsec_inb_sa_sw_rsvd (roc_sa);
    }

  roc_sa = roc_nix_inl_ot_ipsec_inb_sa (oidm->inb_sa_base, idx);
  return roc_nix_inl_ot_ipsec_inb_sa_sw_rsvd (roc_sa);
}

static_always_inline vlib_buffer_t *
oct_seg_to_bp (void *p)
{
  return (vlib_buffer_t *) p - 1;
}

static_always_inline void
oct_rx_verify_vlib (vlib_main_t *vm, vlib_buffer_t *b)
{
  /*
   * Warning: Since this assertion is performed in a critical section,
   * with increasing number of worker cores, scaling of packet receive-rates
   * will be impacted in debug builds
   */
  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
	  vlib_buffer_is_known (vm, vlib_get_buffer_index (vm, b)));
}

static_always_inline u32
oct_rx_n_segs (vlib_main_t *vm, const oct_nix_rx_parse_t *rxp)
{
  struct nix_rx_sg_s *sg;

  sg = (struct nix_rx_sg_s *) (((char *) rxp) + sizeof (rxp->f));
  return sg->segs;
}

static_always_inline void
oct_rx_attach_tail (vlib_main_t *vm, oct_rx_node_ctx_t *ctx,
		    vlib_buffer_template_t *bt, vlib_buffer_t *h,
		    oct_nix_rx_cqe_desc_t *d)
{
  u32 tail_sz = 0, n_tail_segs = 0;
  vlib_buffer_t *p, *b;
  u8 segs0 = d->sg0.segs, segs1 = 0;

  if (segs0 < 2)
    return;

  b = oct_seg_to_bp (d->segs0[1]);
  b->template = *bt;
  h->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg0.seg2_size;
  n_tail_segs++;

  if (segs0 == 2)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs0[2]);
  b->template = *bt;
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg0.seg3_size;
  n_tail_segs++;

  if (d->sg1.subdc != NIX_SUBDC_SG)
    goto done;

  segs1 = d->sg1.segs;
  if (segs1 == 0)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[0]);
  b->template = *bt;
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg1_size;
  n_tail_segs++;

  if (segs1 == 1)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[1]);
  b->template = *bt;
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg2_size;
  n_tail_segs++;

  if (segs1 == 2)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[2]);
  b->template = *bt;
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg3_size;
  n_tail_segs++;

done:
  b->flags = 0;
  h->total_length_not_including_first_buffer = tail_sz;
  h->flags |= VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;
  ctx->n_rx_bytes += tail_sz;
  ctx->n_segs += n_tail_segs;
}

/*
 * Read upto 4 fragments in case of successful reassembly.
 * Fragments which are further segmented are not
 * supported currently.
 */
static_always_inline u8
oct_rx_ipsec_reassembly_success (vlib_main_t *vm, vlib_buffer_template_t *bt,
				 struct cpt_cn10k_parse_hdr_s *hdr,
				 oct_nix_rx_cqe_desc_t *d, vlib_buffer_t *buf,
				 u32 *olen, u32 *esp_len, u32 l2_ol3_hdr_size)
{
  oct_nix_rx_parse_t *rxp_ptr2, *rxp_ptr3;
  oct_nix_rx_parse_t *rxp_ptr, *rxp_ptr1;
  u16 frag_size1, frag_size2, frag_size3;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  struct cpt_frag_info_s *frag_info;
  oct_nix_rx_parse_t *rxp_meta = &d->parse;
  u32 offset, l2_l3_inner_hdr_size;
  u64 *wqe_ptr2, *wqe_ptr3;
  u64 *wqe_ptr, *wqe_ptr1;
  uint64_t *frag_ptr;
  u8 frag_cnt;

  wqe_ptr = (u64 *) clib_net_to_host_u64 (hdr->wqe_ptr);
  rxp_ptr = (oct_nix_rx_parse_t *) (wqe_ptr + 1);
  ASSERT (oct_rx_n_segs (vm, rxp_ptr) == 1);

  l2_l3_inner_hdr_size = rxp_meta->f.ldptr - rxp_meta->f.laptr;
  frag_cnt = hdr->w0.num_frags;

  buf->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  buf->total_length_not_including_first_buffer = 0;
  b0 = buf;

  /*
   * fi_offset is 8B offset from cpt_parse_hdr_s + fi_pad to frag_info_s.
   * fi_offset 0 indicates 256B.
   */
  offset = hdr->w2.fi_offset;
  offset = (((offset - 1) & 0x1f) + 1) * 8;
  frag_info = PLT_PTR_ADD (hdr, offset);

  if (frag_cnt == 2)
    {
      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);

      oct_rx_verify_vlib (vm, b1);
      b1->template = *bt;

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b1->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b0->next_buffer = vlib_get_buffer_index (vm, b1);

      return 2;
    }

  if (PREDICT_FALSE (frag_cnt == 3))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      frag_size2 = clib_net_to_host_u16 (frag_info->w1.frag_size2);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);

      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      b2 = (vlib_buffer_t *) ((u8 *) wqe_ptr2 - 128);

      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (oct_nix_rx_parse_t *) (wqe_ptr2 + 1);

      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr2) == 1);

      b1->template = *bt;
      b2->template = *bt;

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *olen += rxp_ptr2->f.pkt_lenm1 + 1;

      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b2->current_length = frag_size2;
      b1->current_data = l2_l3_inner_hdr_size;
      b2->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->total_length_not_including_first_buffer += b2->current_length;

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b1->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b0->next_buffer = vlib_get_buffer_index (vm, b1);
      b1->next_buffer = vlib_get_buffer_index (vm, b2);

      return 3;
    }

  if (PREDICT_FALSE (frag_cnt == 4))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      frag_size2 = clib_net_to_host_u16 (frag_info->w1.frag_size2);
      frag_size3 = clib_net_to_host_u16 (frag_info->w1.frag_size3);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);
      wqe_ptr3 = (u64 *) clib_net_to_host_u64 (*(frag_ptr + 1));

      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      b2 = (vlib_buffer_t *) ((u8 *) wqe_ptr2 - 128);
      b3 = (vlib_buffer_t *) ((u8 *) wqe_ptr3 - 128);

      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (oct_nix_rx_parse_t *) (wqe_ptr2 + 1);
      rxp_ptr3 = (oct_nix_rx_parse_t *) (wqe_ptr3 + 1);

      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr2) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr3) == 1);

      b1->template = *bt;
      b2->template = *bt;
      b3->template = *bt;

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *olen += rxp_ptr2->f.pkt_lenm1 + 1;
      *olen += rxp_ptr3->f.pkt_lenm1 + 1;

      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr3->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b2->current_length = frag_size2;
      b3->current_length = frag_size3;
      b1->current_data = l2_l3_inner_hdr_size;
      b2->current_data = l2_l3_inner_hdr_size;
      b3->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->total_length_not_including_first_buffer += b2->current_length;
      b0->total_length_not_including_first_buffer += b3->current_length;

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b1->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b2->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b0->next_buffer = vlib_get_buffer_index (vm, b1);
      b1->next_buffer = vlib_get_buffer_index (vm, b2);
      b2->next_buffer = vlib_get_buffer_index (vm, b3);

      return 4;
    }

  return frag_cnt;
}

/*
 * Reassemble failure cases. Read upto 4 fragments.
 * Append them to the buffer list.
 * Fragments which are further segmented are not
 * supported currently.
 * */
static_always_inline u8
oct_rx_ipsec_reassembly_failure (vlib_main_t *vm, vlib_buffer_template_t *bt,
				 struct cpt_cn10k_parse_hdr_s *hdr,
				 oct_nix_rx_cqe_desc_t *d,
				 vlib_buffer_t **buffs, u16 *next,
				 u16 *buffer_next_index, u32 *olen,
				 u32 *esp_len, u32 l2_ol3_hdr_size,
				 const u64 fp_flags)
{
  oct_nix_rx_parse_t *rxp_ptr2, *rxp_ptr3;
  oct_nix_rx_parse_t *rxp_ptr, *rxp_ptr1;
  struct cpt_frag_info_s *frag_info;
  vlib_buffer_t *b1, *b2, *b3;
  u32 l2_sz1, l2_sz2, l2_sz3;
  u64 *wqe_ptr2, *wqe_ptr3;
  u64 *wqe_ptr, *wqe_ptr1;
  u16 rlen1, rlen2, rlen3;
  uint64_t *frag_ptr;
  uint32_t offset;
  u16 next_index = next[*buffer_next_index - 1];
  u8 frag_cnt;

  wqe_ptr = (u64 *) clib_net_to_host_u64 (hdr->wqe_ptr);
  rxp_ptr = (oct_nix_rx_parse_t *) (wqe_ptr + 1);
  ASSERT (oct_rx_n_segs (vm, rxp_ptr) == 1);

  frag_cnt = hdr->w0.num_frags;

  /*
   * fi_offset is 8B offset from cpt_parse_hdr_s + fi_pad to frag_info_s.
   * fi_offset 0 indicates 256B.
   */
  offset = hdr->w2.fi_offset;
  offset = (((offset - 1) & 0x1f) + 1) * 8;
  frag_info = PLT_PTR_ADD (hdr, offset);

  if (frag_cnt == 2)
    {
      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);
      rlen1 = ((*(wqe_ptr1 + 10)) >> 16) & 0xFFFF;

      oct_rx_verify_vlib (vm, b1);
      b1->template = *bt;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

      l2_sz1 = rxp_ptr1->f.lcptr - rxp_ptr1->f.laptr;
      b1->current_length = rlen1 + l2_sz1;
      b1->current_data = 0;
      if (fp_flags & OCT_FP_FLAG_TRACE_EN)
	clib_memcpy_fast (b1->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      buffs[*buffer_next_index] = b1;
      next[*buffer_next_index] = next_index;
      *buffer_next_index = *buffer_next_index + 1;

      return 2;
    }

  if (PREDICT_FALSE (frag_cnt == 3))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);

      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      b2 = (vlib_buffer_t *) ((u8 *) wqe_ptr2 - 128);

      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (oct_nix_rx_parse_t *) (wqe_ptr2 + 1);

      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr2) == 1);

      rlen1 = ((*(wqe_ptr1 + 10)) >> 16) & 0xFFFF;
      rlen2 = ((*(wqe_ptr2 + 10)) >> 16) & 0xFFFF;

      oct_rx_verify_vlib (vm, b1);
      oct_rx_verify_vlib (vm, b2);

      b1->template = *bt;
      b2->template = *bt;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);

      l2_sz1 = rxp_ptr1->f.lcptr - rxp_ptr1->f.laptr;
      l2_sz2 = rxp_ptr2->f.lcptr - rxp_ptr2->f.laptr;

      b1->current_length = rlen1 + l2_sz1;
      b2->current_length = rlen2 + l2_sz2;
      b1->current_data = 0;
      b2->current_data = 0;

      if (fp_flags & OCT_FP_FLAG_TRACE_EN)
	{
	  clib_memcpy_fast (b1->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));
	  clib_memcpy_fast (b2->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));
	}

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *olen += rxp_ptr2->f.pkt_lenm1 + 1;
      *esp_len += rxp_ptr2->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      buffs[*buffer_next_index] = b1;
      buffs[*buffer_next_index + 1] = b2;
      next[*buffer_next_index] = next_index;
      next[*buffer_next_index + 1] = next_index;
      *buffer_next_index = *buffer_next_index + 2;

      return 3;
    }

  if (PREDICT_FALSE (frag_cnt == 4))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);
      wqe_ptr3 = (u64 *) clib_net_to_host_u64 (*(frag_ptr + 1));
      b1 = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
      b2 = (vlib_buffer_t *) ((u8 *) wqe_ptr2 - 128);
      b3 = (vlib_buffer_t *) ((u8 *) wqe_ptr3 - 128);
      rxp_ptr1 = (oct_nix_rx_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (oct_nix_rx_parse_t *) (wqe_ptr2 + 1);
      rxp_ptr3 = (oct_nix_rx_parse_t *) (wqe_ptr3 + 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr2) == 1);
      ASSERT (oct_rx_n_segs (vm, rxp_ptr3) == 1);
      rlen1 = ((*(wqe_ptr1 + 10)) >> 16) & 0xFFFF;
      rlen2 = ((*(wqe_ptr2 + 10)) >> 16) & 0xFFFF;
      rlen3 = ((*(wqe_ptr3 + 10)) >> 16) & 0xFFFF;

      oct_rx_verify_vlib (vm, b1);
      oct_rx_verify_vlib (vm, b2);
      oct_rx_verify_vlib (vm, b3);

      b1->template = *bt;
      b2->template = *bt;
      b3->template = *bt;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

      l2_sz1 = rxp_ptr1->f.lcptr - rxp_ptr1->f.laptr;
      l2_sz2 = rxp_ptr2->f.lcptr - rxp_ptr2->f.laptr;
      l2_sz3 = rxp_ptr3->f.lcptr - rxp_ptr3->f.laptr;

      b1->current_length = rlen1 + l2_sz1;
      b2->current_length = rlen2 + l2_sz2;
      b3->current_length = rlen3 + l2_sz3;
      b1->current_data = 0;
      b2->current_data = 0;
      b3->current_data = 0;

      if (fp_flags & OCT_FP_FLAG_TRACE_EN)
	{
	  clib_memcpy_fast (b1->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));
	  clib_memcpy_fast (b2->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));
	  clib_memcpy_fast (b3->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));
	}

      *olen += rxp_ptr1->f.pkt_lenm1 + 1;
      *olen += rxp_ptr2->f.pkt_lenm1 + 1;
      *olen += rxp_ptr3->f.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr3->f.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      buffs[*buffer_next_index] = b1;
      buffs[*buffer_next_index + 1] = b2;
      buffs[*buffer_next_index + 2] = b3;
      next[*buffer_next_index] = next_index;
      next[*buffer_next_index + 1] = next_index;
      next[*buffer_next_index + 2] = next_index;
      *buffer_next_index = *buffer_next_index + 3;

      return 4;
    }

  return frag_cnt;
}

static_always_inline u32
oct_ipsec_update_itf_sw_idx (oct_ipsec_session_t *session, u32 sa_idx)
{
  clib_bihash_kv_24_16_t bkey60 = { 0 };
  clib_bihash_kv_8_16_t bkey40 = { 0 };
  ipsec_tun_lkup_result_t res;
  ipsec4_tunnel_kv_t *key40;
  ipsec6_tunnel_kv_t *key60;
  ip_address_t *ip_addr;
  ipsec_main_t *ipm;
  ipsec_sa_t *sa;
  i32 rv;

  sa = ipsec_sa_get (sa_idx);
  ASSERT (sa);

  ipm = &ipsec_main;
  ip_addr = &sa->tunnel.t_src;

  if (AF_IP4 == ip_addr->version)
    {
      key40 = (ipsec4_tunnel_kv_t *) &bkey40;
      ipsec4_tunnel_mk_key (key40, &ip_addr->ip.ip4,
			    clib_host_to_net_u32 (sa->spi));
      rv = clib_bihash_search_inline_8_16 (&ipm->tun4_protect_by_key, &bkey40);
      if (PREDICT_FALSE (rv))
	return ~0;

      clib_memcpy_fast (&res, &bkey40.value, sizeof (res));
    }
  else
    {

      key60 = (ipsec6_tunnel_kv_t *) &bkey60;
      key60->key.remote_ip = ip_addr->ip.ip6;
      key60->key.spi = clib_host_to_net_u32 (sa->spi);
      key60->key.__pad = 0;

      rv =
	clib_bihash_search_inline_24_16 (&ipm->tun6_protect_by_key, &bkey60);
      if (PREDICT_FALSE (rv))
	return ~0;

      clib_memcpy_fast (&res, &bkey60.value, sizeof (res));
    }

  /* Store the ITF sw_if_index in the SA session to avoid duplicate
     lookups for each packet */
  session->itf_sw_idx = res.sw_if_index;

  return res.sw_if_index;
}

static_always_inline void
oct_rx_ipsec_update_counters (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_buffer_t **buffs, u16 *next,
			      u16 *buffer_next_index, u32 ilen, u8 frag_cnt,
			      u32 idx, const u8 reass_fail, const u64 fp_flags)
{
  vlib_combined_counter_main_t *rx_counter;
  ipsec_main_t *im = &ipsec_main;
  oct_ipsec_session_t *session;
  oct_ipsec_inb_sa_priv_data_t *inb_sa_priv;
  vlib_buffer_t *b = buffs[*buffer_next_index - 1];
  u32 sa_idx, itf_sw_idx;
  vnet_interface_main_t *vim;
  oct_ipsec_main_t *oim = &oct_ipsec_main;
  vnet_main_t *vnm;
  int i;

  vnm = im->vnet_main;
  vim = &vnm->interface_main;
  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;

  inb_sa_priv = oct_ipsec_inb_sa_priv (idx, fp_flags);

  sa_idx = (u32) inb_sa_priv->user_data;

  vnet_buffer (b)->ipsec.sad_index = sa_idx;
  ASSERT (sa_idx < vec_len (oim->inline_ipsec_sessions));

  session = pool_elt_at_index (oim->inline_ipsec_sessions, sa_idx);
  itf_sw_idx = session->itf_sw_idx;
  /*
   * Check if itf_sw_idx is populated already. First packet on the SA
   * populates the itf_sw_idx in the SA session.
   */
  if (PREDICT_FALSE (itf_sw_idx == ~0))
    itf_sw_idx = oct_ipsec_update_itf_sw_idx (session, sa_idx);

  /* Update IPsec counters with inner IP length */
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx, frag_cnt, ilen);

  if (PREDICT_FALSE (itf_sw_idx == ~0))
    {
      b->error = node->errors[OCT_RX_NODE_CTR_ERR_NO_TUNNEL];
      next[*buffer_next_index - 1] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;

      if (reass_fail)
	{
	  for (i = frag_cnt; i > 1; i--)
	    {
	      buffs[*buffer_next_index - frag_cnt]->error =
		node->errors[OCT_RX_NODE_CTR_ERR_NO_TUNNEL];
	      next[*buffer_next_index - frag_cnt] =
		VNET_DEV_ETH_RX_PORT_NEXT_DROP;
	    }
	}
    }
  else
    /* Update ITF counters with inner IP length */
    vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx,
				     frag_cnt, ilen);
}

static_always_inline u8
oct_rx_ipsec_reassembly (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_buffer_template_t *bt,
			 union cpt_parse_hdr_u *cpt_hdr_u,
			 oct_nix_rx_cqe_desc_t *d, vlib_buffer_t *b,
			 vlib_buffer_t **buf, u16 *next,
			 u16 *buffer_next_index, u32 *olen, u32 *esp_len,
			 u32 l2_ol3_hdr_size, const u64 fp_flags)
{
  u8 frag_cnt = 1;
  u32 idx;

  if (fp_flags & OCT_FP_FLAG_O20)
    {
      idx = cpt_hdr_u->s.w0.cookie;
    }
  else
    {
      struct cpt_cn10k_parse_hdr_s *cpt_hdr =
	(struct cpt_cn10k_parse_hdr_s *) cpt_hdr_u;

      idx = cpt_hdr->w0.cookie;
      if ((cpt_hdr->w0.num_frags) && !(cpt_hdr->w0.reas_sts))
	frag_cnt = oct_rx_ipsec_reassembly_success (
	  vm, bt, cpt_hdr, d, b, olen, esp_len, l2_ol3_hdr_size);
      else if (cpt_hdr->w0.reas_sts)
	{
	  frag_cnt = oct_rx_ipsec_reassembly_failure (
	    vm, bt, cpt_hdr, d, buf, next, buffer_next_index, olen, esp_len,
	    l2_ol3_hdr_size, fp_flags);
	  oct_rx_ipsec_update_counters (vm, node, buf, next, buffer_next_index,
					*esp_len, frag_cnt, idx, 1, fp_flags);
	  return frag_cnt;
	}
    }
  oct_rx_ipsec_update_counters (vm, node, buf, next, buffer_next_index,
				*esp_len, frag_cnt, idx, 0, fp_flags);
  return frag_cnt;
}

static_always_inline u8
oct_is_packet_from_cpt (union nix_rx_parse_u *rxp)
{
#ifdef PLATFORM_OCTEON9
  return 0;
#else
  return rxp->chan >> 11;
#endif
}

static_always_inline uword
oct_ipsec_is_inl_op_success (union cpt_parse_hdr_u *cpt_hdr,
			     const u64 fp_flags)
{
  if (fp_flags & OCT_FP_FLAG_O20)
    {
      u8 hw_ccode = cpt_hdr->s.w3.hw_ccode;
      u8 uc_ccode = cpt_hdr->s.w3.uc_ccode;

      return (((1U << hw_ccode) & CPT_COMP_HWGOOD_MASK) &&
	      roc_ie_ow_ucc_is_success (uc_ccode));
    }
  else
    {
      u8 hw_ccode = cpt_hdr->cn10k.w3.hw_ccode;
      u8 uc_ccode = cpt_hdr->cn10k.w3.uc_ccode;

      return (((1U << hw_ccode) & CPT_COMP_HWGOOD_MASK) &&
	      roc_ie_ot_ucc_is_success (uc_ccode));
    }
}

static_always_inline u32
oct_get_len_from_meta (union cpt_parse_hdr_u *cpt_hdr, u64 w0, u64 w4)
{
  u32 len;
  uintptr_t ip;
  ip = (uintptr_t) cpt_hdr + ((w4 >> 16) & 0xFF);
  ip += ((w0 >> 40) & 0x6);
  len = plt_be_to_cpu_16 (*(u16 *) ip);
  len += ((w4 >> 16) & 0xFF) - (w4 & 0xFF);
  len += (w0 & BIT (42)) ? 40 : 0;

  return len;
}

static_always_inline void
oct_rx_ipsec_set_error (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_buffer_t *b, union cpt_parse_hdr_u *cpt_hdr,
			const u64 fp_flags)
{
  u8 uc_err;
  if (fp_flags & OCT_FP_FLAG_O20)
    {
      uc_err = cpt_hdr->s.w3.uc_ccode;
      switch (uc_err)
	{
	  /* clang-format off */
#define _(f, n, s, d)                                               \
    case ROC_IE_OW_UCC_##f:                                         \
      b->error = node->errors[OCT_RX_NODE_CTR_##f];                 \
      break;
    foreach_octeon_ipsec_ucc;
#undef _
	  /* clang-format on */
	default:
	  b->error = node->errors[OCT_RX_NODE_CTR_ERR_UNDEFINED];
	}
    }
  else
    {
      uc_err = cpt_hdr->cn10k.w3.uc_ccode;
      switch (uc_err)
	{
	  /* clang-format off */
#define _(f, n, s, d)                                               \
    case ROC_IE_OT_UCC_##f:                                         \
      b->error = node->errors[OCT_RX_NODE_CTR_##f];                 \
      break;
    foreach_octeon_ipsec_ucc;
#undef _
      /* clang-format on */
    default:
      b->error = node->errors[OCT_RX_NODE_CTR_ERR_UNDEFINED];
    }
    }
}

#define OCT_SEG_LEN_SHIFT 16
#define OCT_SEG_LEN_MASK  0xFFFF

static_always_inline void
oct_rx_ipsec_attach_tail (vlib_main_t *vm, oct_rx_node_ctx_t *ctx,
			  const union nix_rx_parse_u *rxp0,
			  vlib_buffer_template_t *bt, vlib_buffer_t *b)
{
  u32 n_words, n_words_processed, desc_sizem1;
  vlib_buffer_t *last_buf, *seg_buf;
  u32 n_sg_desc, n_segs, next_seg;
  u32 current_desc, bi, sg_len;
  vlib_buffer_t *buf = b;
  struct nix_rx_sg_s *sg;
  u32 total_segs = 0;
  u64 seg_len;
  i64 len;

  desc_sizem1 = rxp0->desc_sizem1;
  if (desc_sizem1 == 0)
    return;

  n_words = desc_sizem1 << 1;
  n_sg_desc = (n_words / 4) + 1;

  sg = (struct nix_rx_sg_s *) (((char *) rxp0) + sizeof (*rxp0));
  /* Typecast to u64 to read each seg length swiftly */
  seg_len = *(u64 *) sg;
  n_segs = sg->segs;

  /* Start with first descriptor */
  current_desc = 0;

  len = buf->current_length;
  /*
   * We updated length which is valid in single segment case.
   * incase of multi seg, update seg1 length and advance total words processed.
   * also, updates total bytes in buffer.
   */
  sg_len = seg_len & OCT_SEG_LEN_MASK;
  len -= sg_len;
  if (len < 0)
    {
      sg_len = sg_len + len;
      len = 0;
    }
  buf->current_length = sg_len;

  /* Process from 2nd segment */
  next_seg = 2;
  seg_len = seg_len >> OCT_SEG_LEN_SHIFT;
  n_words_processed = 2;

  buf->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  buf->total_length_not_including_first_buffer = 0;
  last_buf = buf;

  while (current_desc <= n_sg_desc)
    {
      while (next_seg <= n_segs)
	{
	  seg_buf = (vlib_buffer_t *) ((*(((u64 *) sg) + n_words_processed)) -
				       sizeof (vlib_buffer_t));
	  seg_buf->template = *bt;
	  sg_len = seg_len & OCT_SEG_LEN_MASK;
	  /*
	   * Adjust last buf data length with negative offset for
	   * ipsec pkts if needed.
	   */
	  len -= sg_len;
	  if (len < 0)
	    {
	      sg_len = sg_len + len;
	      len = 0;
	    }

	  seg_buf->current_length = sg_len;
	  bi = vlib_get_buffer_index (vm, seg_buf);

	  if (seg_buf->current_length == 0)
	    {
	      vlib_buffer_free_no_next (vm, &bi, 1);
	      total_segs++;
	      goto done;
	    }

	  last_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  last_buf->next_buffer = bi;
	  last_buf = seg_buf;
	  seg_len = seg_len >> OCT_SEG_LEN_SHIFT;
	  buf->total_length_not_including_first_buffer +=
	    seg_buf->current_length;
	  n_words_processed++;
	  next_seg++;
	  total_segs++;
	}
      current_desc++;
      n_sg_desc--;
      if (n_sg_desc)
	{
	  struct nix_rx_sg_s *tsg;

	  tsg = (struct nix_rx_sg_s *) ((u64 *) sg + n_words_processed);
	  seg_len = *((u64 *) (tsg));
	  n_words_processed++;
	  /* Start over */
	  n_segs = tsg->segs;
	  next_seg = 1;
	}
    }

done:
  ctx->n_segs += total_segs;
}

static_always_inline u32
oct_rx_inl_ipsec_vlib_from_cq (
  vlib_main_t *vm, vlib_node_runtime_t *node, oct_nix_rx_cqe_desc_t *d,
  vlib_buffer_t **b, oct_rx_node_ctx_t *ctx, vlib_buffer_template_t *bt,
  union cpt_parse_hdr_u *cpt_hdr, vlib_buffer_t **buffs, u32 *err_flags,
  u16 *next, u16 *buffer_next_index, const u64 fp_flags)
{
  union nix_rx_parse_u *orig_rxp, *rxp;
  u32 is_fail, olen, esp_sz, l2_ol3_sz;
  u64 *wqe_ptr;
  u8 frag_cnt;

  rxp = &d->parse.f;
  cpt_hdr = (union cpt_parse_hdr_u *) *(((u64 *) d) + 9);
  wqe_ptr = (u64 *) oct_get_wqe_from_cpt_hdr (cpt_hdr, fp_flags);

  b[0] = (vlib_buffer_t *) ((u8 *) wqe_ptr - 128);
  orig_rxp = (union nix_rx_parse_u *) (wqe_ptr + 1);
  l2_ol3_sz = orig_rxp->leptr - orig_rxp->laptr;
  olen = orig_rxp->pkt_lenm1 + 1;
  esp_sz = olen - l2_ol3_sz;
  b[0]->template = *bt;
  b[0]->flow_id = d[0].parse.w[3] >> 48;
  *err_flags |= ((d[0].parse.w[0] >> 20) & 0xFFF);

  is_fail = !oct_ipsec_is_inl_op_success (cpt_hdr, fp_flags);

  buffs[*buffer_next_index] = b[0];
  if (PREDICT_FALSE (is_fail))
    {
      b[0]->current_length = olen;
      clib_memcpy_fast (rxp, orig_rxp, sizeof (oct_nix_rx_parse_t));
      next[*buffer_next_index] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
      *buffer_next_index = *buffer_next_index + 1;
      oct_rx_ipsec_set_error (vm, node, b[0], cpt_hdr, fp_flags);
      frag_cnt = 1;
    }
  else
    {
      next[*buffer_next_index] = ctx->next_index;
      *buffer_next_index = *buffer_next_index + 1;
      b[0]->current_length =
	oct_get_len_from_meta (cpt_hdr, d[0].parse.w[0], d[0].parse.w[4]);

      frag_cnt = oct_rx_ipsec_reassembly (vm, node, bt, cpt_hdr, &d[0], b[0],
					  buffs, next, buffer_next_index,
					  &olen, &esp_sz, l2_ol3_sz, fp_flags);
    }
  oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp, bt, b[0]);
  ctx->n_rx_bytes += olen;
  ctx->n_segs += frag_cnt;

  if (fp_flags & OCT_FP_FLAG_TRACE_EN)
    clib_memcpy_fast (b[0]->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));

  return 0;
}

static_always_inline u32
oct_rx_vlib_from_cq (vlib_main_t *vm, oct_nix_rx_cqe_desc_t *d,
		     vlib_buffer_t **b, oct_rx_node_ctx_t *ctx,
		     vlib_buffer_template_t *bt, vlib_buffer_t **buffs,
		     u32 *err_flags, u16 *next, u16 *buffer_next_index,
		     const u64 fp_flags)
{
  b[0] = (vlib_buffer_t *) d->segs0[0] - 1;
  b[0]->template = *bt;
  ctx->n_rx_bytes += b[0]->current_length = d[0].sg0.seg1_size;
  b[0]->flow_id = d[0].parse.w[3] >> 48;
  *err_flags |= ((d[0].parse.w[0] >> 20) & 0xFFF);
  ctx->n_segs += 1;
  if (d[0].sg0.segs > 1)
    oct_rx_attach_tail (vm, ctx, bt, b[0], d + 0);
  buffs[*buffer_next_index] = b[0];
  next[*buffer_next_index] = ctx->next_index;
  *buffer_next_index = *buffer_next_index + 1;

  if (fp_flags & OCT_FP_FLAG_TRACE_EN)
    clib_memcpy_fast (b[0]->pre_data, d, sizeof (oct_nix_rx_cqe_desc_t));

  return 0;
}

#define OCT_PUSH_META_TO_FREE(_metabuf, _laddr, _loff_p)                      \
  do                                                                          \
    {                                                                         \
      *(u64 *) ((_laddr) + (*(_loff_p) << 3)) = (u64) _metabuf;               \
      *(_loff_p) = *(_loff_p) + 1;                                            \
    }                                                                         \
  while (0)

#define LMT_OFF(lmt_addr, lmt_num, offset)                                    \
  (void *) ((uintptr_t) (lmt_addr) +                                          \
	    ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2) + (offset))

static_always_inline void
oct_rx_flush_meta_burst (u16 lmt_id, u64 data, u16 lnum, uintptr_t aura_handle)
{
  u64 pa;

  /* Prepare PA and Data */
  pa = roc_npa_aura_handle_to_base (aura_handle) + NPA_LF_AURA_BATCH_FREE0;
  pa |= ((data & 0x7) << 4);

  data >>= 3;
  data <<= 19;
  data |= (u64) lmt_id;
  data |= (u64) (lnum - 1) << 12;

  roc_lmt_submit_steorl (data, pa);
}

static_always_inline u32
oct_rx_batch (vlib_main_t *vm, vlib_node_runtime_t *node,
	      oct_rx_node_ctx_t *ctx, vnet_dev_rx_queue_t *rxq, u32 n,
	      vlib_buffer_t **buffers, const u64 fp_flags)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 b0_err_flags = 0, b1_err_flags = 0;
  u32 b2_err_flags = 0, b3_err_flags = 0;
  u32 n_left, err_flags = 0;
  oct_nix_rx_cqe_desc_t *d = ctx->next_desc;
  union cpt_parse_hdr_u *cpt_hdr0, *cpt_hdr1;
  union cpt_parse_hdr_u *cpt_hdr2, *cpt_hdr3;
  union nix_rx_parse_u *rxp0, *rxp1;
  union nix_rx_parse_u *rxp2, *rxp3;
  union nix_rx_parse_u *orig_rxp0, *orig_rxp1;
  union nix_rx_parse_u *orig_rxp2, *orig_rxp3;
  u8 is_b0_from_cpt, is_b1_from_cpt;
  u8 is_b2_from_cpt, is_b3_from_cpt;
  u64 *wqe_ptr0, *wqe_ptr1;
  u64 *wqe_ptr2, *wqe_ptr3;
  u32 is_fail0, is_fail1, is_fail2, is_fail3;
  u32 olen0, olen1, olen2, olen3;
  u32 esp_sz0, esp_sz1, esp_sz2, esp_sz3;
  u32 l2_ol3_sz0, l2_ol3_sz1, l2_ol3_sz2, l2_ol3_sz3;
  vlib_buffer_t *b[4];
  vlib_buffer_t **buffs = buffers + ctx->buffer_start_index;
  u16 *next = ctx->next + ctx->buffer_start_index;
  u8 frag_cnt0 = 1, frag_cnt1 = 1;
  u8 frag_cnt2 = 1, frag_cnt3 = 1;
  u8 n_from_cpt, n_cpt_err;
  u64 meta_aura_handle;
  u64 lbase = crq->lmt_base_addr;
  u8 loff = 0, lnum = 0, shft = 0;
  u16 lmt_id, buffer_next_index = 0;
  u16 cqe_desc_bytes = sizeof (oct_nix_rx_cqe_desc_t);
  u64 laddr;

  meta_aura_handle = crq->rq.meta_aura_handle;
  ROC_LMT_BASE_ID_GET (lbase, lmt_id);
  laddr = lbase;
  laddr += 8;

  for (n_left = n; n_left >= 8; d += 4, n_left -= 4)
    {
      u32 segs = 0;
      clib_prefetch_store (oct_seg_to_bp (d[4].segs0[0]));
      clib_prefetch_store (oct_seg_to_bp (d[5].segs0[0]));
      b[0] = oct_seg_to_bp (d[0].segs0[0]);
      clib_prefetch_store (oct_seg_to_bp (d[6].segs0[0]));
      b[1] = oct_seg_to_bp (d[1].segs0[0]);
      clib_prefetch_store (oct_seg_to_bp (d[7].segs0[0]));
      b[2] = oct_seg_to_bp (d[2].segs0[0]);
      b[3] = oct_seg_to_bp (d[3].segs0[0]);

      rxp0 = &d[0].parse.f;
      rxp1 = &d[1].parse.f;
      rxp2 = &d[2].parse.f;
      rxp3 = &d[3].parse.f;

      is_b0_from_cpt = oct_is_packet_from_cpt (&d[0].parse.f);
      is_b1_from_cpt = oct_is_packet_from_cpt (&d[1].parse.f);
      is_b2_from_cpt = oct_is_packet_from_cpt (&d[2].parse.f);
      is_b3_from_cpt = oct_is_packet_from_cpt (&d[3].parse.f);

      n_from_cpt =
	is_b0_from_cpt + is_b1_from_cpt + is_b2_from_cpt + is_b3_from_cpt;
      if (n_from_cpt == 0)
	{
	  next[buffer_next_index + 0] = ctx->next_index;
	  next[buffer_next_index + 1] = ctx->next_index;
	  next[buffer_next_index + 2] = ctx->next_index;
	  next[buffer_next_index + 3] = ctx->next_index;

	  b[0]->template = bt;
	  b[1]->template = bt;
	  b[2]->template = bt;
	  b[3]->template = bt;

	  ctx->n_rx_bytes += b[0]->current_length = d[0].sg0.seg1_size;
	  ctx->n_rx_bytes += b[1]->current_length = d[1].sg0.seg1_size;
	  ctx->n_rx_bytes += b[2]->current_length = d[2].sg0.seg1_size;
	  ctx->n_rx_bytes += b[3]->current_length = d[3].sg0.seg1_size;

	  b[0]->flow_id = d[0].parse.w[3] >> 48;
	  b[1]->flow_id = d[1].parse.w[3] >> 48;
	  b[2]->flow_id = d[2].parse.w[3] >> 48;
	  b[3]->flow_id = d[3].parse.w[3] >> 48;

	  b0_err_flags = (d[0].parse.w[0] >> 20) & 0xFFF;
	  b1_err_flags = (d[1].parse.w[0] >> 20) & 0xFFF;
	  b2_err_flags = (d[2].parse.w[0] >> 20) & 0xFFF;
	  b3_err_flags = (d[3].parse.w[0] >> 20) & 0xFFF;

	  err_flags |=
	    b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;

	  if (fp_flags & OCT_FP_FLAG_TRACE_EN)
	    {
	      clib_memcpy_fast (b[0]->pre_data, &d[0], cqe_desc_bytes);
	      clib_memcpy_fast (b[1]->pre_data, &d[1], cqe_desc_bytes);
	      clib_memcpy_fast (b[2]->pre_data, &d[2], cqe_desc_bytes);
	      clib_memcpy_fast (b[3]->pre_data, &d[3], cqe_desc_bytes);
	    }

	  ctx->n_segs += 4;
	  segs = d[0].sg0.segs + d[1].sg0.segs + d[2].sg0.segs + d[3].sg0.segs;

	  if (PREDICT_FALSE (segs > 4))
	    {
	      oct_rx_attach_tail (vm, ctx, &bt, b[0], d + 0);
	      oct_rx_attach_tail (vm, ctx, &bt, b[1], d + 1);
	      oct_rx_attach_tail (vm, ctx, &bt, b[2], d + 2);
	      oct_rx_attach_tail (vm, ctx, &bt, b[3], d + 3);
	    }

	  buffs[buffer_next_index + 0] = b[0];
	  buffs[buffer_next_index + 1] = b[1];
	  buffs[buffer_next_index + 2] = b[2];
	  buffs[buffer_next_index + 3] = b[3];

	  buffer_next_index += 4;
	}
      else if (n_from_cpt == 4)
	{
	  /* All packets are from cpt */
	  cpt_hdr0 = (union cpt_parse_hdr_u *) *(((u64 *) &d[0]) + 9);
	  cpt_hdr1 = (union cpt_parse_hdr_u *) *(((u64 *) &d[1]) + 9);
	  cpt_hdr2 = (union cpt_parse_hdr_u *) *(((u64 *) &d[2]) + 9);
	  cpt_hdr3 = (union cpt_parse_hdr_u *) *(((u64 *) &d[3]) + 9);

	  wqe_ptr0 = (u64 *) oct_get_wqe_from_cpt_hdr (cpt_hdr0, fp_flags);
	  wqe_ptr1 = (u64 *) oct_get_wqe_from_cpt_hdr (cpt_hdr1, fp_flags);
	  wqe_ptr2 = (u64 *) oct_get_wqe_from_cpt_hdr (cpt_hdr2, fp_flags);
	  wqe_ptr3 = (u64 *) oct_get_wqe_from_cpt_hdr (cpt_hdr3, fp_flags);

	  b[0] = (vlib_buffer_t *) ((u8 *) wqe_ptr0 - 128);
	  b[1] = (vlib_buffer_t *) ((u8 *) wqe_ptr1 - 128);
	  b[2] = (vlib_buffer_t *) ((u8 *) wqe_ptr2 - 128);
	  b[3] = (vlib_buffer_t *) ((u8 *) wqe_ptr3 - 128);

	  orig_rxp0 = (union nix_rx_parse_u *) (wqe_ptr0 + 1);
	  orig_rxp1 = (union nix_rx_parse_u *) (wqe_ptr1 + 1);
	  orig_rxp2 = (union nix_rx_parse_u *) (wqe_ptr2 + 1);
	  orig_rxp3 = (union nix_rx_parse_u *) (wqe_ptr3 + 1);

	  l2_ol3_sz0 = orig_rxp0->leptr - orig_rxp0->laptr;
	  l2_ol3_sz1 = orig_rxp1->leptr - orig_rxp1->laptr;
	  l2_ol3_sz2 = orig_rxp2->leptr - orig_rxp2->laptr;
	  l2_ol3_sz3 = orig_rxp3->leptr - orig_rxp3->laptr;

	  olen0 = orig_rxp0->pkt_lenm1 + 1;
	  olen1 = orig_rxp1->pkt_lenm1 + 1;
	  olen2 = orig_rxp2->pkt_lenm1 + 1;
	  olen3 = orig_rxp3->pkt_lenm1 + 1;

	  esp_sz0 = olen0 - l2_ol3_sz0;
	  esp_sz1 = olen1 - l2_ol3_sz1;
	  esp_sz2 = olen2 - l2_ol3_sz2;
	  esp_sz3 = olen3 - l2_ol3_sz3;

	  b[0]->template = bt;
	  b[1]->template = bt;
	  b[2]->template = bt;
	  b[3]->template = bt;

	  is_fail0 = !oct_ipsec_is_inl_op_success (cpt_hdr0, fp_flags);
	  is_fail1 = !oct_ipsec_is_inl_op_success (cpt_hdr1, fp_flags);
	  is_fail2 = !oct_ipsec_is_inl_op_success (cpt_hdr2, fp_flags);
	  is_fail3 = !oct_ipsec_is_inl_op_success (cpt_hdr3, fp_flags);
	  n_cpt_err = is_fail0 + is_fail1 + is_fail2 + is_fail3;

	  if (PREDICT_TRUE (!n_cpt_err))
	    {
	      b[0]->current_length = oct_get_len_from_meta (
		cpt_hdr0, d[0].parse.w[0], d[0].parse.w[4]);
	      b[1]->current_length = oct_get_len_from_meta (
		cpt_hdr1, d[1].parse.w[0], d[1].parse.w[4]);
	      b[2]->current_length = oct_get_len_from_meta (
		cpt_hdr2, d[2].parse.w[0], d[2].parse.w[4]);
	      b[3]->current_length = oct_get_len_from_meta (
		cpt_hdr3, d[3].parse.w[0], d[3].parse.w[4]);

	      next[buffer_next_index] = ctx->next_index;
	      buffs[buffer_next_index] = b[0];
	      buffer_next_index += 1;
	      frag_cnt0 = oct_rx_ipsec_reassembly (
		vm, node, &bt, cpt_hdr0, &d[0], b[0], buffs, next,
		&buffer_next_index, &olen0, &esp_sz0, l2_ol3_sz0, fp_flags);

	      buffs[buffer_next_index] = b[1];
	      next[buffer_next_index] = ctx->next_index;
	      buffer_next_index += 1;
	      frag_cnt1 = oct_rx_ipsec_reassembly (
		vm, node, &bt, cpt_hdr1, &d[1], b[1], buffs, next,
		&buffer_next_index, &olen1, &esp_sz1, l2_ol3_sz1, fp_flags);

	      buffs[buffer_next_index] = b[2];
	      next[buffer_next_index] = ctx->next_index;
	      buffer_next_index += 1;
	      frag_cnt2 = oct_rx_ipsec_reassembly (
		vm, node, &bt, cpt_hdr2, &d[2], b[2], buffs, next,
		&buffer_next_index, &olen2, &esp_sz2, l2_ol3_sz2, fp_flags);

	      buffs[buffer_next_index] = b[3];
	      next[buffer_next_index] = ctx->next_index;
	      buffer_next_index += 1;
	      frag_cnt3 = oct_rx_ipsec_reassembly (
		vm, node, &bt, cpt_hdr3, &d[3], b[3], buffs, next,
		&buffer_next_index, &olen3, &esp_sz3, l2_ol3_sz3, fp_flags);

	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp0, &bt, b[0]);
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp1, &bt, b[1]);
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp2, &bt, b[2]);
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp3, &bt, b[3]);
	    }
	  else
	    {
	      buffs[buffer_next_index] = b[0];

	      if (is_fail0)
		{
		  b[0]->current_length = olen0;
		  clib_memcpy_fast (rxp0, orig_rxp0,
				    sizeof (oct_nix_rx_parse_t));
		  next[buffer_next_index] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
		  buffer_next_index += 1;
		  oct_rx_ipsec_set_error (vm, node, b[0], cpt_hdr0, fp_flags);
		  frag_cnt0 = 1;
		}
	      else
		{
		  next[buffer_next_index] = ctx->next_index;
		  buffer_next_index += 1;
		  b[0]->current_length = oct_get_len_from_meta (
		    cpt_hdr0, d[0].parse.w[0], d[0].parse.w[4]);

		  frag_cnt0 = oct_rx_ipsec_reassembly (
		    vm, node, &bt, cpt_hdr0, &d[0], b[0], buffs, next,
		    &buffer_next_index, &olen0, &esp_sz0, l2_ol3_sz0,
		    fp_flags);
		}
	      /* Success and Failure both cases can be multi seg */
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp0, &bt, b[0]);

	      buffs[buffer_next_index] = b[1];

	      if (is_fail1)
		{
		  b[1]->current_length = olen1;
		  clib_memcpy_fast (rxp1, orig_rxp1,
				    sizeof (oct_nix_rx_parse_t));
		  next[buffer_next_index] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
		  buffer_next_index += 1;
		  oct_rx_ipsec_set_error (vm, node, b[1], cpt_hdr1, fp_flags);
		  frag_cnt1 = 1;
		}
	      else
		{
		  next[buffer_next_index] = ctx->next_index;
		  buffer_next_index += 1;
		  b[1]->current_length = oct_get_len_from_meta (
		    cpt_hdr1, d[1].parse.w[0], d[1].parse.w[4]);
		  frag_cnt1 = oct_rx_ipsec_reassembly (
		    vm, node, &bt, cpt_hdr1, &d[1], b[1], buffs, next,
		    &buffer_next_index, &olen1, &esp_sz1, l2_ol3_sz1,
		    fp_flags);
		}
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp1, &bt, b[1]);

	      buffs[buffer_next_index] = b[2];

	      if (is_fail2)
		{
		  b[2]->current_length = olen2;
		  clib_memcpy_fast (rxp2, orig_rxp2,
				    sizeof (oct_nix_rx_parse_t));
		  next[buffer_next_index] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
		  buffer_next_index += 1;
		  oct_rx_ipsec_set_error (vm, node, b[2], cpt_hdr2, fp_flags);
		  frag_cnt2 = 1;
		}
	      else
		{
		  next[buffer_next_index] = ctx->next_index;
		  buffer_next_index += 1;
		  b[2]->current_length = oct_get_len_from_meta (
		    cpt_hdr2, d[2].parse.w[0], d[2].parse.w[4]);
		  frag_cnt2 = oct_rx_ipsec_reassembly (
		    vm, node, &bt, cpt_hdr2, &d[2], b[2], buffs, next,
		    &buffer_next_index, &olen2, &esp_sz2, l2_ol3_sz2,
		    fp_flags);
		}
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp2, &bt, b[2]);

	      buffs[buffer_next_index] = b[3];

	      if (is_fail3)
		{
		  b[3]->current_length = olen3;
		  clib_memcpy_fast (rxp3, orig_rxp3,
				    sizeof (oct_nix_rx_parse_t));
		  next[buffer_next_index] = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
		  buffer_next_index += 1;
		  oct_rx_ipsec_set_error (vm, node, b[3], cpt_hdr3, fp_flags);
		  frag_cnt3 = 1;
		}
	      else
		{
		  next[buffer_next_index] = ctx->next_index;
		  buffer_next_index += 1;
		  b[3]->current_length = oct_get_len_from_meta (
		    cpt_hdr3, d[3].parse.w[0], d[3].parse.w[4]);

		  frag_cnt3 = oct_rx_ipsec_reassembly (
		    vm, node, &bt, cpt_hdr3, &d[3], b[3], buffs, next,
		    &buffer_next_index, &olen3, &esp_sz3, l2_ol3_sz3,
		    fp_flags);
		}
	      oct_rx_ipsec_attach_tail (vm, ctx, orig_rxp3, &bt, b[3]);
	    }
	  ctx->n_rx_bytes += olen0 + olen1 + olen2 + olen3;
	  ctx->n_segs += frag_cnt0 + frag_cnt1 + frag_cnt2 + frag_cnt3;

	  b[0]->flow_id = d[0].parse.w[3] >> 48;
	  b[1]->flow_id = d[1].parse.w[3] >> 48;
	  b[2]->flow_id = d[2].parse.w[3] >> 48;
	  b[3]->flow_id = d[3].parse.w[3] >> 48;

	  b0_err_flags = (d[0].parse.w[0] >> 20) & 0xFFF;
	  b1_err_flags = (d[1].parse.w[0] >> 20) & 0xFFF;
	  b2_err_flags = (d[2].parse.w[0] >> 20) & 0xFFF;
	  b3_err_flags = (d[3].parse.w[0] >> 20) & 0xFFF;

	  err_flags |=
	    b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;

	  OCT_PUSH_META_TO_FREE ((u64) cpt_hdr0, laddr, &loff);
	  OCT_PUSH_META_TO_FREE ((u64) cpt_hdr1, laddr, &loff);
	  OCT_PUSH_META_TO_FREE ((u64) cpt_hdr2, laddr, &loff);
	  OCT_PUSH_META_TO_FREE ((u64) cpt_hdr3, laddr, &loff);

	  if (fp_flags & OCT_FP_FLAG_TRACE_EN)
	    {
	      clib_memcpy_fast (b[0]->pre_data, &d[0], cqe_desc_bytes);
	      clib_memcpy_fast (b[1]->pre_data, &d[1], cqe_desc_bytes);
	      clib_memcpy_fast (b[2]->pre_data, &d[2], cqe_desc_bytes);
	      clib_memcpy_fast (b[3]->pre_data, &d[3], cqe_desc_bytes);
	    }
	}
      else
	{
	  /* CQ ring contains mix of packets from wire and CPT */
	  if (is_b0_from_cpt)
	    {
	      cpt_hdr0 = (union cpt_parse_hdr_u *) *(((u64 *) &d[0]) + 9);
	      oct_rx_inl_ipsec_vlib_from_cq (vm, node, &d[0], &b[0], ctx, &bt,
					     cpt_hdr0, buffs, &err_flags, next,
					     &buffer_next_index, fp_flags);
	      OCT_PUSH_META_TO_FREE ((u64) cpt_hdr0, laddr, &loff);
	    }
	  else
	    oct_rx_vlib_from_cq (vm, &d[0], &b[0], ctx, &bt, buffs, &err_flags,
				 next, &buffer_next_index, fp_flags);

	  if (is_b1_from_cpt)
	    {
	      cpt_hdr1 = (union cpt_parse_hdr_u *) *(((u64 *) &d[1]) + 9);
	      oct_rx_inl_ipsec_vlib_from_cq (vm, node, &d[1], &b[1], ctx, &bt,
					     cpt_hdr1, buffs, &err_flags, next,
					     &buffer_next_index, fp_flags);
	      OCT_PUSH_META_TO_FREE ((u64) cpt_hdr1, laddr, &loff);
	    }
	  else
	    oct_rx_vlib_from_cq (vm, &d[1], &b[1], ctx, &bt, buffs, &err_flags,
				 next, &buffer_next_index, fp_flags);
	  if (is_b2_from_cpt)
	    {
	      cpt_hdr2 = (union cpt_parse_hdr_u *) *(((u64 *) &d[2]) + 9);
	      oct_rx_inl_ipsec_vlib_from_cq (vm, node, &d[2], &b[2], ctx, &bt,
					     cpt_hdr2, buffs, &err_flags, next,
					     &buffer_next_index, fp_flags);
	      OCT_PUSH_META_TO_FREE ((u64) cpt_hdr2, laddr, &loff);
	    }
	  else
	    oct_rx_vlib_from_cq (vm, &d[2], &b[2], ctx, &bt, buffs, &err_flags,
				 next, &buffer_next_index, fp_flags);
	  if (is_b3_from_cpt)
	    {
	      cpt_hdr3 = (union cpt_parse_hdr_u *) *(((u64 *) &d[3]) + 9);
	      oct_rx_inl_ipsec_vlib_from_cq (vm, node, &d[3], &b[3], ctx, &bt,
					     cpt_hdr3, buffs, &err_flags, next,
					     &buffer_next_index, fp_flags);
	      OCT_PUSH_META_TO_FREE ((u64) cpt_hdr3, laddr, &loff);
	    }
	  else
	    oct_rx_vlib_from_cq (vm, &d[3], &b[3], ctx, &bt, buffs, &err_flags,
				 next, &buffer_next_index, fp_flags);
	}
      /* Check if lmtline border is crossed and adjust lnum */
      if (loff > 15)
	{
	  /* Update aura handle */
	  *(u64 *) (laddr - 8) =
	    (((u64) (15 & 0x1) << 32) |
	     roc_npa_aura_handle_to_aura (meta_aura_handle));
	  loff = loff - 15;
	  shft += 3;

	  lnum++;
	  laddr = (uintptr_t) LMT_OFF (lbase, lnum, 8);
	  /* Pick the pointer from 16th index and put it
	   * at end of this new line.
	   */
	  *(u64 *) (laddr + (loff << 3) - 8) = *(u64 *) (laddr - 8);
	}

      /* Flush it when we are in 16th line and might
       * overflow it
       */
      if (lnum >= 15 && loff >= 12)
	{
	  /* 16 LMT Line size m1 */
	  u64 data = BIT_ULL (48) - 1;

	  /* Update aura handle */
	  *(u64 *) (laddr - 8) =
	    (((u64) (loff & 0x1) << 32) |
	     roc_npa_aura_handle_to_aura (meta_aura_handle));

	  data = (data & ~(0x7UL << shft)) | (((u64) loff >> 1) << shft);

	  /* Send up to 16 lmt lines of pointers */
	  oct_rx_flush_meta_burst (lmt_id, data, lnum + 1, meta_aura_handle);
	  plt_wmb ();
	  lnum = 0;
	  loff = 0;
	  shft = 0;
	  /* First pointer starts at 8B offset */
	  laddr = (uintptr_t) LMT_OFF (lbase, lnum, 8);
	}
    }

  if (loff)
    {
      /* 16 LMT Line size m1 */
      u64 data = BIT_ULL (48) - 1;

      /* Update aura handle */
      *(u64 *) (laddr - 8) = (((u64) (loff & 0x1) << 32) |
			      roc_npa_aura_handle_to_aura (meta_aura_handle));

      data = (data & ~(0x7UL << shft)) | (((u64) loff >> 1) << shft);

      /* Send up to 16 lmt lines of pointers */
      oct_rx_flush_meta_burst (lmt_id, data, lnum + 1, meta_aura_handle);
      plt_wmb ();
      lnum = 0;
      loff = 0;
      shft = 0;
      /* First pointer starts at 8B offset */
      laddr = (uintptr_t) LMT_OFF (lbase, lnum, 8);
    }

  for (; n_left; d += 1, n_left -= 1)
    {
      is_b0_from_cpt = oct_is_packet_from_cpt (&d[0].parse.f);
      if (is_b0_from_cpt)
	{
	  cpt_hdr0 = (union cpt_parse_hdr_u *) *(((u64 *) &d[0]) + 9);
	  oct_rx_inl_ipsec_vlib_from_cq (vm, node, &d[0], &b[0], ctx, &bt,
					 cpt_hdr0, buffs, &err_flags, next,
					 &buffer_next_index, fp_flags);
	  OCT_PUSH_META_TO_FREE ((u64) cpt_hdr0, laddr, &loff);
	}
      else

	oct_rx_vlib_from_cq (vm, &d[0], &b[0], ctx, &bt, buffs, &err_flags,
			     next, &buffer_next_index, fp_flags);
    }
  if (loff)
    {
      /* 16 LMT Line size m1 */
      u64 data = BIT_ULL (48) - 1;

      /* Update aura handle */
      *(u64 *) (laddr - 8) = (((u64) (loff & 0x1) << 32) |
			      roc_npa_aura_handle_to_aura (meta_aura_handle));

      data = (data & ~(0x7UL << shft)) | (((u64) loff >> 1) << shft);

      /* Send up to 16 lmt lines of pointers */
      oct_rx_flush_meta_burst (lmt_id, data, lnum + 1, meta_aura_handle);
      plt_wmb ();
    }

  plt_write64 ((crq->cq.wdata | n), crq->cq.door);
  ctx->n_rx_pkts += buffer_next_index;
  ctx->n_left_to_next -= buffer_next_index;
  ctx->buffer_start_index += buffer_next_index;
  if (err_flags)
    ctx->parse_w0_or = (err_flags << 20);

  return buffer_next_index;
}

#ifdef PLATFORM_OCTEON9
static_always_inline u32
oct_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u16 n_refill)
{
  u32 n_alloc, n_free;
  u32 buffer_indices[n_refill];
  vlib_buffer_t *buffers[n_refill];
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u64 aura = roc_npa_aura_handle_to_aura (crq->aura_handle);
  const u64 addr =
    roc_npa_aura_handle_to_base (crq->aura_handle) + NPA_LF_AURA_OP_FREE0;

  if (n_refill < 256)
    return 0;

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_refill);
  if (PREDICT_FALSE (n_alloc < n_refill))
    goto alloc_fail;

  vlib_get_buffers (vm, buffer_indices, (vlib_buffer_t **) buffers, n_alloc);

  for (n_free = 0; n_free < n_alloc; n_free++)
    roc_store_pair ((u64) buffers[n_free], aura, addr);

  return n_alloc;

alloc_fail:
  vlib_buffer_unalloc_to_pool (vm, buffer_indices, n_alloc, bpi);
  return 0;
}
#else
static_always_inline void
oct_rxq_refill_batch (vlib_main_t *vm, u64 lmt_id, u64 addr,
		      oct_npa_lf_aura_batch_free_line_t *lines, u32 *bi,
		      oct_npa_lf_aura_batch_free0_t w0, u64 n_lines)
{
  u64 data;

  for (u32 i = 0; i < n_lines; i++, bi += 15)
    {
      lines[i].w0 = w0;
      vlib_get_buffers (vm, bi, (vlib_buffer_t **) lines[i].data, 15);
    }

  data = lmt_id | ((n_lines - 1) << 12) | ((1ULL << (n_lines * 3)) - 1) << 19;
  roc_lmt_submit_steorl (data, addr);

  /* Data Store Memory Barrier - outer shareable domain */
  asm volatile("dmb oshst" ::: "memory");
}

static_always_inline u32
oct_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u16 n_refill)
{
  const u32 batch_max_lines = 16;
  const u32 bufs_per_line = 15;
  const u32 batch_max_bufs = 15 * 16;

  u32 batch_bufs, n_lines, n_alloc;
  u32 buffer_indices[batch_max_bufs];
  u64 lmt_addr, lmt_id, addr, n_enq = 0;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  oct_npa_lf_aura_batch_free_line_t *lines;

  if (n_refill < bufs_per_line)
    return 0;

  n_lines = n_refill / bufs_per_line;

  addr = crq->aura_batch_free_ioaddr;
  lmt_addr = crq->lmt_base_addr;
  lmt_id = vm->thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
  lmt_addr += lmt_id << ROC_LMT_LINE_SIZE_LOG2;
  lines = (oct_npa_lf_aura_batch_free_line_t *) lmt_addr;

  oct_npa_lf_aura_batch_free0_t w0 = {
    .aura = roc_npa_aura_handle_to_aura (crq->aura_handle),
    .count_eot = 1,
  };

  while (n_lines >= batch_max_lines)
    {
      n_alloc =
	vlib_buffer_alloc_from_pool (vm, buffer_indices, batch_max_bufs, bpi);
      if (PREDICT_FALSE (n_alloc < batch_max_bufs))
	goto alloc_fail;
      oct_rxq_refill_batch (vm, lmt_id, addr, lines, buffer_indices, w0,
			    batch_max_lines);
      n_lines -= batch_max_lines;
      n_enq += batch_max_bufs;
    }

  if (n_lines == 0)
    return n_enq;

  batch_bufs = n_lines * bufs_per_line;
  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, batch_bufs, bpi);

  if (PREDICT_FALSE (n_alloc < batch_bufs))
    {
    alloc_fail:
      if (n_alloc >= bufs_per_line)
	{
	  u32 n_unalloc;
	  n_lines = n_alloc / bufs_per_line;
	  batch_bufs = n_lines * bufs_per_line;
	  n_unalloc = n_alloc - batch_bufs;

	  if (n_unalloc)
	    vlib_buffer_unalloc_to_pool (vm, buffer_indices + batch_bufs,
					 n_unalloc, bpi);
	}
      else
	{
	  if (n_alloc)
	    vlib_buffer_unalloc_to_pool (vm, buffer_indices, n_alloc, bpi);
	  return n_enq;
	}
    }

  oct_rxq_refill_batch (vm, lmt_id, addr, lines, buffer_indices, w0, n_lines);
  n_enq += batch_bufs;

  return n_enq;
}
#endif

static_always_inline void
oct_rx_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
	      oct_rx_node_ctx_t *ctx, oct_nix_rx_cqe_desc_t *d, u32 n_desc,
	      vlib_buffer_t **buffs)
{
  u32 i = 0;
  if (PREDICT_TRUE (ctx->trace_count == 0))
    return;

  while (ctx->n_traced < ctx->trace_count && i < n_desc)
    {
      vlib_buffer_t *b = *buffs;

      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, ctx->next_index, b,
					   /* follow_chain */ 0)))
	{
	  oct_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = ctx->next_index;
	  tr->sw_if_index = ctx->sw_if_index;
	  tr->desc = *(oct_nix_rx_cqe_desc_t *) b->pre_data;
	  ctx->n_traced++;
	}
      i++;
      buffs++;
    }
}

static_always_inline void
oct_rx_enq_to_next (vlib_main_t *vm, vlib_node_runtime_t *node,
		    oct_rx_node_ctx_t *ctx, u8 *is_single_next)
{
#ifdef PLATFORM_OCTEON9
  vlib_buffer_enqueue_to_single_next (vm, node, ctx->to_next, ctx->next_index,
				      ctx->n_rx_pkts);
#else
  u32 i;

  for (i = 0; i < ctx->n_rx_pkts; i++)
    {
      if (ctx->next[i] == VNET_DEV_ETH_RX_PORT_NEXT_DROP)
	{
	  *is_single_next = 0;
	  break;
	}
    }
  vlib_buffer_enqueue_to_next (vm, node, ctx->to_next, ctx->next,
			       ctx->n_rx_pkts);
#endif
}

static_always_inline uword
oct_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, vnet_dev_port_t *port,
		    vnet_dev_rx_queue_t *rxq, int with_flows, const u64 flags)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_desc, head, n, n_enq, n_processed = 0;
  u32 cq_size = crq->cq.nb_desc;
  u32 cq_mask = crq->cq.qmask;
  oct_nix_rx_cqe_desc_t *descs = crq->cq.desc_base;
  oct_nix_lf_cq_op_status_t status;
  u32 to_next[OCT_FRAME_SIZE];
  u16 next[OCT_FRAME_SIZE];
  vlib_buffer_t *buffs[OCT_FRAME_SIZE];
  u8 is_single_next = 1;
  oct_rx_node_ctx_t _ctx = {
    .next_index = vnet_dev_get_rx_queue_if_next_index(rxq),
    .sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq),
    .hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq),
    .to_next = to_next,
    .next = next,
    .n_left_to_next = OCT_FRAME_SIZE,
    .buffer_start_index = 0,
  }, *ctx = &_ctx;

  /* get head and tail from NIX_LF_CQ_OP_STATUS */
  status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
  if (status.cq_err || status.op_err)
    return 0;

  head = status.head;
  n_desc = (status.tail - head) & cq_mask;

  if (n_desc == 0)
    goto refill;

  ctx->trace_count = vlib_get_trace_count (vm, node);

  while (1)
    {
      ctx->next_desc = descs + head;
      n =
	clib_min (cq_size - head, clib_min (n_desc, ctx->n_left_to_next / 4));

      if (PREDICT_TRUE (ctx->trace_count == 0))
	n_processed += oct_rx_batch (vm, node, ctx, rxq, n, buffs, flags);
      else
	n_processed += oct_rx_batch (vm, node, ctx, rxq, n, buffs,
				     OCT_FP_FLAG_TRACE_EN | flags);

      if (n_processed >= 256)
	break;

      status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
      if (status.cq_err || status.op_err)
	break;

      head = status.head;
      n_desc = (status.tail - head) & cq_mask;
      if (n_desc == 0)
	break;
    }

  vlib_get_buffer_indices_with_offset (vm, (void **) buffs, ctx->to_next,
				       n_processed, 0);

  ctx->next = next;

  oct_rx_trace (vm, node, ctx, descs + head, n_processed, buffs);

  oct_rx_enq_to_next (vm, node, ctx, &is_single_next);

  if (ctx->n_traced)
    vlib_set_trace_count (vm, node, ctx->trace_count - ctx->n_traced);

  if (PREDICT_TRUE (is_single_next &&
		    ctx->next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      oct_nix_rx_parse_t p = { .w[0] = ctx->parse_w0_or };
      nf = vlib_node_runtime_get_next_frame (vm, node, ctx->next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = ctx->sw_if_index;
      ef->hw_if_index = ctx->hw_if_index;

      if (p.f.errcode == 0 && p.f.errlev == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

      vlib_frame_no_append (f);
    }

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, ctx->hw_if_index, ctx->n_rx_pkts, ctx->n_rx_bytes);

refill:
  n_enq = crq->n_enq - ctx->n_segs;
  n_enq += oct_rxq_refill (vm, rxq, rxq->size - n_enq);
  crq->n_enq = n_enq;

  return ctx->n_rx_pkts;
}

VNET_DEV_NODE_FN (oct_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;

      if (!rxq->started)
	continue;

      n_rx += oct_rx_node_inline (vm, node, frame, port, rxq, 0, 0);
    }

  return n_rx;
}

VNET_DEV_NODE_FN (oct_o20_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;

      if (!rxq->started)
	continue;

      n_rx +=
	oct_rx_node_inline (vm, node, frame, port, rxq, 0, OCT_FP_FLAG_O20);
    }

  return n_rx;
}
