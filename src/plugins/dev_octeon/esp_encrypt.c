#include <dev_octeon/octeon.h>
#include <dev_octeon/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/fib/fib_entry.h>

extern oct_ipsec_main_t oct_ipsec_main;

#define foreach_oct_esp_handoff_core                                          \
  _ (0)                                                                       \
  _ (1)                                                                       \
  _ (2)                                                                       \
  _ (3)                                                                       \
  _ (4)                                                                       \
  _ (5)                                                                       \
  _ (6)                                                                       \
  _ (7)                                                                       \
  _ (8)                                                                       \
  _ (9)                                                                       \
  _ (10)                                                                      \
  _ (11)                                                                      \
  _ (12)                                                                      \
  _ (13)                                                                      \
  _ (14)                                                                      \
  _ (15)                                                                      \
  _ (16)                                                                      \
  _ (17)                                                                      \
  _ (18)                                                                      \
  _ (19)                                                                      \
  _ (20)                                                                      \
  _ (21)                                                                      \
  _ (22)                                                                      \
  _ (23)                                                                      \
  _ (24)                                                                      \
  _ (25)                                                                      \
  _ (26)                                                                      \
  _ (27)                                                                      \
  _ (28)                                                                      \
  _ (29)                                                                      \
  _ (30)                                                                      \
  _ (31)                                                                      \
  _ (32)                                                                      \
  _ (33)                                                                      \
  _ (34)                                                                      \
  _ (35)

#define OCT_ESP_ENCRYPT_TUN_N_NEXT (OCT_ESP_ENCRYPT_TUN_NEXT_PREP35 + 1)

#define OCT_ESP_ENCRYPT_TUN_PREP_NODES(x, y)                                  \
  [OCT_ESP_ENCRYPT_TUN_NEXT_PREP##y] = #x #y,

#define foreach_oct_esp_encrypt_error                                         \
  _ (RX_PKTS, "ESP pkts received")                                            \
  _ (RX_POST_PKTS, "ESP-POST pkts received")                                  \
  _ (NOT_L3PKT, "L3 header offset not valid")                                 \
  _ (CHAINING_NOSUPP, "Packet chainining not supported in IPsec")             \
  _ (SEQ_CYCLED, "sequence number cycled (packet dropped)")                   \
  _ (HANDOFF, "handoff")                                                      \
  _ (INVALID_SA, "invalid SA")                                                \
  _ (FRAME_ALLOC, "encrypt ipsec frame alloc failed")                         \
  _ (UNDEFINED, "undefined encrypt error")

typedef struct
{
  u32 sa_index;
  u32 spi;
  u32 seq;
  u32 sa_seq_hi;
  u32 next_index;
  u32 owner_thread;
  u32 handoff_thread;
  u8 udp_encap;
  vlib_error_t error;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 data[256];
  vlib_buffer_t buf;
} oct_esp_encrypt_trace_t;

#define foreach_oct_esp_encrypt_tun_next                                      \
  _ (DROP4, "ip4-drop")                                                       \
  _ (DROP6, "ip6-drop")                                                       \
  _ (ADJ_MIDCHAIN_TX, "adj-midchain-tx")

/* clang-format off */
typedef enum
{
#define _(v, s) OCT_ESP_ENCRYPT_TUN_NEXT_##v,
  foreach_oct_esp_encrypt_tun_next
#undef _
#define _(Y) OCT_ESP_ENCRYPT_TUN_NEXT_PREP##Y,
  foreach_oct_esp_handoff_core
#undef _
} oct_esp_encrypt_tun_next_t;
/* clang-format on */

/* clang-format off */
typedef enum
{
#define _(sym, str) OCT_ESP_ENCRYPT_ERROR_##sym,
  foreach_oct_esp_encrypt_error
#undef _
#define _(sym, str) OCT_ESP_ENCRYPT_CN10K_ERROR_##sym,
  foreach_octeon_cn10k_ipsec_ucc
#undef _
} oct_esp_encrypt_error_t;
/* clang-format on */

/* Packet trace format function */
static u8 *
format_oct_esp_encrypt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  oct_esp_encrypt_trace_t *t = va_arg (*args, oct_esp_encrypt_trace_t *);
  vlib_error_main_t *em = &vm->error_main;
  u32 indent = format_get_indent (s);
  vlib_error_t e = t->error;
  u32 ci;

  s = format (s, "%U %U\n", format_white_space, indent, format_vnet_buffer,
	      &t->buf);

  if (e)
    {
      ci = vlib_error_get_code (&vm->node_main, e);

      ci += node->error_heap_index;

      s = format (s, "%UStatus: %s", format_white_space, indent,
		  em->counters_heap[ci].name);

      if (t->handoff_thread == t->owner_thread)
	s = format (s, ", Handoff thread: %u", t->handoff_thread);

      s = format (s, "\n");
    }

  s = format (s, "%USA owner thread: %u\n", format_white_space, indent,
	      t->owner_thread);

  if (t->next_index != ~0)
    s = format (s, "%Unext node: %U\n", format_white_space, indent,
		format_vlib_next_node_name, vm, node->index, t->next_index);

  s = format (s,
	      "%Uesp: sa-index %d spi %u (0x%08x) seq %u sa-seq-hi %u "
	      "crypto %U integrity %U%s",
	      format_white_space, indent, t->sa_index, t->spi, t->spi, t->seq,
	      t->sa_seq_hi, format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");

  if (vm->trace_main.verbose)
    {
      s = format (s, "\n%U%U", format_white_space, indent + 4, format_hexdump,
		  &t->data, 128);
    }
  return s;
}

static_always_inline void
oct_esp_encrypt_tun_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame, vlib_buffer_t *b,
			       u32 next_index)
{
  oct_esp_encrypt_trace_t *tr;
  ipsec_sa_t *sa;
  u32 sa_index;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  sa_index = vnet_buffer (b)->ipsec.sad_index;
  sa = ipsec_sa_get (sa_index);
  tr->next_index = next_index;
  tr->sa_index = sa_index;
  tr->spi = sa->spi;
  tr->seq = sa->seq;
  tr->sa_seq_hi = sa->seq_hi;
  tr->udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa);
  tr->crypto_alg = sa->crypto_alg;
  tr->integ_alg = sa->integ_alg;
  tr->owner_thread = sa->thread_index;

  clib_memcpy_fast (&tr->buf, b, sizeof b[0] - sizeof b->pre_data);
  clib_memcpy_fast (tr->buf.pre_data, b->data, sizeof tr->buf.pre_data);
  clib_memcpy_fast (tr->data, vlib_buffer_get_current (b), 256);
}

static_always_inline u32
oct_ipsec_sa_index_get (vlib_buffer_t *b, const int is_tun)
{
  u32 sa_index, adj_index;

  if (is_tun)
    {
      adj_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
      sa_index = ipsec_tun_protect_get_sa_out (adj_index);
      vnet_buffer (b)->ipsec.sad_index = sa_index;
    }
  else
    sa_index = vnet_buffer (b)->ipsec.sad_index;

  return sa_index;
}

static_always_inline uword
oct_esp_encrypt_tun (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, const int is_ip6)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 sa0_index, sa1_index, sa2_index, sa3_index;
  u32 current_sa0_index = ~0, current_sa1_index = ~0;
  u32 current_sa2_index = ~0, current_sa3_index = ~0;
  ipsec_sa_t *sa0 = NULL, *sa1 = NULL, *sa2 = NULL, *sa3 = NULL;
  u16 thread0_next = OCT_ESP_ENCRYPT_TUN_NEXT_PREP0;

  vlib_get_buffers (vm, from, b, frame->n_vectors);

  while (n_left > 11)
    {
      vlib_prefetch_buffer_header (b[8], LOAD);
      vlib_prefetch_buffer_header (b[9], LOAD);
      vlib_prefetch_buffer_header (b[10], LOAD);
      vlib_prefetch_buffer_header (b[11], LOAD);

      sa0_index = oct_ipsec_sa_index_get (b[0], 1);
      sa1_index = oct_ipsec_sa_index_get (b[1], 1);
      sa2_index = oct_ipsec_sa_index_get (b[2], 1);
      sa3_index = oct_ipsec_sa_index_get (b[3], 1);

      if (sa0_index != current_sa0_index)
	{
	  sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}
      if (sa1_index != current_sa1_index)
	{
	  sa1 = ipsec_sa_get (sa1_index);
	  current_sa1_index = sa1_index;
	}
      if (sa2_index != current_sa2_index)
	{
	  sa2 = ipsec_sa_get (sa2_index);
	  current_sa2_index = sa2_index;
	}
      if (sa3_index != current_sa3_index)
	{
	  sa3 = ipsec_sa_get (sa3_index);
	  current_sa3_index = sa3_index;
	}

      /*
       * If this is the first packet to use this SA, assign thread based
       * on SA index. Don't need to do core-handoff on OCTEON as send queue
       * is used based on thread index.
       */
      if (PREDICT_FALSE (sa0->thread_index == 0xFFFF))
	sa0->thread_index = (sa0_index % vlib_num_workers ()) + 1;
      if (PREDICT_FALSE (sa1->thread_index == 0xFFFF))
	sa1->thread_index = (sa1_index % vlib_num_workers ()) + 1;
      if (PREDICT_FALSE (sa2->thread_index == 0xFFFF))
	sa2->thread_index = (sa2_index % vlib_num_workers ()) + 1;
      if (PREDICT_FALSE (sa3->thread_index == 0xFFFF))
	sa3->thread_index = (sa3_index % vlib_num_workers ()) + 1;

      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      vnet_buffer (b[1])->ipsec.thread_index = sa1->thread_index;
      vnet_buffer (b[2])->ipsec.thread_index = sa2->thread_index;
      vnet_buffer (b[3])->ipsec.thread_index = sa3->thread_index;

      next[0] = thread0_next + sa0->thread_index;
      next[1] = thread0_next + sa1->thread_index;
      next[2] = thread0_next + sa2->thread_index;
      next[3] = thread0_next + sa3->thread_index;

      next += 4;
      b += 4;
      n_left -= 4;
    }

  current_sa0_index = ~0;
  while (n_left > 0)
    {
      sa0_index = oct_ipsec_sa_index_get (b[0], 1);

      if (sa0_index != current_sa0_index)
	{
	  sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}

      if (PREDICT_FALSE (0XFFFF == sa0->thread_index))
	{
	  /*
	   * If this is the first packet to use this SA, claim the SA
	   * for this thread. Use atomic operation as this could happen
	   * simultaneously on another thread
	   */
	  clib_atomic_cmp_and_swap (&sa0->thread_index, ~0,
				    ipsec_sa_assign_thread (vm->thread_index));
	}

      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      next[0] = thread0_next + sa0->thread_index;

      next++;
      b++;
      n_left--;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = frame->n_vectors;
      next = nexts;
      b = bufs;
      while (n_left > 0)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      oct_esp_encrypt_tun_add_trace (vm, node, frame, b[0], next[0]);
	    }

	  b += 1;
	  n_left--;
	  next++;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/**
 * @brief OCTEON ESP4 encryption tunnel node.
 * @node oct-esp4-encrypt-tun
 *
 * This is the OCTEON ESP4 encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (oct_esp4_encrypt_tun_node) (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame)
{
  return oct_esp_encrypt_tun (
    vm, node, frame, 0);
}

VLIB_REGISTER_NODE (oct_esp4_encrypt_tun_node) = {
  .name = "oct-esp4-encrypt-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_oct_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = OCT_ESP_ENCRYPT_TUN_N_NEXT,
  .next_nodes = {
#define _(next, node) [OCT_ESP_ENCRYPT_TUN_NEXT_##next] = node,
    foreach_oct_esp_encrypt_tun_next
#undef _
#define _(core)                                                               \
   OCT_ESP_ENCRYPT_TUN_PREP_NODES (oct-esp4-encrypt-tun-prep, core)
    foreach_oct_esp_handoff_core
#undef _
  },

};
/* clang-format on */

/**
 * @brief OCT ESP6 encryption tunnel node.
 * @node oct-esp6-encrypt-tun
 *
 * This is the ONP ESP6 encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (oct_esp6_encrypt_tun_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return oct_esp_encrypt_tun (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (oct_esp6_encrypt_tun_node) = {
  .name = "oct-esp6-encrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "oct-esp4-encrypt-tun",
};
/* clang-format on */

static_always_inline i32
oct_ipsec_rlen_get (oct_ipsec_encap_len_t *encap, uint32_t plen)
{
  uint32_t enc_payload_len;

  enc_payload_len =
    round_pow2 (plen + encap->roundup_len, encap->roundup_byte);

  return encap->partial_len + enc_payload_len;
}

static_always_inline u32
oct_ipsec_esp_add_footer_and_icv (oct_ipsec_encap_len_t *encap, u32 rlen)
{
  /* plain_text len + pad_bytes + ESP_footer size + icv_len */
  return rlen + encap->icv_len - encap->partial_len;
}

static_always_inline uword
oct_esp_prep_to_core (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u16 core_id, const int is_ipv6)
{
  oct_device_t *od;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 sa_index, current_sa_index = ~0, rlen, pkt_len;
  oct_ipsec_main_t *im = &oct_ipsec_main;
  oct_ipsec_outbound_pkt_meta_t *meta;
  oct_ipsec_session_t *sess = NULL;
  u16 sa_bytes;
  u64 dptr;

  vlib_get_buffers (vm, from, b, frame->n_vectors);

  while (n_left > 0)
    {
      sa_index = vnet_buffer (b[0])->ipsec.sad_index;
      if (sa_index != current_sa_index)
	{
	  sess = pool_elt_at_index (im->inline_ipsec_sessions, sa_index);
	  if (!sess->inst.w7.s.cptr)
	    {
	      od = oct_ipsec_get_oct_device_from_outb_sa (sa_index);
	      sess->inst.w7.s.cptr = (u64) sess->out_sa[od->nix_idx];
	    }
	  current_sa_index = sa_index;
	  ALWAYS_ASSERT (current_sa_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      vnet_buffer (b[0])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;
      vnet_buffer (b[0])->ipsec.sad_index = current_sa_index;

      /*
       * External header buffer is used to store
       * the cn10k_ipsec_outbound_pkt_meta_t
       */

      meta =
	(oct_ipsec_outbound_pkt_meta_t *) OCT_EXT_HDR_FROM_VLIB_BUFFER (b[0]);

      clib_memset (meta, 0, sizeof (oct_ipsec_outbound_pkt_meta_t));

      meta->res.cn10k.compcode = CPT_COMP_NOT_DONE;

      pkt_len = b[0]->current_length;
      rlen = oct_ipsec_rlen_get (&sess->encap, pkt_len);
      meta->core_id = core_id;

      if (is_ipv6)
	meta->is_ip6 = 1;

      /* Populate CPT instruction template */
      meta->inst.res_addr = (u64) &meta->res;
      meta->inst.w2.u64 = sess->inst.w2.u64;
      /* WQE must be aligned on an 64-bit / 8 byte boundary */
      ASSERT (((uintptr_t) b[0] & 0x7ULL) == 0);
      meta->inst.w3.u64 = (uintptr_t) b[0];
      /* Enable queue ordering */
      meta->inst.w3.u64 |= 0x1ULL;

      if ((b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) ||
	  (rlen > buffer_data_size))
	{
	  u16 total_length;
	  total_length = b[0]->current_length +
			 b[0]->total_length_not_including_first_buffer;
	  rlen = oct_ipsec_rlen_get (&sess->encap, total_length);
	  sa_bytes = oct_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
	  meta->sa_bytes = sa_bytes;

	  meta->dlen_adj = rlen - total_length;
	  meta->is_sg_mode = 1;
	  meta->inst.w4.u64 = sess->inst.w4.u64;
	}
      else
	{
	  dptr = (u64) vlib_buffer_get_current (b[0]);
	  sa_bytes = oct_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
	  meta->sa_bytes = sa_bytes;
	  meta->dlen_adj = rlen - pkt_len;

	  /* Set w0 nixtx_offset */
	  meta->inst.w0.u64 |=
	    (((int64_t) meta->nixtx - (int64_t) dptr) & 0xFFFFF) << 32;

	  /*
	   * Set nixtx length to 2 dwords.
	   * NIXTXL + 1 represents the length in dwords
	   */
	  meta->inst.w0.u64 |= 1;
	  meta->inst.w4.u64 = sess->inst.w4.u64 | pkt_len;
	  meta->inst.dptr = dptr;
	  meta->inst.rptr = dptr;
	}

      meta->inst.w7.u64 = sess->inst.w7.u64;

      b++;
      n_left--;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = frame->n_vectors;
      b = bufs;

      while (n_left)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      oct_esp_encrypt_tun_add_trace (
		vm, node, frame, b[0],
		OCT_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX);
	    }
	  n_left--;
	  b++;
	}
    }

  vlib_buffer_enqueue_to_single_next (vm, node, from,
				      OCT_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX,
				      frame->n_vectors);

  return frame->n_vectors;
}

/**
 * @brief OCTEON ESP4 encryption tunnel preparation node.
 * @node oct-esp4-encrypt-tun-prep
 *
 * This is the OCTEON ESP4 encryption tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define OCT_DEFINE_ESP4_TUN_PREP_NODE(core)                            \
  VLIB_NODE_FN (oct_esp4_encrypt_tun_prep##core##_node)                   \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return oct_esp_prep_to_core (vm, node, frame, core,                   \
                              0 /* is_ipv6 */);   \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (oct_esp4_encrypt_tun_prep##core##_node) = {         \
    .name = "oct-esp4-encrypt-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_oct_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "oct-esp4-encrypt-tun",                                 \
  };

#define _(core) OCT_DEFINE_ESP4_TUN_PREP_NODE (core)
foreach_oct_esp_handoff_core;
#undef _
/* clang-format on */

/**
 * @brief OCTEON ESP6 encryption tunnel preparation node.
 * @node oct-esp6-encrypt-tun-prep
 *
 * This is the OCTEON ESP6 encryption tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define OCT_DEFINE_ESP6_TUN_PREP_NODE(core)                            \
  VLIB_NODE_FN (oct_esp6_encrypt_tun_prep##core##_node)                   \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return oct_esp_prep_to_core (vm, node, frame, core,                   \
                              1 /* is_ipv6 */);   \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (oct_esp6_encrypt_tun_prep##core##_node) = {         \
    .name = "oct-esp6-encrypt-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_oct_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "oct-esp6-encrypt-tun",                                 \
  };

#define _(core) OCT_DEFINE_ESP6_TUN_PREP_NODE (core)
foreach_oct_esp_handoff_core;
#undef _
/* clang-format on */
