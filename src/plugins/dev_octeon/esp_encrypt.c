#include <dev_octeon/octeon.h>
#include <dev_octeon/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/dpo/dpo.h>

extern oct_ipsec_main_t oct_ipsec_main;

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

/* Policy-mode next nodes */
#define foreach_oct_esp_encrypt_next                                          \
  _ (DROP4, "ip4-drop")                                                       \
  _ (DROP6, "ip6-drop")                                                       \
  _ (DROP_MPLS, "mpls-drop")                                                  \
  _ (SW_ESP4, "esp4-encrypt")                                                 \
  _ (SW_ESP6, "esp6-encrypt")                                                 \
  _ (HANDOFF_MPLS, "error-drop")                                              \
  _ (INTERFACE_OUTPUT, "interface-output")

/* clang-format off */
typedef enum
{
#define _(v, s) OCT_ESP_ENCRYPT_NEXT_##v,
  foreach_oct_esp_encrypt_next
#undef _
  OCT_ESP_ENCRYPT_N_NEXT,
} oct_esp_encrypt_next_t;
/* clang-format on */

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
  OCT_ESP_ENCRYPT_TUN_N_NEXT
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

/* Set next node for a policy mode tunnel packet */
static_always_inline void
oct_policy_tun_inline_mark (vlib_buffer_t *b, ipsec_sa_t *sa, u16 *next)
{
  dpo_id_t *dpo = &sa->dpo;
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = dpo->dpoi_index;
  *next = dpo->dpoi_next_node;
}

static_always_inline void
oct_esp_encrypt_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
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
oct_ipsec_sa_index_get (vlib_buffer_t *b, const int is_route)
{
  u32 sa_index, adj_index;

  if (is_route)
    {
      adj_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
      sa_index = ipsec_tun_protect_get_sa_out (adj_index);
      vnet_buffer (b)->ipsec.sad_index = sa_index;
    }
  else
    sa_index = vnet_buffer (b)->ipsec.sad_index;

  return sa_index;
}

/*
 * Route-based SAs and policy based transport SAs go through the
 * hardware offload path.
 *
 * Policy based tunnel SAs are sent for software ESP currently.
 */
static_always_inline uword
oct_esp_encrypt_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, const int is_ip6,
			const int is_route)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 workers = vlib_num_workers ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE];
  u16 *next = nexts;
  u32 sa0_index = 0, sa1_index = 0, sa2_index = 0, sa3_index = 0;
  u32 current_sa0_index = ~0, current_sa1_index = ~0;
  u32 current_sa2_index = ~0, current_sa3_index = ~0;
  ipsec_sa_t *sa0 = NULL, *sa1 = NULL, *sa2 = NULL, *sa3 = NULL;

  u16 hw_offload_next = is_route ? OCT_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX :
				   OCT_ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;

  vlib_get_buffers (vm, from, b, frame->n_vectors);

  while (n_left > 11)
    {
      vlib_prefetch_buffer_header (b[8], LOAD);
      vlib_prefetch_buffer_header (b[9], LOAD);
      vlib_prefetch_buffer_header (b[10], LOAD);
      vlib_prefetch_buffer_header (b[11], LOAD);

      sa0_index = oct_ipsec_sa_index_get (b[0], is_route);
      sa1_index = oct_ipsec_sa_index_get (b[1], is_route);
      sa2_index = oct_ipsec_sa_index_get (b[2], is_route);
      sa3_index = oct_ipsec_sa_index_get (b[3], is_route);

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
	sa0->thread_index = (sa0_index % workers) + 1;
      if (PREDICT_FALSE (sa1->thread_index == 0xFFFF))
	sa1->thread_index = (sa1_index % workers) + 1;
      if (PREDICT_FALSE (sa2->thread_index == 0xFFFF))
	sa2->thread_index = (sa2_index % workers) + 1;
      if (PREDICT_FALSE (sa3->thread_index == 0xFFFF))
	sa3->thread_index = (sa3_index % workers) + 1;

      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      vnet_buffer (b[1])->ipsec.thread_index = sa1->thread_index;
      vnet_buffer (b[2])->ipsec.thread_index = sa2->thread_index;
      vnet_buffer (b[3])->ipsec.thread_index = sa3->thread_index;

      vnet_buffer (b[0])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;
      vnet_buffer (b[1])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;
      vnet_buffer (b[2])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;
      vnet_buffer (b[3])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;

      if (is_route)
	{
	  /* Route mode */
	  next[0] = hw_offload_next;
	  next[1] = hw_offload_next;
	  next[2] = hw_offload_next;
	  next[3] = hw_offload_next;
	}
      else
	{
	  /* Policy mode */
	  if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	    {
	      oct_policy_tun_inline_mark (b[0], sa0, &next[0]);
	    }
	  else
	    {
	      next[0] = hw_offload_next;
	      vlib_buffer_advance (b[0], -vnet_buffer (b[0])->l3_hdr_offset);
	    }

	  if (ipsec_sa_is_set_IS_TUNNEL (sa1))
	    {
	      oct_policy_tun_inline_mark (b[1], sa1, &next[1]);
	    }
	  else
	    {
	      next[1] = hw_offload_next;
	      vlib_buffer_advance (b[1], -vnet_buffer (b[1])->l3_hdr_offset);
	    }

	  if (ipsec_sa_is_set_IS_TUNNEL (sa2))
	    {
	      oct_policy_tun_inline_mark (b[2], sa2, &next[2]);
	    }
	  else
	    {
	      next[2] = hw_offload_next;
	      vlib_buffer_advance (b[2], -vnet_buffer (b[2])->l3_hdr_offset);
	    }

	  if (ipsec_sa_is_set_IS_TUNNEL (sa3))
	    {
	      oct_policy_tun_inline_mark (b[3], sa3, &next[3]);
	    }
	  else
	    {
	      next[3] = hw_offload_next;
	      vlib_buffer_advance (b[3], -vnet_buffer (b[3])->l3_hdr_offset);
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  current_sa0_index = ~0;
  sa0 = NULL;

  while (n_left > 0)
    {
      sa0_index = oct_ipsec_sa_index_get (b[0], is_route);
      if (sa0_index != current_sa0_index)
	{
	  sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}

      if (PREDICT_FALSE (sa0->thread_index == 0xFFFF))
	sa0->thread_index = (sa0_index % workers) + 1;
      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      vnet_buffer (b[0])->oflags |= VNET_BUFFER_OFFLOAD_F_IPSEC_OFFLOAD;

      if (is_route)
	{
	  /* Route mode */
	  *next = hw_offload_next;
	}
      else
	{
	  /* Policy mode */
	  if (ipsec_sa_is_set_IS_TUNNEL (sa0))
	    {
	      oct_policy_tun_inline_mark (b[0], sa0, next);
	    }
	  else
	    {
	      *next = hw_offload_next;
	      vlib_buffer_advance (b[0], -vnet_buffer (b[0])->l3_hdr_offset);
	    }
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = frame->n_vectors;
      b = bufs;
      next = nexts;
      while (n_left > 0)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    oct_esp_encrypt_add_trace (vm, node, frame, b[0], *next);
	  b += 1;
	  next += 1;
	  n_left--;
	}
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/**
 * @brief OCTEON ESP4 encryption policy node.
 * @node oct-esp4-encrypt
 *
 * This is the OCTEON ESP4 policy-based encryption node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (oct_esp4_encrypt_node) (vlib_main_t *vm,
                                      vlib_node_runtime_t *node,
                                      vlib_frame_t *frame)
{
  return oct_esp_encrypt_inline (vm, node, frame, 0, 0);
}

VLIB_REGISTER_NODE (oct_esp4_encrypt_node) = {
  .name = "oct-esp4-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_oct_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = OCT_ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(next, node) [OCT_ESP_ENCRYPT_NEXT_##next] = node,
    foreach_oct_esp_encrypt_next
#undef _
  },
};
/* clang-format on */

/**
 * @brief OCTEON ESP6 encryption policy node.
 * @node oct-esp6-encrypt
 *
 * This is the OCTEON ESP4 policy-based encryption node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (oct_esp6_encrypt_node) (vlib_main_t *vm,
                                      vlib_node_runtime_t *node,
                                      vlib_frame_t *frame)
{
  return oct_esp_encrypt_inline (vm, node, frame, 1, 0);
}

VLIB_REGISTER_NODE (oct_esp6_encrypt_node) = {
  .name = "oct-esp6-encrypt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "oct-esp4-encrypt",
};
/* clang-format on */

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
  return oct_esp_encrypt_inline (vm, node, frame, 0, 1);
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
  },

};

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
  return oct_esp_encrypt_inline (vm, node, frame, 1, 1);
}

VLIB_REGISTER_NODE (oct_esp6_encrypt_tun_node) = {
  .name = "oct-esp6-encrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "oct-esp4-encrypt-tun",
};
/* clang-format on */
