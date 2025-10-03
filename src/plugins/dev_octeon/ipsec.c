/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <dev_octeon/octeon.h>
#include <dev_octeon/crypto.h>
#include <dev_octeon/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/fib/fib_entry.h>

#define OCT_NIX_INL_META_POOL_NAME "OCT_NIX_INL_META_POOL"

oct_ipsec_main_t oct_ipsec_main;
oct_inl_dev_main_t oct_inl_dev_main;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "ipsec",
};

static inline union cpt_eng_caps
oct_cpt_get_eng_caps (oct_crypto_main_t *ocm)
{
  oct_crypto_dev_t *ocd = ocm->crypto_dev[0];

  if (roc_model_is_cn20k ())
    return ocd->roc_cpt->hw_caps[CPT_ENG_TYPE_SE];
  else
    return ocd->roc_cpt->hw_caps[CPT_ENG_TYPE_IE];
}

static inline u32
oct_ipsec_get_inb_sa_sz ()
{
  if (roc_model_is_cn20k ())
    return (sizeof (struct roc_ow_ipsec_inb_sa));
  return (sizeof (struct roc_ot_ipsec_inb_sa));
}

static inline u32
oct_ipsec_get_outb_sa_sz ()
{
  if (roc_model_is_cn20k ())
    return (sizeof (struct roc_ow_ipsec_outb_sa));
  return (sizeof (struct roc_ot_ipsec_outb_sa));
}

static inline void
oct_ipsec_sa_init (void *sa_dptr, bool is_inb)
{
  if (roc_model_is_cn20k ())
    {
      if (is_inb)
	roc_ow_ipsec_inb_sa_init (sa_dptr);
      else
	roc_ow_ipsec_outb_sa_init (sa_dptr);
      return;
    }

  if (is_inb)
    roc_ot_ipsec_inb_sa_init (sa_dptr);
  else
    roc_ot_ipsec_outb_sa_init (sa_dptr);

  return;
}

static void
oct_ipsec_hmac_opad_ipad_gen (ipsec_sa_t *sa, u8 *hmac_opad_ipad)
{
  u8 opad[128] = { [0 ... 127] = 0x5c };
  u8 ipad[128] = { [0 ... 127] = 0x36 };
  const u8 *key = sa->integ_key.data;
  u32 length = sa->integ_key.len;
  u32 i;

  /* HMAC OPAD and IPAD */
  for (i = 0; i < 128 && i < length; i++)
    {
      opad[i] = opad[i] ^ key[i];
      ipad[i] = ipad[i] ^ key[i];
    }

  /*
   * Precompute hash of HMAC OPAD and IPAD to avoid
   * per-packet computation
   */
  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_SHA1_96:
      roc_hash_sha1_gen (opad, (u32 *) &hmac_opad_ipad[0]);
      roc_hash_sha1_gen (ipad, (u32 *) &hmac_opad_ipad[24]);
      break;
    case IPSEC_INTEG_ALG_SHA_256_96:
    case IPSEC_INTEG_ALG_SHA_256_128:
      roc_hash_sha256_gen (opad, (u32 *) &hmac_opad_ipad[0], 256);
      roc_hash_sha256_gen (ipad, (u32 *) &hmac_opad_ipad[64], 256);
      break;
    case IPSEC_INTEG_ALG_SHA_384_192:
      roc_hash_sha512_gen (opad, (u64 *) &hmac_opad_ipad[0], 384);
      roc_hash_sha512_gen (ipad, (u64 *) &hmac_opad_ipad[64], 384);
      break;
    case IPSEC_INTEG_ALG_SHA_512_256:
      roc_hash_sha512_gen (opad, (u64 *) &hmac_opad_ipad[0], 512);
      roc_hash_sha512_gen (ipad, (u64 *) &hmac_opad_ipad[64], 512);
      break;
    default:
      break;
    }
}

static_always_inline u64
oct_ipsec_crypto_inst_w7_get (void *sa)
{
  union cpt_inst_w7 w7;

  w7.u64 = 0;
  w7.s.ctx_val = 1;

  if (roc_model_is_cn20k ())
    w7.s.egrp = ROC_CPT_DFLT_ENG_GRP_SE;
  else
    w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE;

  return w7.u64;
}

static_always_inline i32
oct_ipsec_sa_common_param_fill (union roc_ot_ipsec_sa_word2 *w2,
				u8 *cipher_key, u8 *salt_key,
				u8 *hmac_opad_ipad, ipsec_sa_t *sa)
{
  u32 *tmp_salt;
  u64 *tmp_key;
  int i;

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    w2->s.encap_type = ROC_IE_OT_SA_ENCAP_UDP;

  /* Set protocol - ESP vs AH */
  if (sa->protocol == IPSEC_PROTOCOL_ESP)
    w2->s.protocol = ROC_IE_SA_PROTOCOL_ESP;
  else
    w2->s.protocol = ROC_IE_SA_PROTOCOL_AH;

  /* Set mode - transport vs tunnel */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    w2->s.mode = ROC_IE_SA_MODE_TUNNEL;
  else
    w2->s.mode = ROC_IE_SA_MODE_TRANSPORT;

  if (ipsec_sa_is_set_IS_CTR (sa))
    {
      if (ipsec_sa_is_set_IS_AEAD (sa))
	{
	  /* AEAD is set for AES_GCM */
	  if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	    {
	      w2->s.enc_type = ROC_IE_SA_ENC_AES_GCM;
	      w2->s.auth_type = ROC_IE_SA_AUTH_NULL;
	    }
	  else
	    {
	      clib_warning ("Unsupported AEAD algorithm");
	      return -1;
	    }
	}
      else
	w2->s.enc_type = ROC_IE_SA_ENC_AES_CTR;
    }
  else
    {
      switch (sa->crypto_alg)
	{
	case IPSEC_CRYPTO_ALG_NONE:
	  w2->s.enc_type = ROC_IE_SA_ENC_NULL;
	  break;
	case IPSEC_CRYPTO_ALG_AES_CBC_128:
	case IPSEC_CRYPTO_ALG_AES_CBC_192:
	case IPSEC_CRYPTO_ALG_AES_CBC_256:
	  w2->s.enc_type = ROC_IE_SA_ENC_AES_CBC;
	  break;
	case IPSEC_CRYPTO_ALG_3DES_CBC:
	  w2->s.enc_type = ROC_IE_SA_ENC_3DES_CBC;
	  break;
	default:
	  clib_warning ("Unsupported encryption algorithm");
	  return -1;
	}
    }

  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_128;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_192;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_256:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_256;
      break;
    default:
      break;
    }

  if (!ipsec_sa_is_set_IS_AEAD (sa))
    {
      switch (sa->integ_alg)
	{
	case IPSEC_INTEG_ALG_NONE:
	  w2->s.auth_type = ROC_IE_SA_AUTH_NULL;
	  break;
	case IPSEC_INTEG_ALG_SHA1_96:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA1;
	  break;
	case IPSEC_INTEG_ALG_SHA_256_96:
	case IPSEC_INTEG_ALG_SHA_256_128:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_256;
	  break;
	case IPSEC_INTEG_ALG_SHA_384_192:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_384;
	  break;
	case IPSEC_INTEG_ALG_SHA_512_256:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_512;
	  break;
	default:
	  clib_warning ("Unsupported authentication algorithm");
	  return -1;
	}
    }

  oct_ipsec_hmac_opad_ipad_gen (sa, hmac_opad_ipad);

  tmp_key = (u64 *) hmac_opad_ipad;
  for (i = 0; i < (int) (ROC_CTX_MAX_OPAD_IPAD_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  if (ipsec_sa_is_set_IS_AEAD (sa))
    {
      if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	clib_memcpy (salt_key, &sa->salt, OCT_ROC_SALT_LEN);
      tmp_salt = (u32 *) salt_key;
      *tmp_salt = clib_net_to_host_u32 (*tmp_salt);
    }

  /* Populate encryption key */
  clib_memcpy (cipher_key, sa->crypto_key.data, sa->crypto_key.len);
  tmp_key = (u64 *) cipher_key;
  for (i = 0; i < (int) (ROC_CTX_MAX_CKEY_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  w2->s.spi = sa->spi;

  return 0;
}

static_always_inline i32
oct_o20_ipsec_sa_common_param_fill (union roc_ow_ipsec_sa_word2 *w2,
				    u8 *cipher_key, u8 *salt_key,
				    u8 *hmac_opad_ipad, ipsec_sa_t *sa)
{
  u32 *tmp_salt;
  u64 *tmp_key;
  int i;

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    w2->s.encap_type = ROC_IE_OW_SA_ENCAP_UDP;

  /* Set protocol - ESP vs AH */
  if (sa->protocol == IPSEC_PROTOCOL_ESP)
    w2->s.protocol = ROC_IE_SA_PROTOCOL_ESP;
  else
    w2->s.protocol = ROC_IE_SA_PROTOCOL_AH;

  /* Set mode - transport vs tunnel */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    w2->s.mode = ROC_IE_SA_MODE_TUNNEL;
  else
    w2->s.mode = ROC_IE_SA_MODE_TRANSPORT;

  if (ipsec_sa_is_set_IS_CTR (sa))
    {
      if (ipsec_sa_is_set_IS_AEAD (sa))
	{
	  /* AEAD is set for AES_GCM */
	  if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	    {
	      w2->s.enc_type = ROC_IE_SA_ENC_AES_GCM;
	      w2->s.auth_type = ROC_IE_SA_AUTH_NULL;
	    }
	  else
	    {
	      clib_warning ("Unsupported AEAD algorithm");
	      return -1;
	    }
	}
      else
	w2->s.enc_type = ROC_IE_SA_ENC_AES_CTR;
    }
  else
    {
      switch (sa->crypto_alg)
	{
	case IPSEC_CRYPTO_ALG_NONE:
	  w2->s.enc_type = ROC_IE_SA_ENC_NULL;
	  break;
	case IPSEC_CRYPTO_ALG_AES_CBC_128:
	case IPSEC_CRYPTO_ALG_AES_CBC_192:
	case IPSEC_CRYPTO_ALG_AES_CBC_256:
	  w2->s.enc_type = ROC_IE_SA_ENC_AES_CBC;
	  break;
	default:
	  clib_warning ("Unsupported encryption algorithm");
	  return -1;
	}
    }

  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_128;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_192;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_256:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_256;
      break;
    default:
      break;
    }

  if (!ipsec_sa_is_set_IS_AEAD (sa))
    {
      switch (sa->integ_alg)
	{
	case IPSEC_INTEG_ALG_NONE:
	  w2->s.auth_type = ROC_IE_SA_AUTH_NULL;
	  break;
	case IPSEC_INTEG_ALG_SHA1_96:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA1;
	  break;
	case IPSEC_INTEG_ALG_SHA_256_96:
	case IPSEC_INTEG_ALG_SHA_256_128:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_256;
	  break;
	case IPSEC_INTEG_ALG_SHA_384_192:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_384;
	  break;
	case IPSEC_INTEG_ALG_SHA_512_256:
	  w2->s.auth_type = ROC_IE_SA_AUTH_SHA2_512;
	  break;
	default:
	  clib_warning ("Unsupported authentication algorithm");
	  return -1;
	}
    }

  oct_ipsec_hmac_opad_ipad_gen (sa, hmac_opad_ipad);

  tmp_key = (u64 *) hmac_opad_ipad;
  for (i = 0; i < (int) (ROC_CTX_MAX_OPAD_IPAD_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  if (ipsec_sa_is_set_IS_AEAD (sa))
    {
      if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	clib_memcpy (salt_key, &sa->salt, OCT_ROC_SALT_LEN);
      tmp_salt = (u32 *) salt_key;
      *tmp_salt = clib_net_to_host_u32 (*tmp_salt);
    }

  /* Populate encryption key */
  clib_memcpy (cipher_key, sa->crypto_key.data, sa->crypto_key.len);
  tmp_key = (u64 *) cipher_key;
  for (i = 0; i < (int) (ROC_CTX_MAX_CKEY_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  w2->s.spi = sa->spi;

  return 0;
}

static_always_inline void
oct_ipsec_sa_len_precalc (ipsec_sa_t *sa, oct_ipsec_encap_len_t *encap)
{
  encap->adj_len = 0;

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	encap->partial_len = ROC_CPT_TUNNEL_IPV6_HDR_LEN;
      else
	encap->partial_len = ROC_CPT_TUNNEL_IPV4_HDR_LEN;
    }
  else
    {
      encap->partial_len = 0;
      encap->adj_len = ROC_CPT_TUNNEL_IPV4_HDR_LEN;
    }

  if (sa->protocol == IPSEC_PROTOCOL_ESP)
    {
      encap->partial_len += ROC_CPT_ESP_HDR_LEN;
      encap->roundup_len = ROC_CPT_ESP_TRL_LEN;
      encap->footer_len = ROC_CPT_ESP_TRL_LEN;
    }
  else
    {
      encap->partial_len = ROC_CPT_AH_HDR_LEN;
    }

  encap->partial_len += sa->crypto_iv_size;
  encap->partial_len += sa->integ_icv_size;

  encap->roundup_byte = sa->esp_block_align;
  encap->icv_len = sa->integ_icv_size;

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    encap->partial_len += sizeof (udp_header_t);
}

static size_t
oct_ipsec_inb_ctx_size (struct roc_ot_ipsec_inb_sa *sa)
{
  size_t size;

  /* Variable based on anti-replay window */
  size = offsetof (struct roc_ot_ipsec_inb_sa, ctx) +
	 offsetof (struct roc_ot_ipsec_inb_ctx_update_reg, ar_winbits);

  if (sa->w0.s.ar_win)
    size += (1 << (sa->w0.s.ar_win - 1)) * sizeof (u64);

  return size;
}

static size_t
oct_o20_ipsec_inb_ctx_size (struct roc_ow_ipsec_inb_sa *sa)
{
  size_t size;

  /* Variable based on anti-replay window */
  size = offsetof (struct roc_ow_ipsec_inb_sa, ctx) +
	 offsetof (struct roc_ow_ipsec_inb_ctx_update_reg, ar_winbits);

  if (sa->w0.s.ar_win)
    size += (1 << (sa->w0.s.ar_win - 1)) * sizeof (u64);

  return size;
}

static_always_inline void
oct_ipsec_common_inst_param_fill (void *sa, oct_ipsec_session_t *sess)
{
  union cpt_inst_w2 w2;
  union cpt_inst_w3 w3;

  clib_memset (&sess->inst, 0, sizeof (struct cpt_inst_s));

  sess->inst.w7.u64 = oct_ipsec_crypto_inst_w7_get (sa);

  w2.u64 = 0;
  w2.u64 = ((u64) OCT_EVENT_TYPE_FRM_CPU << 28);
  sess->inst.w2.u64 = w2.u64;

  /* Populate word3 in CPT instruction template */
  w3.u64 = 0;
  w3.s.qord = 1;
  sess->inst.w3.u64 = w3.u64;
}

static i32
oct_o10_ipsec_inb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  union roc_ot_ipsec_sa_word2 w2;
  u32 min_spi, max_spi, spi_mask;
  struct roc_ot_ipsec_inb_sa *roc_sa;
  oct_ipsec_inb_sa_priv_data_t *inb_sa_priv;
  union cpt_inst_w4 inst_w4;
  union roc_ot_ipsec_inb_param1 param1;
  size_t offset;

  /* Ensure SPI is within the range supported by inline pktio device */
  spi_mask = roc_nix_inl_inb_spi_range (NULL, true, &min_spi, &max_spi);
  if (sa->spi < min_spi || sa->spi > max_spi)
    {
      clib_warning ("SPI %u is not within supported range %u-%u", sa->spi,
		    min_spi, max_spi);
      return -1;
    }

  roc_sa = (struct roc_ot_ipsec_inb_sa *) roc_nix_inl_inb_sa_get (NULL, true,
								  sa->spi);
  if (!roc_sa)
    {
      clib_warning ("Failed to create inbound sa session");
      return -1;
    }

  inb_sa_priv = roc_nix_inl_ot_ipsec_inb_sa_sw_rsvd (roc_sa);
  inb_sa_priv->user_data = sa->stat_index;

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      roc_sa->w10.s.udp_dst_port = 4500;
      roc_sa->w10.s.udp_src_port = 4500;
    }

  w2.u64 = 0;
  int rv = oct_ipsec_sa_common_param_fill (
    &w2, roc_sa->cipher_key, roc_sa->w8.s.salt, roc_sa->hmac_opad_ipad, sa);
  if (rv)
    return rv;

  oct_ipsec_sa_len_precalc (sa, &sess->encap);

  if (sa->flags & IPSEC_SA_FLAG_USE_ANTI_REPLAY)
    roc_sa->w0.s.ar_win = max_log2 (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE (sa)) - 5;

  /* Set direction and enable ESN (if needed) */
  w2.s.dir = ROC_IE_SA_DIR_INBOUND;
  if (ipsec_sa_is_set_USE_ESN (sa))
    w2.s.esn_en = 1;

  /*
   * Default options for pkt_out and pkt_fmt are with
   * second pass meta and defrag.
   */
  roc_sa->w0.s.pkt_format = ROC_IE_OT_SA_PKT_FMT_META;

  if (sa->flags & IPSEC_SA_FLAG_IS_INL_REASSEMBLY)
    roc_sa->w0.s.pkt_output = ROC_IE_OT_SA_PKT_OUTPUT_HW_BASED_DEFRAG;
  else
    roc_sa->w0.s.pkt_output = ROC_IE_OT_SA_PKT_OUTPUT_NO_FRAG;

  roc_sa->w0.s.pkind = ROC_IE_OT_CPT_PKIND;

  offset = offsetof (struct roc_ot_ipsec_inb_sa, ctx);
  roc_sa->w0.s.hw_ctx_off = offset / 8;
  roc_sa->w0.s.ctx_push_size = roc_sa->w0.s.hw_ctx_off + 1;

  /* Set context size, in number of 128B units following the first 128B */
  roc_sa->w0.s.ctx_size =
    (round_pow2 (oct_ipsec_inb_ctx_size (roc_sa), 128) >> 7) - 1;

  /* Save SA index/SPI in cookie for now */
  roc_sa->w1.s.cookie = plt_cpu_to_be_32 (sa->spi & spi_mask);

  /* Enable SA */
  w2.s.valid = 1;
  roc_sa->w2.u64 = w2.u64;

  asm volatile ("dmb oshst" ::: "memory");

  oct_ipsec_common_inst_param_fill (roc_sa, sess);

  /* Populate word4 in CPT instruction template */
  inst_w4.u64 = 0;
  inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC;
  param1.u16 = 0;
  /* Disable IP checksum verification by default */
  param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_DISABLE;
  /* Disable L4 checksum verification by default */
  param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_DISABLE;
  param1.s.esp_trailer_disable = 0;
  inst_w4.s.param1 = param1.u16;
  sess->inst.w4.u64 = inst_w4.u64;

  rv = roc_nix_inl_ctx_write (NULL, roc_sa, roc_sa, true,
			      sizeof (struct roc_ot_ipsec_inb_sa));
  if (rv)
    {
      clib_warning ("roc_nix_inl_ctx_write failed with '%s' error",
		    roc_error_msg_get (rv));
      return rv;
    }

  rv = roc_nix_inl_sa_sync (NULL, roc_sa, true, ROC_NIX_INL_SA_OP_FLUSH);
  if (rv)
    {
      clib_warning (
	"roc_nix_inl_sa_sync flush operation failed with '%s' error",
	roc_error_msg_get (rv));
      return rv;
    }

  return 0;
}

static i32
oct_o20_ipsec_inb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  union roc_ow_ipsec_sa_word2 w2;
  u32 min_spi, max_spi, spi_mask;
  struct roc_ow_ipsec_inb_sa *roc_sa;
  oct_ipsec_inb_sa_priv_data_t *inb_sa_priv;
  union cpt_inst_w4 inst_w4;
  union roc_ow_ipsec_inb_param1 param1;
  size_t offset;

  /* Ensure SPI is within the range supported by inline pktio device */
  spi_mask = roc_nix_inl_inb_spi_range (NULL, true, &min_spi, &max_spi);
  if (sa->spi < min_spi || sa->spi > max_spi)
    {
      clib_warning ("SPI %u is not within supported range %u-%u", sa->spi,
		    min_spi, max_spi);
      return -1;
    }

  roc_sa = (struct roc_ow_ipsec_inb_sa *) roc_nix_inl_inb_sa_get (NULL, true,
								  sa->spi);
  if (!roc_sa)
    {
      clib_warning ("Failed to create inbound sa session");
      return -1;
    }

  inb_sa_priv = roc_nix_inl_ow_ipsec_inb_sa_sw_rsvd (roc_sa);
  inb_sa_priv->user_data = sa->stat_index;

  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    {
      roc_sa->w10.s.udp_dst_port = 4500;
      roc_sa->w10.s.udp_src_port = 4500;
    }

  w2.u64 = 0;
  int rv = oct_o20_ipsec_sa_common_param_fill (
    &w2, roc_sa->cipher_key, roc_sa->w8.s.salt, roc_sa->hmac_opad_ipad, sa);
  if (rv)
    return rv;

  oct_ipsec_sa_len_precalc (sa, &sess->encap);

  if (sa->flags & IPSEC_SA_FLAG_USE_ANTI_REPLAY)
    roc_sa->w0.s.ar_win = max_log2 (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE (sa)) - 5;

  /* Set direction and enable ESN (if needed) */
  w2.s.dir = ROC_IE_SA_DIR_INBOUND;
  if (ipsec_sa_is_set_USE_ESN (sa))
    w2.s.esn_en = 1;

  /*
   * Default options for pkt_out and pkt_fmt are with
   * second pass meta and defrag.
   */
  roc_sa->w0.s.pkt_format = ROC_IE_OW_SA_PKT_FMT_META;

  if (sa->flags & IPSEC_SA_FLAG_IS_INL_REASSEMBLY)
    roc_sa->w0.s.pkt_output = ROC_IE_OW_SA_PKT_OUTPUT_HW_BASED_DEFRAG;
  else
    roc_sa->w0.s.pkt_output = ROC_IE_OW_SA_PKT_OUTPUT_NO_FRAG;

  roc_sa->w0.s.pkind = ROC_IE_OW_CPT_PKIND;

  offset = offsetof (struct roc_ow_ipsec_inb_sa, ctx);
  roc_sa->w0.s.hw_ctx_off = offset / 8;
  roc_sa->w0.s.ctx_push_size = roc_sa->w0.s.hw_ctx_off + 1;

  /* Set context size, in number of 128B units following the first 128B */
  roc_sa->w0.s.ctx_size =
    (round_pow2 (oct_o20_ipsec_inb_ctx_size (roc_sa), 128) >> 7) - 1;

  /* Save SA index/SPI in cookie for now */
  roc_sa->w1.s.cookie = sa->spi & spi_mask;

  /* Enable SA */
  w2.s.valid = 1;
  roc_sa->w2.u64 = w2.u64;

  asm volatile ("dmb oshst" ::: "memory");

  oct_ipsec_common_inst_param_fill (roc_sa, sess);

  /* Populate word4 in CPT instruction template */
  inst_w4.u64 = 0;
  inst_w4.s.opcode_major = ROC_IE_OW_MAJOR_OP_PROCESS_INBOUND_IPSEC;
  param1.u16 = 0;
  /* Disable IP checksum verification by default */
  param1.s.ip_csum_disable = ROC_IE_OW_SA_INNER_PKT_IP_CSUM_DISABLE;
  /* Disable L4 checksum verification by default */
  param1.s.l4_csum_disable = ROC_IE_OW_SA_INNER_PKT_L4_CSUM_DISABLE;
  param1.s.esp_trailer_disable = 0;
  inst_w4.s.param1 = param1.u16;
  sess->inst.w4.u64 = inst_w4.u64;

  rv = roc_nix_inl_ctx_write (NULL, roc_sa, roc_sa, true,
			      sizeof (struct roc_ow_ipsec_inb_sa));
  if (rv)
    {
      clib_warning ("roc_nix_inl_ctx_write failed with '%s' error",
		    roc_error_msg_get (rv));
      return rv;
    }

  rv = roc_nix_inl_sa_sync (NULL, roc_sa, true, ROC_NIX_INL_SA_OP_FLUSH);
  if (rv)
    {
      clib_warning (
	"roc_nix_inl_sa_sync flush operation failed with '%s' error",
	roc_error_msg_get (rv));
      return rv;
    }

  return 0;
}

static i32
oct_ipsec_inb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  if (roc_model_is_cn20k ())
    return oct_o20_ipsec_inb_session_update (sess, sa);
  return oct_o10_ipsec_inb_session_update (sess, sa);
}

int
oct_ipsec_outb_sa_idx_get (oct_device_t *od, u32 *index, u32 spi)
{
  u32 pos, idx;
  u64 slab;
  int rc;

  if (!od->outb.sa_bmap)
    return -ENOTSUP;

  pos = 0;
  slab = 0;
  /* Scan from the beginning */
  plt_bitmap_scan_init (od->outb.sa_bmap);

  /* Scan bitmap to get the free sa index */
  rc = plt_bitmap_scan (od->outb.sa_bmap, &pos, &slab);
  /* Empty bitmap */
  if (rc == 0)
    {
      plt_err ("Outbound SA' exhausted, use 'ipsec_out_max_sa' "
	       "devargs to increase");
      return -ERANGE;
    }

  /* Get free SA index */
  idx = pos + (slab ? plt_ctz64 (slab) : 0);

  plt_bitmap_clear (od->outb.sa_bmap, idx);
  *index = idx;
  return 0;
}

void *
oct_ipsec_get_oct_device_from_outb_sa (u32 sa_index)
{
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  u32 sw_if_index;
  vnet_dev_port_t *port;

  sw_if_index =
    fib_entry_get_resolving_interface (sa->tunnel.t_fib_entry_index);
  si = vnet_get_sw_interface_or_null (vnm, sw_if_index);
  port = vnet_dev_get_port_from_hw_if_index (si->hw_if_index);

  return (oct_device_t *) vnet_dev_get_data (port->dev);
}

static_always_inline i32
oct_o10_ipsec_outb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  oct_main_t *om = &oct_main;
  union roc_ot_ipsec_outb_param1 param1;
  struct roc_ot_ipsec_outb_sa *out_sa;
  oct_ipsec_outb_sa_priv_data_t *outb_priv;
  union roc_ot_ipsec_sa_word2 w2;
  union cpt_inst_w4 inst_w4;
  u32 sa_idx;
  u64 *ipv6_addr;
  size_t offset;
  int rv = 0, i = 0;

  vec_validate_aligned (sess->out_sa, vec_len (om->oct_dev),
			CLIB_CACHE_LINE_BYTES);

  pool_foreach_pointer (oct_dev, om->oct_dev)
    {
      /* Alloc an sa index */
      rv = oct_ipsec_outb_sa_idx_get (oct_dev, &sa_idx, sa->spi);
      if (rv)
	return rv;

      out_sa = sess->out_sa[i] =
	roc_nix_inl_ot_ipsec_outb_sa (oct_dev->outb.sa_base, sa_idx);

      outb_priv = roc_nix_inl_ot_ipsec_outb_sa_sw_rsvd (out_sa);
      outb_priv->sa_idx = sa_idx;

      roc_ot_ipsec_outb_sa_init (out_sa);

      w2.u64 = 0;
      rv = oct_ipsec_sa_common_param_fill (&w2, out_sa->cipher_key,
					   out_sa->iv.s.salt,
					   out_sa->hmac_opad_ipad, sa);
      if (rv)
	return rv;

      /* Set direction and enable ESN (if needed) */
      w2.s.dir = ROC_IE_SA_DIR_OUTBOUND;
      if (ipsec_sa_is_set_USE_ESN (sa))
	out_sa->w0.s.esn_en = 1;

      /* Configure tunnel header generation */
      if (ipsec_sa_is_set_IS_TUNNEL (sa))
	{
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	    {
	      w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_6;

	      clib_memcpy (&out_sa->outer_hdr.ipv6.src_addr,
			   &sa->tunnel.t_src.ip.ip6, sizeof (ip6_address_t));
	      clib_memcpy (&out_sa->outer_hdr.ipv6.dst_addr,
			   &sa->tunnel.t_dst.ip.ip6, sizeof (ip6_address_t));

	      /* Convert host to network byte order of ipv6 address */
	      ipv6_addr = (u64 *) &out_sa->outer_hdr.ipv6.src_addr;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	      ipv6_addr++;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);

	      ipv6_addr = (u64 *) &out_sa->outer_hdr.ipv6.dst_addr;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	      ipv6_addr++;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	    }
	  else
	    {
	      w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_4;
	      out_sa->outer_hdr.ipv4.src_addr =
		clib_host_to_net_u32 (sa->tunnel.t_src.ip.ip4.as_u32);
	      out_sa->outer_hdr.ipv4.dst_addr =
		clib_host_to_net_u32 (sa->tunnel.t_dst.ip.ip4.as_u32);
	    }
	}

      offset = offsetof (struct roc_ot_ipsec_outb_sa, ctx);
      out_sa->w0.s.hw_ctx_off = offset / 8;
      out_sa->w0.s.ctx_push_size = out_sa->w0.s.hw_ctx_off + 1;
      /* Set context size, in number of 128B units following the first 128B */
      out_sa->w0.s.ctx_size = (round_pow2 (offset, 128) >> 7) - 1;
      out_sa->w0.s.ctx_hdr_size = 1;
      out_sa->w0.s.aop_valid = 1;

      out_sa->w2.u64 = w2.u64;

      if (ipsec_sa_is_set_IS_TUNNEL (sa))
	{
	  if (sa->tunnel.t_encap_decap_flags &
	      TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF)
	    out_sa->w2.s.ipv4_df_src_or_ipv6_flw_lbl_src =
	      ROC_IE_OT_SA_COPY_FROM_INNER_IP_HDR;
	  if (!sa->tunnel.t_dscp)
	    out_sa->w2.s.dscp_src = ROC_IE_OT_SA_COPY_FROM_INNER_IP_HDR;
	  else
	    {
	      out_sa->w2.s.dscp_src = ROC_IE_OT_SA_COPY_FROM_SA;
	      out_sa->w10.s.dscp = sa->tunnel.t_dscp;
	    }
	}

      out_sa->w2.s.ipid_gen = 1;
      out_sa->w2.s.iv_src = ROC_IE_OT_SA_IV_SRC_FROM_SA;
      out_sa->w2.s.valid = 1;

      asm volatile ("dmb oshst" ::: "memory");

      oct_ipsec_sa_len_precalc (sa, &sess->encap);

      oct_ipsec_common_inst_param_fill (out_sa, sess);

      /* Populate word4 in CPT instruction template */
      inst_w4.u64 = 0;
      inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC;
      param1.u16 = 0;
      if (sa->tunnel.t_hop_limit)
	param1.s.ttl_or_hop_limit = 1;

      /* Enable IP checksum computation by default */
      param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_ENABLE;
      /* Enable L4 checksum computation by default */
      param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_ENABLE;

      inst_w4.s.param1 = param1.u16;
      sess->inst.w4.u64 = inst_w4.u64;
      if (ipsec_sa_is_set_UDP_ENCAP (sa))
	{
	  out_sa->w10.s.udp_dst_port = 4500;
	  out_sa->w10.s.udp_src_port = 4500;
	}

      rv = roc_nix_inl_ctx_write (oct_dev->nix, out_sa, out_sa, false,
				  sizeof (struct roc_ot_ipsec_outb_sa));
      if (rv)
	{
	  clib_warning ("roc_nix_inl_ctx_write failed with '%s' error",
			roc_error_msg_get (rv));
	  return -1;
	}
      i++;
    }
  return 0;
}

static_always_inline i32
oct_o20_ipsec_outb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  oct_main_t *om = &oct_main;
  union roc_ow_ipsec_outb_param1 param1;
  struct roc_ow_ipsec_outb_sa *out_sa;
  oct_ipsec_outb_sa_priv_data_t *outb_priv;
  union roc_ow_ipsec_sa_word2 w2;
  union cpt_inst_w4 inst_w4;
  u32 sa_idx;
  u64 *ipv6_addr;
  size_t offset;
  int rv = 0, i = 0;

  vec_validate_aligned (sess->out_sa, vec_len (om->oct_dev),
			CLIB_CACHE_LINE_BYTES);

  pool_foreach_pointer (oct_dev, om->oct_dev)
    {
      /* Alloc an sa index */
      rv = oct_ipsec_outb_sa_idx_get (oct_dev, &sa_idx, sa->spi);
      if (rv)
	return rv;

      out_sa = sess->out_sa[i] =
	roc_nix_inl_ow_ipsec_outb_sa (oct_dev->outb.sa_base, sa_idx);

      outb_priv = roc_nix_inl_ow_ipsec_outb_sa_sw_rsvd (out_sa);
      outb_priv->sa_idx = sa_idx;

      roc_ow_ipsec_outb_sa_init (out_sa);

      w2.u64 = 0;
      rv = oct_o20_ipsec_sa_common_param_fill (&w2, out_sa->cipher_key,
					       out_sa->iv.s.salt,
					       out_sa->hmac_opad_ipad, sa);
      if (rv)
	return rv;

      /* Set direction and enable ESN (if needed) */
      w2.s.dir = ROC_IE_SA_DIR_OUTBOUND;
      if (ipsec_sa_is_set_USE_ESN (sa))
	out_sa->w0.s.esn_en = 1;

      /* Configure tunnel header generation */
      if (ipsec_sa_is_set_IS_TUNNEL (sa))
	{
	  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	    {
	      w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_6;

	      clib_memcpy (&out_sa->outer_hdr.ipv6.src_addr,
			   &sa->tunnel.t_src.ip.ip6, sizeof (ip6_address_t));
	      clib_memcpy (&out_sa->outer_hdr.ipv6.dst_addr,
			   &sa->tunnel.t_dst.ip.ip6, sizeof (ip6_address_t));

	      /* Convert host to network byte order of ipv6 address */
	      ipv6_addr = (u64 *) &out_sa->outer_hdr.ipv6.src_addr;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	      ipv6_addr++;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);

	      ipv6_addr = (u64 *) &out_sa->outer_hdr.ipv6.dst_addr;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	      ipv6_addr++;
	      *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	    }
	  else
	    {
	      w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_4;
	      out_sa->outer_hdr.ipv4.src_addr =
		clib_host_to_net_u32 (sa->tunnel.t_src.ip.ip4.as_u32);
	      out_sa->outer_hdr.ipv4.dst_addr =
		clib_host_to_net_u32 (sa->tunnel.t_dst.ip.ip4.as_u32);
	    }
	}

      offset = offsetof (struct roc_ow_ipsec_outb_sa, ctx);
      out_sa->w0.s.hw_ctx_off = offset / 8;
      out_sa->w0.s.ctx_push_size = out_sa->w0.s.hw_ctx_off + 1;
      /* Set context size, in number of 128B units following the first 128B */
      out_sa->w0.s.ctx_size = (round_pow2 (offset, 128) >> 7) - 1;
      out_sa->w0.s.ctx_hdr_size = 1;
      out_sa->w0.s.aop_valid = 1;

      out_sa->w2.u64 = w2.u64;

      if (ipsec_sa_is_set_IS_TUNNEL (sa))
	{
	  if (sa->tunnel.t_encap_decap_flags &
	      TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF)
	    out_sa->w2.s.ipv4_df_src_or_ipv6_flw_lbl_src =
	      ROC_IE_OW_SA_COPY_FROM_INNER_IP_HDR;
	  if (!sa->tunnel.t_dscp)
	    out_sa->w2.s.dscp_src = ROC_IE_OW_SA_COPY_FROM_INNER_IP_HDR;
	  else
	    {
	      out_sa->w2.s.dscp_src = ROC_IE_OW_SA_COPY_FROM_SA;
	      out_sa->w10.s.dscp = sa->tunnel.t_dscp;
	    }
	}

      out_sa->w2.s.ipid_gen = 1;
      out_sa->w2.s.iv_src = ROC_IE_OW_SA_IV_SRC_FROM_SA;
      out_sa->w2.s.valid = 1;

      asm volatile ("dmb oshst" ::: "memory");

      oct_ipsec_sa_len_precalc (sa, &sess->encap);

      oct_ipsec_common_inst_param_fill (out_sa, sess);

      /* Populate word4 in CPT instruction template */
      inst_w4.u64 = 0;
      inst_w4.s.opcode_major = ROC_IE_OW_MAJOR_OP_PROCESS_OUTBOUND_IPSEC;
      param1.u16 = 0;
      if (sa->tunnel.t_hop_limit)
	param1.s.ttl_or_hop_limit = 1;

      /* Enable IP checksum computation by default */
      param1.s.ip_csum_disable = ROC_IE_OW_SA_INNER_PKT_IP_CSUM_ENABLE;
      /* Enable L4 checksum computation by default */
      param1.s.l4_csum_disable = ROC_IE_OW_SA_INNER_PKT_L4_CSUM_ENABLE;

      inst_w4.s.param1 = param1.u16;
      sess->inst.w4.u64 = inst_w4.u64;
      if (ipsec_sa_is_set_UDP_ENCAP (sa))
	{
	  out_sa->w10.s.udp_dst_port = 4500;
	  out_sa->w10.s.udp_src_port = 4500;
	}

      rv = roc_nix_inl_ctx_write (oct_dev->nix, out_sa, out_sa, false,
				  sizeof (struct roc_ow_ipsec_outb_sa));
      if (rv)
	{
	  clib_warning ("roc_nix_inl_ctx_write failed with '%s' error",
			roc_error_msg_get (rv));
	  return -1;
	}
      i++;
    }
  return 0;
}

static i32
oct_ipsec_outb_session_update (oct_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  if (roc_model_is_cn20k ())
    return oct_o20_ipsec_outb_session_update (sess, sa);
  return oct_o10_ipsec_outb_session_update (sess, sa);
}

static i32
oct_ipsec_session_create (u32 sa_index)
{
  oct_ipsec_main_t *oim = &oct_ipsec_main;
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  oct_ipsec_session_t *session = NULL;
  u32 sess_index;
  int rv;

  pool_get_aligned (oim->inline_ipsec_sessions, session, ROC_ALIGN);
  clib_memset (session, 0, sizeof (*session));
  sess_index = session - oim->inline_ipsec_sessions;

  ASSERT (sa_index == sess_index);

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    rv = oct_ipsec_inb_session_update (session, sa);
  else
    rv = oct_ipsec_outb_session_update (session, sa);

  if (rv)
    return rv;

  /* Initialize the ITF details in ipsec_session for tunnel SAs */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    session->itf_sw_idx = ~0;
  return 0;
}

static i32
oct_ipsec_session_destroy (u32 sa_index)
{
  oct_main_t *om = &oct_main;
  oct_ipsec_main_t *oim = &oct_ipsec_main;
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  oct_ipsec_session_t *session = NULL;
  void *roc_sa;
  void *sa_dptr = NULL;
  int rv, i = 0;

  session = pool_elt_at_index (oim->inline_ipsec_sessions, sa_index);
  if (pool_is_free (oim->inline_ipsec_sessions, session))
    return -1;

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    {
      roc_sa = (void *) roc_nix_inl_inb_sa_get (NULL, true, sa->spi);
      if (!roc_sa)
	{
	  clib_warning ("roc_nix_inl_inb_sa_get failed to get SA for spi %u",
			sa->spi);
	  return -1;
	}

      sa_dptr = plt_zmalloc (oct_ipsec_get_inb_sa_sz (), 8);
      if (sa_dptr != NULL)
	{
	  oct_ipsec_sa_init (sa_dptr, true);
	  rv = roc_nix_inl_ctx_write (NULL, sa_dptr, roc_sa, true,
				      oct_ipsec_get_inb_sa_sz ());
	  if (rv)
	    {
	      clib_warning ("roc_nix_inl_ctx_write failed - ROC error %s (%d)",
			    roc_error_msg_get (rv), rv);
	      return rv;
	    }
	  plt_free (sa_dptr);
	}
    }
  else
    {
      pool_foreach_pointer (oct_dev, om->oct_dev)
	{
	  sa_dptr = plt_zmalloc (oct_ipsec_get_outb_sa_sz (), 8);
	  if (sa_dptr != NULL)
	    {
	      oct_ipsec_sa_init (sa_dptr, false);
	      rv = roc_nix_inl_ctx_write (oct_dev->nix, sa_dptr,
					  session->out_sa[i], false,
					  oct_ipsec_get_outb_sa_sz ());
	      if (rv)
		{
		  clib_warning (
		    "Could not write inline outbound session to hardware");
		  return rv;
		}
	      plt_free (sa_dptr);
	    }
	  i++;
	}
    }

  clib_memset (session, 0, sizeof (oct_ipsec_session_t));
  pool_put (oim->inline_ipsec_sessions, session);

  return 0;
}

static clib_error_t *
oct_add_del_session (u32 sa_index, u8 is_add)
{
  ipsec_sa_t *sa;

  if (!is_add)
    {
      if (oct_ipsec_session_destroy (sa_index) < 0)
	{
	  return clib_error_create (
	    "IPsec session destroy operation failed for IPsec "
	    "index %u",
	    sa_index);
	}
      return 0;
    }

  if (oct_ipsec_session_create (sa_index) < 0)
    return clib_error_create ("ipsec session create failed for sa index %u",
			      sa_index);

  sa = ipsec_sa_get (sa_index);

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    return oct_inl_inb_ipsec_flow_enable ();

  return 0;
}

static clib_error_t *
oct_ipsec_check_support (ipsec_sa_t *sa)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  union cpt_eng_caps hw_caps = oct_cpt_get_eng_caps (ocm);
  u8 is_cipher_algo_supported;
  u8 is_auth_algo_supported;

  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_NONE:
      is_cipher_algo_supported = 1;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
    case IPSEC_CRYPTO_ALG_AES_GCM_192:
    case IPSEC_CRYPTO_ALG_AES_GCM_256:
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      is_cipher_algo_supported = hw_caps.aes;
      break;
    case IPSEC_CRYPTO_ALG_3DES_CBC:
      is_cipher_algo_supported = hw_caps.des;
      break;
    default:
      is_cipher_algo_supported = 0;
      break;
    }

  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_NONE:
      is_auth_algo_supported = 1;
      break;
    case IPSEC_INTEG_ALG_SHA1_96:
    case IPSEC_INTEG_ALG_SHA_256_128:
    case IPSEC_INTEG_ALG_SHA_384_192:
    case IPSEC_INTEG_ALG_SHA_512_256:
      is_auth_algo_supported = hw_caps.sha1_sha2;
      break;
    default:
      is_auth_algo_supported = 0;
      break;
    }

  if (!is_cipher_algo_supported)
    return clib_error_create ("crypto-alg %U not supported",
			      format_ipsec_crypto_alg, sa->crypto_alg);

  if (!is_auth_algo_supported)
    return clib_error_create ("integ-alg %U not supported",
			      format_ipsec_integ_alg, sa->integ_alg);

  return 0;
}

vnet_dev_rv_t
oct_init_ipsec_backend (vlib_main_t *vm, vnet_dev_t *dev)
{
  ipsec_main_t *im = &ipsec_main;
  int rv;
  u32 idx;

  idx = ipsec_register_esp_backend (
    vm, im, "octeon backend", "esp4-encrypt", "oct-esp4-encrypt-tun",
    "esp4-decrypt", "esp4-decrypt-tun", "esp6-encrypt", "oct-esp6-encrypt-tun",
    "esp6-decrypt", "esp6-decrypt-tun", "esp-mpls-encrypt-tun",
    oct_ipsec_check_support, oct_add_del_session);

  rv = ipsec_select_esp_backend (im, idx);
  if (rv)
    {
      log_err (dev, "OCTEON IPsec ESP backend selection failed");
      return VNET_DEV_ERR_INTERNAL;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_ipsec_inl_dev_inb_cfg (vlib_main_t *vm, vnet_dev_t *dev,
			   oct_inl_dev_cfg_t *inl_dev_cfg)
{
  oct_inl_dev_main_t *inl_dev_main = &oct_inl_dev_main;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_cpt_rxc_time_cfg rxc_cfg = { 0 };
  int rrv;

  cd->nix->ipsec_in_min_spi = inl_dev_main->in_min_spi;
  cd->nix->ipsec_in_max_spi = inl_dev_main->in_max_spi;

  if ((rrv = roc_nix_inl_inb_init (cd->nix)))
    {
      log_err (dev, "roc_nix_inl_inb_init failed - ROC error %s [%d]",
	       roc_error_msg_get (rrv), rrv);
      return VNET_DEV_ERR_INTERNAL;
    }

  roc_nix_inb_mode_set (cd->nix, true);
  if (roc_model_is_cn10k ())
    roc_nix_inl_inb_set (cd->nix, true);

  if ((rrv = roc_nix_reassembly_configure (&rxc_cfg, 1000)))
    {
      log_err (dev, "roc_nix_reassembly_configure failed - ROC error %s [%d]",
	       roc_error_msg_get (rrv), rrv);
      return VNET_DEV_ERR_INTERNAL;
    }

  inl_dev_main->inb_sa_base = roc_nix_inl_inb_sa_base_get (NULL, true);
  inl_dev_main->inb_sa_sz = roc_nix_inl_inb_sa_sz (NULL, true);

  inl_dev_main->inb_spi_mask =
    roc_nix_inl_inb_spi_range (NULL, true, NULL, NULL);

  return VNET_DEV_OK;
}

static int
oct_pool_inl_meta_pool_cb (u64 *aura_handle, uintptr_t *mpool, u32 buf_sz,
			   u32 nb_bufs, bool destroy, const char *mempool_name)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  u64 mem_start, mem_end, elem_addr;
  struct npa_pool_s npapool;
  struct npa_aura_s aura;
  const char *mp_name;
  u32 i;
  u64 total_sz;
  u64 roc_aura_handle;
  int rv;

  mp_name = mempool_name ? mempool_name : OCT_NIX_INL_META_POOL_NAME;

  if (destroy)
    return 0;

  buf_sz = PLT_ALIGN (buf_sz, ROC_ALIGN);
  total_sz = nb_bufs * buf_sz;

  mem_start = (u64) oct_plt_init_param.oct_plt_zmalloc (total_sz, ROC_ALIGN);
  if (!mem_start)
    {
      clib_warning ("Failed to allocate physmem for pool %s", mp_name);
      return -1;
    }

  clib_memset (&aura, 0, sizeof (struct npa_aura_s));
  clib_memset (&npapool, 0, sizeof (struct npa_pool_s));

  npapool.nat_align = 1;

  rv = roc_npa_pool_create (&roc_aura_handle, buf_sz, nb_bufs, &aura, &npapool,
			    mempool_name ? 0 : ROC_NPA_ZERO_AURA_F);
  if (rv)
    {
      clib_warning ("roc_npa_pool_create failed with '%s' error",
		    roc_error_msg_get (rv));
      return -1;
    }

  mem_end = mem_start + total_sz;

  roc_npa_aura_op_range_set (roc_aura_handle, mem_start, mem_end);

  elem_addr = mem_start;
  for (i = 0; i < nb_bufs; i++)
    {
      roc_npa_aura_op_free (roc_aura_handle, 0, elem_addr);
      elem_addr += buf_sz;
    }

  /* Read back to confirm pointers are freed */
  roc_npa_aura_op_available (roc_aura_handle);

  *aura_handle = roc_aura_handle;
  *mpool = (uintptr_t) mem_start;

  return 0;
}

vnet_dev_rv_t
oct_ipsec_inl_dev_outb_cfg (vnet_dev_t *dev, oct_inl_dev_cfg_t *inl_dev_cfg)
{
  oct_inl_dev_main_t *inl_dev_main = &oct_inl_dev_main;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_cpt_lf *cpt_lf;
  u64 cpt_io_addr;
  struct plt_bitmap *bmap;
  size_t bmap_sz;
  void *mem;
  int rrv, i;

  nix->outb_nb_desc = inl_dev_cfg->outb_nb_desc = 8192;
  nix->outb_nb_crypto_qs = inl_dev_cfg->outb_nb_crypto_qs = 1;
  nix->ipsec_out_max_sa = cd->outb.max_sa = inl_dev_main->out_max_sa;
  nix->ipsec_out_sso_pffunc = false;

  rrv = roc_nix_inl_outb_init (nix);
  if (rrv)
    {
      log_err (dev, "roc_nix_inl_outb_init failed - ROC error '%s [%d]",
	       roc_error_msg_get (rrv), rrv);
      return VNET_DEV_ERR_INTERNAL;
    }

  cpt_lf = roc_nix_inl_outb_lf_base_get (nix);

  cpt_io_addr = cpt_lf->io_addr;
  cpt_io_addr |= (ROC_CN10K_CPT_INST_DW_M1 << 4);
  cd->cpt_io_addr = cpt_io_addr;

  bmap_sz = plt_bitmap_get_memory_footprint (cd->outb.max_sa);
  mem = plt_zmalloc (bmap_sz, PLT_CACHE_LINE_SIZE);
  if (mem == NULL)
    {
      log_err (dev, "Outbound SA bmap alloc failed");
      roc_nix_inl_outb_fini (nix);

      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
    }

  bmap = plt_bitmap_init (cd->outb.max_sa, mem, bmap_sz);
  if (!bmap)
    {
      log_err (dev, "Outbound SA bmap init failed");
      roc_nix_inl_outb_fini (nix);
      plt_free (mem);

      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
    }

  for (i = 0; i < cd->outb.max_sa; i++)
    plt_bitmap_set (bmap, i);

  cd->outb.sa_base = roc_nix_inl_outb_sa_base_get (nix);
  cd->outb.sa_bmap_mem = mem;
  cd->outb.sa_bmap = bmap;

  return VNET_DEV_OK;
}

void
oct_ipsec_sso_work_cb (uint64_t *gw, void *args, enum nix_inl_event_type type,
		       void *cq_s, uint32_t port_id)
{
  vlib_main_t *vm = vlib_get_main ();
  struct roc_ot_ipsec_outb_sa *sa;
  oct_ipsec_outb_sa_priv_data_t *outb_priv;
  vlib_buffer_t *b;
  u32 bi;

  switch ((gw[0] >> 28) & 0xF)
    {
    case OCT_EVENT_TYPE_FRM_INL_DEV:
      /* Event from inbound inline dev due to IPSEC packet bad L4 */
      b = (vlib_buffer_t *) (gw[1] - sizeof (vlib_buffer_t));
      bi = vlib_get_buffer_index (vm, b);
      vlib_buffer_free_no_next (vm, &bi, 1);
      return;
    case OCT_EVENT_TYPE_FRM_CPU:
      /* Event from outbound inline error */
      b = (vlib_buffer_t *) gw[1];
      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, b));
      break;
      /* Fall through */
    default:
      if (type == NIX_INL_SOFT_EXPIRY_THRD)
	{
	  sa = (struct roc_ot_ipsec_outb_sa *) args;
	  outb_priv = roc_nix_inl_ot_ipsec_outb_sa_sw_rsvd (sa);
	  clib_warning ("Soft expiry event received for sa_index %u",
			outb_priv->sa_idx);
	}
      else
	{
	  clib_warning ("Unknown event gw[0] = 0x%016lx, gw[1] = 0x%016lx",
			gw[0], gw[1]);
	}
      return;
    }

  return;
}

vnet_dev_rv_t
oct_early_init_inline_ipsec (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  u8 bp_index = vlib_buffer_pool_get_default_for_numa (vm, 0);
  vlib_buffer_pool_t *bp = NULL;
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_inl_dev_main_t *inl_dev_main = &oct_inl_dev_main;
  int rrv;

  bp = vec_elt_at_index (bm->buffer_pools, bp_index);

  inl_dev_main->inl_dev->ipsec_in_min_spi = inl_dev_main->in_min_spi;
  inl_dev_main->inl_dev->ipsec_in_max_spi = inl_dev_main->in_max_spi;
  inl_dev_main->inl_dev->wqe_skip =
    STRUCT_OFFSET_OF (vlib_buffer_t, pre_data) / ROC_ALIGN;
  inl_dev_main->inl_dev->nb_meta_bufs = bp->n_buffers;
  inl_dev_main->inl_dev->res_addr_offset = -1;
  if (roc_feature_nix_has_inl_multi_queue ())
    inl_dev_main->inl_dev->nb_inb_cptlfs = 1;

  if ((rrv = roc_nix_inl_dev_init (inl_dev_main->inl_dev)) < 0)
    {
      log_err (dev, "roc_nix_inl_dev_init: %s [%d]", roc_error_msg_get (rrv),
	       rrv);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  roc_nix_inl_meta_pool_cb_register (oct_pool_inl_meta_pool_cb);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_init_nix_inline_ipsec (vlib_main_t *vm, vnet_dev_t *inl_dev,
			   vnet_dev_t *dev)
{
  oct_inl_dev_cfg_t inl_dev_cfg;
  vnet_dev_rv_t rv;

  if ((rv = oct_ipsec_inl_dev_inb_cfg (vm, dev, &inl_dev_cfg)))
    return rv;

  if ((rv = oct_ipsec_inl_dev_outb_cfg (dev, &inl_dev_cfg)))
    return rv;

  /* Register callback to handle security error work */
  roc_nix_inl_cb_register (oct_ipsec_sso_work_cb, NULL);

  return VNET_DEV_OK;
}
