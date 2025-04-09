/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _OCTEON_IPSEC_H_
#define _OCTEON_IPSEC_H_

#define OCT_EVENT_TYPE_FRM_INL_DEV 0x0
#define OCT_EVENT_TYPE_FRM_CPU	   0x1

#define OCT_ROC_SALT_LEN 4
#define OCT_EXT_HDR_FROM_VLIB_BUFFER(x)                                       \
  (((oct_ipsec_outbound_pkt_meta_t *) (x)) - 1)

#define foreach_octeon10_ipsec_ucc                                            \
  _ (SUCCESS, success, INFO, "Packet successfully processed")                 \
  _ (ERR_SA_INVAL, err_sa_inval, ERROR, "SA invalid")                         \
  _ (ERR_SA_EXPIRED, err_sa_expired, ERROR, "SA hard-expired")                \
  _ (ERR_SA_OVERFLOW, err_sa_overflow, ERROR, "SA overflow")                  \
  _ (ERR_SA_ESP_BAD_ALGO, err_sa_esp_bad_algo, ERROR, "ESP bad algorithm")    \
  _ (ERR_SA_AH_BAD_ALGO, err_sa_ah_bad_algo, ERROR, "SA AH bad algorithm")    \
  _ (ERR_SA_BAD_CTX, err_sa_bad_ctx, ERROR, "Bad SA context received on CPT") \
  _ (SA_CTX_FLAG_MISMATCH, sa_ctx_flag_mismatch, ERROR,                       \
     "SA context flags mismatch")                                             \
  _ (ERR_AOP_IPSEC, err_aop_ipsec, ERROR, "AOP logical error")                \
  _ (ERR_PKT_IP, err_pkt_ip, ERROR, "Bad IP version or TTL")                  \
  _ (ERR_PKT_IP6_BAD_EXT, err_pkt_ip6_bad_ext, ERROR,                         \
     "IPv6 mobility extension not supported")                                 \
  _ (ERR_PKT_IP6_HBH, err_pkt_ip6_hbh, ERROR,                                 \
     "Error with IPv6 hop-by-hop header")                                     \
  _ (ERR_PKT_IP6_BIGEXT, err_pkt_ip6_bigext, ERROR,                           \
     "IPv6 extension header length exceeded")                                 \
  _ (ERR_PKT_IP_ULP, err_pkt_ip_ulp, ERROR, "Bad protocol in IP header")      \
  _ (ERR_PKT_SA_MISMATCH, err_pkt_sa_mismatch, ERROR,                         \
     "IP address mismatch b/w SA and packet")                                 \
  _ (ERR_PKT_SPI_MISMATCH, err_pkt_spi_mismatch, ERROR,                       \
     "SPI mismatch b/w SA and packet")                                        \
  _ (ERR_PKT_ESP_BADPAD, err_pkt_esp_badpad, ERROR,                           \
     "Bad padding in ESP packet")                                             \
  _ (ERR_PKT_BADICV, err_pkt_badicv, ERROR, "ICV verification failed")        \
  _ (ERR_PKT_REPLAY_SEQ, err_pkt_replay_seq, ERROR,                           \
     "Sequence number out of anti-replay window")                             \
  _ (ERR_PKT_BADNH, err_pkt_badnh, ERROR, "Bad next-hop")                     \
  _ (ERR_PKT_SA_PORT_MISMATCH, err_pkt_sa_port_mismatch, ERROR,               \
     "Port mismatch b/w packet and SA")                                       \
  _ (ERR_PKT_BAD_DLEN, err_pkt_bad_dlen, ERROR, "Dlen mismatch")              \
  _ (ERR_SA_ESP_BAD_KEYS, err_sa_esp_bad_keys, ERROR,                         \
     "Bad key-size for selected ESP algorithm")                               \
  _ (ERR_SA_AH_BAD_KEYS, err_sa_ah_bad_keys, ERROR,                           \
     "Bad key-size for selected AH algorithm")                                \
  _ (ERR_SA_BAD_IP, err_sa_bad_ip, ERROR,                                     \
     "IP version mismatch b/w packet and SA")                                 \
  _ (ERR_PKT_IP_FRAG, err_pkt_ip_frag, ERROR,                                 \
     "IPsec packet is an outer-IP fragment")                                  \
  _ (ERR_PKT_REPLAY_WINDOW, err_pkt_replay_window, ERROR,                     \
     "Sequence number already seen")                                          \
  _ (SUCCESS_PKT_IP_BADCSUM, success_pkt_ip_badcsum, ERROR,                   \
     "Bad IP checksum ")                                                      \
  _ (SUCCESS_PKT_L4_GOODCSUM, success_pkt_l4_goodcsum, INFO,                  \
     "Good inner L4 checksum")                                                \
  _ (SUCCESS_PKT_L4_BADCSUM, success_pkt_l4_badcsum, ERROR,                   \
     "Bad inner L4 checksum")                                                 \
  _ (SUCCESS_SA_SOFTEXP_FIRST, success_sa_softexp_first, WARN,                \
     "SA soft-expired - first encounter")                                     \
  _ (SUCCESS_PKT_UDPESP_NZCSUM, success_pkt_udpesp_nzcsum, ERROR,             \
     "Non-zero UDP checksum in UDP-ESP packet")                               \
  _ (SUCCESS_SA_SOFTEXP_AGAIN, success_sa_softexp_again, WARN,                \
     "SA soft-expired - subsequent encounter")                                \
  _ (SUCCESS_PKT_UDP_ZEROCSUM, success_pkt_udp_zerocsum, INFO,                \
     "Zero UDP checksum")

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  u64 nixtx[2];
  u8 sg_buffer[128];
} oct_ipsec_outbound_pkt_meta_t;

typedef struct
{
  union cpt_res_s res;
  u16 dlen_adj;
  u16 sa_bytes;
} oct_ipsec_outb_data_t;

STATIC_ASSERT (sizeof (oct_ipsec_outb_data_t) <=
		 STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
	       "Outbound meta-data too large for vnet_buffer_opaque2_t");

#define oct_ipsec_outb_data(b)                                                \
  ((oct_ipsec_outb_data_t *) ((u8 *) (b)->opaque2 +                           \
			      STRUCT_OFFSET_OF (vnet_buffer_opaque2_t,        \
						unused)))

typedef struct
{
  uint8_t partial_len;
  uint8_t roundup_len;
  uint8_t footer_len;
  uint8_t roundup_byte;
  uint8_t icv_len;
} oct_ipsec_encap_len_t;

typedef struct
{
  u64 user_data;
} oct_ipsec_inb_sa_priv_data_t;

typedef struct
{
  /* SA index */
  u32 sa_idx;
} oct_ipsec_outb_sa_priv_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Outbound SA */
  struct roc_ot_ipsec_outb_sa **out_sa;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  struct cpt_inst_s inst;
  u16 sq;
  u32 itf_sw_idx;
  /* Packet length for IPsec encapsulation */
  oct_ipsec_encap_len_t encap;
} oct_ipsec_session_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  oct_ipsec_session_t *inline_ipsec_sessions;

} oct_ipsec_main_t;

typedef struct
{
  u32 outb_nb_desc;
  u16 outb_nb_crypto_qs;
} oct_inl_dev_cfg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct roc_nix_inl_dev *inl_dev;
  vnet_dev_t *vdev;
  uintptr_t inb_sa_base;
  u32 inb_sa_sz;
  u32 inb_spi_mask;
  u8 is_inl_ipsec_flow_enabled;
  u32 in_min_spi;
  u32 in_max_spi;
  u32 out_max_sa;
} oct_inl_dev_main_t;

extern oct_ipsec_main_t oct_ipsec_main;
extern oct_inl_dev_main_t oct_inl_dev_main;

vnet_dev_rv_t oct_init_ipsec_backend (vlib_main_t *vm, vnet_dev_t *dev);

vnet_dev_rv_t oct_early_init_inline_ipsec (vlib_main_t *vm, vnet_dev_t *dev);
vnet_dev_rv_t oct_init_nix_inline_ipsec (vlib_main_t *vm, vnet_dev_t *inl_dev,
					 vnet_dev_t *dev);
void *oct_ipsec_get_oct_device_from_outb_sa (u32 sa_index);

clib_error_t *oct_inl_inb_ipsec_flow_enable (void);

#endif /* _OCTEON_IPSEC_H_ */
