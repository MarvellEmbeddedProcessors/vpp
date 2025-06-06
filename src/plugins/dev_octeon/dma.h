/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vlib/dma/dma.h>

#ifndef _DMA_H_
#define _DMA_H_

#define OCT_MAX_N_DMA_DEV 32

#define OCT_DPI_MAX_POINTER	      15
#define OCT_DPI_STRM_INC_N(s, var, n) ((s).var = ((s).var + n) & (s).max_cnt)
#define OCT_DPI_STRM_INC(s, var)      ((s).var = ((s).var + 1) & (s).max_cnt)
#define OCT_DPI_STRM_DEC(s, var)                                              \
  ((s).var = ((s).var - 1) == -1 ? (s).max_cnt : ((s).var - 1))
#define OCT_DPI_MAX_DESC	     32768
#define OCT_DPI_MIN_DESC	     2
#define CN10K_DPI_MAX_PRI	     2
#define OCT_DPI_MAX_VCHANS_PER_QUEUE 128
#define OCT_DPI_QUEUE_BUF_SIZE	     16256
#define OCT_DPI_QUEUE_BUF_SIZE_V2    130944
#define OCT_DPI_POOL_MAX_CACHE_SZ    (16)
#define OCT_DPI_DW_PER_SINGLE_CMD    8
#define OCT_DPI_HDR_LEN		     4
#define OCT_DPI_CMD_LEN(src, dst)                                             \
  (OCT_DPI_HDR_LEN + ((src) << 1) + ((dst) << 1))
#define OCT_DPI_MAX_CMD_SZ                                                    \
  OCT_DPI_CMD_LEN (OCT_DPI_MAX_POINTER, OCT_DPI_MAX_POINTER)
#define OCT_DPI_CHUNKS_FROM_DESC(cz, desc)                                    \
  (((desc) / (((cz) / 8) / OCT_DPI_MAX_CMD_SZ)) + 1)
#define OCT_DPI_COMPL_OFFSET ROC_CACHE_LINE_SZ
/* Set Completion data to 0xFF when request submitted,
 * upon successful request completion engine reset to completion status
 */
#define OCT_DPI_REQ_CDATA 0xFF
#define OCT_DPI_STRM_DEC(s, var)                                              \
  ((s).var = ((s).var - 1) == -1 ? (s).max_cnt : ((s).var - 1))
#define DPI_VDMA_DBELL (0x10)
union oct_dpi_instr_cmd
{
  u64 u;
  struct cn9k_dpi_instr_cmd
  {
    u64 aura : 20;
    u64 func : 16;
    u64 pt : 2;
    u64 reserved_102 : 1;
    u64 pvfe : 1;
    u64 fl : 1;
    u64 ii : 1;
    u64 fi : 1;
    u64 ca : 1;
    u64 csel : 1;
    u64 reserved_109_111 : 3;
    u64 xtype : 2;
    u64 reserved_114_119 : 6;
    u64 fport : 2;
    u64 reserved_122_123 : 2;
    u64 lport : 2;
    u64 reserved_126_127 : 2;
    /* Word 1 - End */
  } cn9k;

  struct cn10k_dpi_instr_cmd
  {
    u64 nfst : 4;
    u64 reserved_4_5 : 2;
    u64 nlst : 4;
    u64 reserved_10_11 : 2;
    u64 pvfe : 1;
    u64 reserved_13 : 1;
    u64 func : 16;
    u64 aura : 20;
    u64 xtype : 2;
    u64 reserved_52_53 : 2;
    u64 pt : 2;
    u64 fport : 2;
    u64 reserved_58_59 : 2;
    u64 lport : 2;
    u64 reserved_62_63 : 2;
    /* Word 0 - End */
  } cn10k;
};

typedef struct oct_dpi_cdesc_data_s
{
  uint16_t max_cnt;
  uint16_t head;
  uint16_t tail;
  uint8_t *compl_ptr;
} oct_dma_desc_t;

typedef struct
{
  u64 cmd;
  u64 compl_ptr;
  u64 flags;
  u64 reserved_word3; // Reserved for future use
  u64 src_length;
  u64 src;
  u64 dst_length;
  u64 dst;
} oct_dpi_inst_hdr_t;

struct oct_dma_stats
{
  u64 submitted;
  u64 completed;
  u64 errors;
};

struct oct_dpi_conf
{
  union oct_dpi_instr_cmd cmd;
  oct_dma_desc_t c_desc;
  u16 desc_idx;
  struct oct_dma_stats stats;
  u64 completed_offset;
  bool adapter_enabled;
};

typedef struct
{
  u64 submitted;
  u64 completed;
  u64 sw_fallback;
  u64 *chunk_base;
  u16 chunk_head;
  u16 chunk_size_m1;
  u16 total_pnum_words;
  struct oct_dpi_conf conf;
  struct roc_dpi rdpi;
  u64 aura_handle;
  u16 n_threads;
  u16 n_enq;
  u16 max_transfers;
  u32 max_transfer_size;
  vnet_dev_t *dev;
  u8 numa;
  u8 lock;
  u8 size;
  struct oct_dma_stats stats;
} oct_dma_dev_t;

typedef struct
{
  vlib_dma_batch_t batch; /* must be first */
  oct_dma_dev_t *dmadev;
  u32 config_heap_index;
  u32 max_transfers;
  u32 config_index;
  union
  {
    struct
    {
      u32 barrier_before_last : 1;
      u32 sw_fallback : 1;
    };
    u32 features;
  };
  CLIB_CACHE_LINE_ALIGN_MARK (descriptors);
  oct_dpi_inst_hdr_t descs[0];
} oct_dma_batch_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 is_pci_addr_configured : 1;
  u32 is_name_configured : 1;
  u8 *name;
  oct_dma_batch_t batch_template;
  u32 alloc_size;
  u32 max_transfers;
  oct_dma_batch_t **freelist;
  u8 numa;
} oct_dma_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  oct_dma_dev_t *dmadev; /* dma device used by this thread */
  oct_dma_batch_t **pending_batches;
} oct_dma_thread_t;

typedef struct
{
  oct_dma_dev_t **dmadevs;
  oct_dma_thread_t *dma_threads;
  oct_dma_config_t *dma_config_heap;
  uword *dma_config_heap_handle_by_config_index;
  clib_spinlock_t lock;
  int n_dmadev;
  u8 started;
} oct_dma_main_t;

vnet_dev_rv_t oct_init_dma_backend (vlib_main_t *vm, vnet_dev_t *dev);
vnet_dev_rv_t oct_dma_dev_setup (oct_dma_dev_t *odma);
vnet_dev_rv_t oct_dma_dev_start (oct_dma_dev_t *odma);
void oct_dma_assign_dmadevs (vlib_main_t *vm);

extern oct_dma_main_t oct_dma_main;
#endif
