/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>
#include <vlib/physmem.h>

#include <dev_octeon/octeon.h>
#include <dev_octeon/dma.h>

#define PFN_MASK_SIZE 8

extern vlib_node_registration_t oct_dma_node;
oct_dma_main_t oct_dma_main = { 0 };

vnet_dev_rv_t
oct_dma_dev_setup_hdr (oct_dma_dev_t *odma)
{
  struct oct_dpi_conf *dpi_conf = &odma->conf;
  union oct_dpi_instr_cmd *header;
  u16 max_desc;
  u32 size;
  int i;

  header = (union oct_dpi_instr_cmd *) &dpi_conf->cmd.u;

  header->cn10k.pt = DPI_HDR_PT_ZBW_CA;

  header->cn10k.xtype = DPI_XTYPE_INTERNAL_ONLY;
  header->cn10k.lport = 0;
  header->cn10k.fport = 0;
  header->cn10k.pvfe = 0;

  max_desc = OCT_DPI_MAX_DESC;

  size = (max_desc * sizeof (uint8_t) * OCT_DPI_COMPL_OFFSET);
  dpi_conf->c_desc.compl_ptr = plt_zmalloc (size, 0);

  if (dpi_conf->c_desc.compl_ptr == NULL)
    {
      plt_err ("Failed to allocate for comp_data");
      return -ENOMEM;
    }

  for (i = 0; i < max_desc; i++)
    dpi_conf->c_desc.compl_ptr[i * OCT_DPI_COMPL_OFFSET] = OCT_DPI_REQ_CDATA;

  dpi_conf->c_desc.max_cnt = (max_desc - 1);

  return VNET_DEV_OK;
}

static int
oct_dma_stats_reset (oct_dma_dev_t *odma)
{
  struct oct_dpi_conf *dpi_conf;

  dpi_conf = &odma->conf;
  dpi_conf->completed_offset += dpi_conf->stats.completed;
  dpi_conf->stats = (struct oct_dma_stats){ 0 };

  return 0;
}

static int
oct_dma_chunk_pool_create (oct_dma_dev_t *odma, uint32_t nb_bufs,
			   uint32_t buf_sz)
{
  char pool_name[48];
  extern oct_plt_init_param_t oct_plt_init_param;
  u64 mem_start, mem_end, elem_addr;
  struct npa_pool_s npapool;
  struct npa_aura_s aura;
  u32 i;
  u64 total_sz;
  u64 roc_aura_handle;
  int rv;

  nb_bufs += (OCT_DPI_POOL_MAX_CACHE_SZ *
	      24); /* TODO: replace 24 with number of threads */
  buf_sz = PLT_ALIGN (buf_sz, ROC_ALIGN);
  total_sz = nb_bufs * buf_sz;

  snprintf (pool_name, sizeof (pool_name), "oct_dma_chunk_pool%d",
	    odma->dev->index);

  mem_start = (u64) oct_plt_init_param.oct_plt_zmalloc (total_sz, ROC_ALIGN);
  if (!mem_start)
    {
      clib_warning ("Failed to allocate physmem for pool %s", pool_name);
      return -1;
    }

  clib_memset (&aura, 0, sizeof (struct npa_aura_s));
  clib_memset (&npapool, 0, sizeof (struct npa_pool_s));

  npapool.nat_align = 1;

  rv = roc_npa_pool_create (&roc_aura_handle, buf_sz, nb_bufs, &aura, &npapool,
			    0);
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

  odma->aura_handle = roc_aura_handle;

  return 0;
}

vnet_dev_rv_t
oct_dma_dev_start (oct_dma_dev_t *dmadev)
{
  struct oct_dpi_conf *dpi_conf;
  u32 chunks, nb_desc = 0;
  u32 queue_buf_sz;
  int j, rc = 0;
  void *chunk;

  dmadev->total_pnum_words = 0;

  if (oct_dma_dev_setup_hdr (dmadev))
    return VNET_DEV_ERR_INTERNAL;

  dpi_conf = &dmadev->conf;
  dpi_conf->c_desc.head = 0;
  dpi_conf->c_desc.tail = 0;
  dpi_conf->desc_idx = 0;
  for (j = 0; j < dpi_conf->c_desc.max_cnt + 1; j++)
    dpi_conf->c_desc.compl_ptr[j * OCT_DPI_COMPL_OFFSET] = OCT_DPI_REQ_CDATA;
  nb_desc += dpi_conf->c_desc.max_cnt + 1;
  oct_dma_stats_reset (dmadev);
  dpi_conf->completed_offset = 0;

  queue_buf_sz = OCT_DPI_QUEUE_BUF_SIZE_V2;
  /* Max block size allowed by cnxk mempool driver is (128 * 1024).
   * Block size = elt_size + mp->header + mp->trailer.
   *
   * Note from cn9k mempool driver:
   * In cn9k additional padding of 128 bytes is added to mempool->trailer to
   * ensure that the element size always occupies odd number of cachelines
   * to ensure even distribution of elements among L1D cache sets.
   */
  if (!roc_model_is_cn10k ())
    queue_buf_sz = OCT_DPI_QUEUE_BUF_SIZE_V2 - 128;

  chunks = OCT_DPI_CHUNKS_FROM_DESC (queue_buf_sz, nb_desc);
  rc = oct_dma_chunk_pool_create (dmadev, chunks, queue_buf_sz);
  if (rc < 0)
    {
      plt_err ("DMA pool configure failed err = %d", rc);
      goto error;
    }

  chunk = (void *) roc_npa_aura_op_alloc (dmadev->aura_handle, 0);
  if (!chunk)
    {
      plt_err ("DMA failed to get chunk pointer err = %d", rc);
      rc = -1;
      goto error;
    }
  u64 aura = roc_npa_aura_handle_to_aura (dmadev->aura_handle);

  rc = roc_dpi_configure_v2 (&dmadev->rdpi, queue_buf_sz, aura, (u64) chunk);
  if (rc < 0)
    {
      plt_err ("DMA configure failed err = %d", rc);
      goto error;
    }
  dmadev->chunk_base = chunk;
  dmadev->chunk_head = 0;
  dmadev->chunk_size_m1 = (queue_buf_sz >> 3) - 2;

  dmadev->max_transfers = 1024;
  dmadev->max_transfer_size = (64 * 1024);

  roc_dpi_enable (&dmadev->rdpi);

  return VNET_DEV_OK;
error:
  return VNET_DEV_ERR_INTERNAL;
}

static void
oct_dma_dev_lock (oct_dma_dev_t *odma)
{
  u8 expected = 0;

  if (odma->n_threads < 2)
    return;

  /* dma device is used by multiple threads so we need to lock it */
  while (!__atomic_compare_exchange_n (&odma->lock, &expected,
				       /* desired */ 1, /* weak */ 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&odma->lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      expected = 0;
    }
}

static void
oct_dma_dev_unlock (oct_dma_dev_t *odma)
{
  if (odma->n_threads < 2)
    return;

  __atomic_store_n (&odma->lock, 0, __ATOMIC_RELEASE);
}

static vlib_dma_batch_t *
oct_dma_batch_new (vlib_main_t *vm, struct vlib_dma_config_data *cd)
{
  oct_dma_main_t *odm = &oct_dma_main;
  oct_dma_config_t *odc;
  oct_dma_batch_t *b;

  odc = vec_elt_at_index (odm->dma_config_heap,
			  cd->private_data + vm->thread_index);

  if (vec_len (odc->freelist) > 0)
    b = vec_pop (odc->freelist);
  else
    {
      clib_spinlock_lock (&odm->lock);
      b = vlib_physmem_alloc (vm, odc->alloc_size);
      clib_spinlock_unlock (&odm->lock);
      /* if no free space in physmem, force quit */
      ASSERT (b != NULL);
      *b = odc->batch_template;
      b->max_transfers = odc->max_transfers;
    }

  return &b->batch;
}

static int
oct_dma_check_dmadev (oct_dma_dev_t *odma, vlib_dma_config_data_t *cd)
{
  vlib_dma_config_t supported_cfg = {
    .barrier_before_last = 1,
    .sw_fallback = 1,
  };

  if (!odma)
    {
      clib_warning ("no available dma device");
      return 1;
    }

  if (cd->cfg.features & ~supported_cfg.features)
    {
      clib_warning ("unsupported feature requested");
      return 1;
    }

  if (cd->cfg.max_transfers > odma->max_transfers)
    {
      clib_warning ("transfer number (%u) too big", cd->cfg.max_transfers);
      return 1;
    }

  if (cd->cfg.max_transfer_size > odma->max_transfer_size)
    {
      clib_warning ("transfer size (%u) too big", cd->cfg.max_transfer_size);
      return 1;
    }
  return 0;
}

static_always_inline void
oct_dma_alloc_dma_batch (vlib_main_t *vm, oct_dma_config_t *odc)
{
  oct_dma_batch_t *b;
  b = vlib_physmem_alloc (vm, odc->alloc_size);
  /* if no free space in physmem, force quit */
  ASSERT (b != NULL);
  *b = odc->batch_template;
  b->max_transfers = odc->max_transfers;

  vec_add1 (odc->freelist, b);
}

void
dpi_cpy_scalar (uint64_t *src, uint64_t *dst, uint8_t n)
{
  uint8_t i;

  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

static_always_inline void
oct_dma_batch_fallback (vlib_main_t *vm, oct_dma_batch_t *b,
			oct_dma_dev_t *odma)
{
  for (u16 i = 0; i < b->batch.n_enq; i++)
    {
      oct_dpi_inst_hdr_t *desc = &b->descs[i];
      clib_memcpy_fast ((void *) desc->dst, (void *) desc->src,
			desc->src_length);
    }
  odma->submitted++;
  return;
}

static __plt_always_inline void
__dpi_cpy_scalar (uint64_t *src, uint64_t *dst, uint8_t n)
{
  uint8_t i;

  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

static __plt_always_inline int
__dpi_queue_write_single (oct_dma_dev_t *dpi, uint64_t *cmd)
{
  uint64_t *ptr = dpi->chunk_base;

  /* Check if command fits in the current chunk. */
  if (dpi->chunk_head + OCT_DPI_DW_PER_SINGLE_CMD < dpi->chunk_size_m1)
    {
      ptr += dpi->chunk_head;

      __dpi_cpy_scalar (cmd, ptr, OCT_DPI_DW_PER_SINGLE_CMD);
      dpi->chunk_head += OCT_DPI_DW_PER_SINGLE_CMD;
    }
  else
    {
      uint64_t *new_buff = NULL;
      int count;

      new_buff = (u64 *) roc_npa_aura_op_alloc (dpi->aura_handle, 0);
      if (!new_buff)
	{
	  clib_warning ("Failed to alloc next buffer from NPA");
	  return -ENOSPC;
	}

      /*
       * Figure out how many cmd words will fit in the current chunk
       * and copy them.
       */
      count = dpi->chunk_size_m1 - dpi->chunk_head;
      ptr += dpi->chunk_head;

      __dpi_cpy_scalar (cmd, ptr, count);

      ptr += count;
      *ptr = (uint64_t) new_buff;
      ptr = new_buff;

      /* Copy the remaining cmd words to new chunk. */
      __dpi_cpy_scalar (cmd + count, ptr, OCT_DPI_DW_PER_SINGLE_CMD - count);

      dpi->chunk_base = new_buff;
      dpi->chunk_head = OCT_DPI_DW_PER_SINGLE_CMD - count;
    }

  return 0;
}

int
oct_dma_batch_submit (vlib_main_t *vm, struct vlib_dma_batch *vb)
{
  oct_dma_main_t *odm = &oct_dma_main;
  oct_dma_batch_t *b = (oct_dma_batch_t *) vb;
  oct_dma_dev_t *dmadev = b->dmadev;
  struct oct_dpi_conf *dpi_conf = &dmadev->conf;
  ;
  int i;

  if (PREDICT_FALSE (vb->n_enq == 0))
    {
      vec_add1 (odm->dma_config_heap[b->config_heap_index].freelist, b);
      return 0;
    }

  oct_dma_dev_lock (dmadev);

  for (i = 0; i < vb->n_enq; i++)
    {
      oct_dpi_inst_hdr_t *desc = &b->descs[i];
      uint8_t *comp_ptr;

      if (unlikely (((dpi_conf->c_desc.tail + 1) & dpi_conf->c_desc.max_cnt) ==
		    dpi_conf->c_desc.head))
	return -ENOSPC;
      comp_ptr = &dpi_conf->c_desc
		    .compl_ptr[dpi_conf->c_desc.tail * OCT_DPI_COMPL_OFFSET];
      OCT_DPI_STRM_INC (dpi_conf->c_desc, tail);

      desc->cmd = dpi_conf->cmd.u | (1U << 6) | 1U;
      desc->compl_ptr = (uint64_t) comp_ptr;
      desc->flags = (1UL << 47) | ((desc->flags & (UINT64_C (1) << 3)) << 43);
      desc->reserved_word3 = 0;
      desc->src_length = desc->src_length;
      desc->src = desc->src;
      desc->dst_length = desc->src_length;
      desc->dst = desc->dst;

      __dpi_queue_write_single (dmadev, (u64 *) desc);

      dmadev->total_pnum_words += OCT_DPI_DW_PER_SINGLE_CMD;
    }

  asm volatile ("dmb st" : : : "memory");
  plt_write64 (dmadev->total_pnum_words, dmadev->rdpi.rbase + DPI_VDMA_DBELL);

  dmadev->total_pnum_words = 0;
  dmadev->stats.submitted++;
  dmadev->n_enq++;

  oct_dma_dev_unlock (dmadev);
  vec_add1 (odm->dma_threads[vm->thread_index].pending_batches, b);
  vlib_node_set_interrupt_pending (vm, oct_dma_node.index);
  return 1;
}

static int
oct_dma_config_add_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  oct_dma_main_t *odm = &oct_dma_main;
  oct_dma_config_t *odc;
  u32 index, n_threads = vlib_get_n_threads ();

  odm->started = 1;

  vec_validate (odm->dma_config_heap_handle_by_config_index, cd->config_index);
  index = heap_alloc_aligned (
    odm->dma_config_heap, n_threads, CLIB_CACHE_LINE_BYTES,
    odm->dma_config_heap_handle_by_config_index[cd->config_index]);

  cd->batch_new_fn = oct_dma_batch_new;
  cd->private_data = index;

  for (u32 thread = 0; thread < n_threads; thread++)
    {
      oct_dma_batch_t *odb;
      vlib_dma_batch_t *b;
      odc = vec_elt_at_index (odm->dma_config_heap, index + thread);

      /* size of physmem allocation for this config */
      odc->max_transfers = cd->cfg.max_transfers;
      odc->alloc_size = sizeof (oct_dma_batch_t) +
			sizeof (oct_dpi_inst_hdr_t) * (odc->max_transfers + 1);
      /* fill batch template */
      odb = &odc->batch_template;
      odb->dmadev = odm->dma_threads[thread].dmadev;
      if (oct_dma_check_dmadev (odb->dmadev, cd))
	return 0;

      clib_warning ("config %d in thread %d ", cd->config_index, thread);
      odb->config_heap_index = index + thread;
      odb->config_index = cd->config_index;
      odb->batch.callback_fn = cd->cfg.callback_fn;
      odb->features = cd->cfg.features;
      b = &odb->batch;
      b->stride = sizeof (oct_dpi_inst_hdr_t);
      b->src_ptr_off = STRUCT_OFFSET_OF (oct_dma_batch_t, descs[0].src);
      b->dst_ptr_off = STRUCT_OFFSET_OF (oct_dma_batch_t, descs[0].dst);
      b->size_off = STRUCT_OFFSET_OF (oct_dma_batch_t, descs[0].src_length);
      b->submit_fn = oct_dma_batch_submit;
      clib_warning ("config %d in thread %d src/dst/size offset %d-%d-%d",
		    cd->config_index, thread, b->src_ptr_off, b->dst_ptr_off,
		    b->size_off);

      /* allocate dma batch in advance */
      for (u32 index = 0; index < cd->cfg.max_batches; index++)
	oct_dma_alloc_dma_batch (vm, odc);
    }
  return 1;
}

static void
oct_dma_config_del_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  clib_warning ("OCTEON_DMA: oct_dma_config_del_fn");
}

static int
oct_dma_map_physmem_fn (vlib_main_t *vm, void *addr)
{
  clib_warning ("OCTEON_DMA: oct_dma_map_physmem_fn");
  vm = vlib_get_main ();
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  linux_vfio_main_t *lvm = &vfio_main;
  struct vfio_iommu_type1_dma_map dm = { 0 };
  uword log2_page_size = vpm->pmalloc_main->def_log2_page_sz;

  if (lvm->container_fd == -1)
    {
      clib_warning ("No cointainer fd");
      return -1;
    }

  dm.argsz = sizeof (struct vfio_iommu_type1_dma_map);
  dm.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
  dm.vaddr = (u64) addr;
  dm.size = 1ULL << log2_page_size;
  dm.iova = dm.vaddr;

  clib_warning ("map DMA page: va:0x%lx iova:%lx "
		"size:0x%lx",
		dm.vaddr, dm.iova, dm.size);

  if (ioctl (lvm->container_fd, VFIO_IOMMU_MAP_DMA, &dm) == -1)
    {
      clib_warning ("map DMA page: va:0x%lx iova:%lx "
		    "size:0x%lx failed, error %s (errno %d)",
		    dm.vaddr, dm.iova, dm.size, strerror (errno), errno);
      return -1;
    }

  return 0;
}

u8 *
format_oct_dma_info (u8 *s, va_list *args)
{
  oct_dma_main_t *odm = &oct_dma_main;
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  oct_dma_dev_t *odma;

  odma = odm->dma_threads[vm->thread_index].dmadev;
  s = format (s, "thread %d dma request %-16lld hw %-16lld", vm->thread_index,
	      odma->stats.submitted, odma->stats.completed);
  return s;
}

vlib_dma_backend_t oct_dma_backend = {
  .name = "OCTEON DMA",
  .config_add_fn = oct_dma_config_add_fn,
  .config_del_fn = oct_dma_config_del_fn,
  .map_physmem_fn = oct_dma_map_physmem_fn,
  .info_fn = format_oct_dma_info,
};

vnet_dev_rv_t
oct_init_dma_backend (vlib_main_t *vm, vnet_dev_t *dev)
{
  clib_error_t *error;

  if (oct_dma_main.lock == 0)
    clib_spinlock_init (&(oct_dma_main.lock));

  if ((error = vlib_dma_register_backend (vm, &oct_dma_backend)))
    return VNET_DEV_ERR_INTERNAL;

  return VNET_DEV_OK;
}

void
oct_dma_assign_dmadevs (vlib_main_t *vm)
{
  oct_dma_main_t *dm = &oct_dma_main;
  oct_dma_dev_t *dmadev;
  u16 n_threads;

  vec_validate (dm->dma_threads, vlib_get_n_threads () - 1);

  if (dm->n_dmadev == 0)
    {
      // Add log
      clib_warning ("No DMA device found");
      return;
    }

  if (dm->n_dmadev >= vlib_get_n_threads ())
    n_threads = 1;
  else
    n_threads = vlib_get_n_threads () % dm->n_dmadev ?
		  vlib_get_n_threads () / dm->n_dmadev + 1 :
		  vlib_get_n_threads () / dm->n_dmadev;

  for (int i = 0; i < vlib_get_n_threads (); i++)
    {
      vlib_main_t *tvm = vlib_get_main_by_index (i);
      dmadev = dm->dmadevs[i / n_threads];
      dm->dma_threads[i].dmadev = dmadev;
      dmadev->n_threads = n_threads;
      clib_warning ("Assigning dma device to thread %u (numa %u)", i,
		    tvm->numa_node);
    }
}

static uword
oct_dma_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame)
{
  oct_dma_main_t *odm = &oct_dma_main;
  oct_dma_thread_t *t = vec_elt_at_index (odm->dma_threads, vm->thread_index);
  u32 n_pending = 0, n = 0;
  u8 glitch = 0, status;

  if (!t->pending_batches)
    return 0;

  n_pending = vec_len (t->pending_batches);

  for (u32 i = 0; i < n_pending; i++)
    {
      oct_dma_batch_t *b = t->pending_batches[i];
      oct_dma_dev_t *dmadev = b->dmadev;
      u16 n_enq = b->batch.n_enq;
      oct_dpi_inst_hdr_t *desc = &b->descs[n_enq - 1];
      oct_dma_desc_t *c_desc = &dmadev->conf.c_desc;

      status = *(u8 *) desc->compl_ptr;
      if (status == 0 && !glitch)
	{
	  if (b->batch.callback_fn)
	    b->batch.callback_fn (vm, &b->batch);
	  vec_add1 (odm->dma_config_heap[b->config_heap_index].freelist, b);
	  oct_dma_dev_lock (dmadev);
	  if (status == 0)
	    {
	      dmadev->n_enq--;
	      dmadev->stats.completed++;
	    }
	  else
	    dmadev->sw_fallback++;

	  OCT_DPI_STRM_INC_N (*c_desc, head, n_enq);
	  oct_dma_dev_unlock (dmadev);
	  b->batch.n_enq = 0;
	}
      else if (status == OCT_DPI_REQ_CDATA)
	{
	  glitch = 1 & b->barrier_before_last;
	  t->pending_batches[n++] = b;
	}
      else if (!glitch)
	{
	  /* fallback to software if exception happened */
	  oct_dma_batch_fallback (vm, b, dmadev);
	  glitch = 1 & b->barrier_before_last;
	}
      else
	{
	  t->pending_batches[n++] = b;
	}
    }

  vec_set_len (t->pending_batches, n);

  if (n)
    {
      vlib_node_set_interrupt_pending (vm, oct_dma_node.index);
    }

  return n_pending - n;
}

VLIB_REGISTER_NODE (oct_dma_node) = {
  .function = oct_dma_node_fn,
  .name = "octeon-dma",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = 4,
};
