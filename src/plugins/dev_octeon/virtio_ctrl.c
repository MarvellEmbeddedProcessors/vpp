/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/mem.h>
#include <dev_octeon/oct_virtio.h>

#define OCT_VIRTIO_MAX_WRKS 24

extern oct_virtio_main_t *oct_virtio_main;
extern oct_virtio_port_map_t *virtio_port_map;
extern oct_virtio_per_thread_data_t *oct_virt_thread_data;

VLIB_REGISTER_LOG_CLASS (oct_virt_log, static) = {
  .class_name = "octeon",
  .subclass_name = "virtio_ctl",
};

int
oct_virtio_vlib_buffer_free (u16 devid, void *buffs[], u16 nb_buffs)
{
  int i = 0;
  u16 hdr_len;
  u32 bi[nb_buffs];
  vlib_buffer_t *b[nb_buffs];
  u32 cpu_id = clib_get_current_cpu_id ();
  vlib_main_t *vm = vlib_get_first_main ();
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;

  hdr_len = ptd[cpu_id].q_map[devid].virtio_hdr_sz;
  for (i = 0; i < nb_buffs; i++)
    b[i] = oct_virt_to_bp (buffs[i], hdr_len);

  vlib_get_buffer_indices (vm, b, bi, nb_buffs);
  vlib_buffer_free_no_next (vm, bi, nb_buffs);

  return 0;
}

int
oct_virtio_vlib_buffer_alloc (u16 devid, void *buffs[], u16 nb_buffs)
{
  int i = 0;
  u16 hdr_len;
  u16 allocated;
  u32 vbuf_idxs[nb_buffs];
  vlib_buffer_t *b[nb_buffs];
  u32 cpu_id = clib_get_current_cpu_id ();
  vlib_main_t *vm = vlib_get_first_main ();
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;

  hdr_len = ptd[cpu_id].q_map[devid].virtio_hdr_sz;
  allocated = vlib_buffer_alloc (vm, vbuf_idxs, nb_buffs);
  if (allocated != nb_buffs)
    {
      vlib_buffer_free_no_next (vm, vbuf_idxs, allocated);
      return -1;
    }
  vlib_get_buffers (vm, vbuf_idxs, b, nb_buffs);

  for (i = 0; i < nb_buffs; i++)
    buffs[i] = oct_bp_to_virt (b[i], hdr_len);

  return 0;
}

int
oct_virtio_mac_addr_add (u16 virtio_devid, struct virtio_net_ctrl_mac *mac_tbl,
			 u8 type)
{
  /* Not supported */
  return 0;
}

int
oct_virtio_mac_addr_set (u16 virtio_devid, u8 *mac)
{
  /* Not supported */
  return 0;
}

int
oct_virtio_configure_allmulti (u16 virtio_devid, u8 enable)
{
  /* Not supported */
  return 0;
}

int
oct_virtio_configure_promisc (u16 virtio_devid, u8 enable)
{
  /* Not supported */
  return 0;
}

static_always_inline void
oct_virtio_clear_lcore_queue_mapping (u16 virtio_devid)
{
  u32 cpu_id = 0;
  oct_virtio_main_t *ovm = oct_virtio_main;
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;
  u64 wrkr_cpu_mask = ovm->wrkr_cpu_mask;

  ovm->netdev_map &= ~(DAO_BIT (virtio_devid));
  while (wrkr_cpu_mask)
    {
      if (!(wrkr_cpu_mask & (1 << cpu_id)))
	{
	  cpu_id++;
	  continue;
	}
      ptd[cpu_id].netdev_map &= ~(DAO_BIT (virtio_devid));
      ptd[cpu_id].q_map[virtio_devid].qmap = 0;
      wrkr_cpu_mask &= ~(1 << cpu_id);
      cpu_id++;
    }

  ovm->netdev_qp_count[virtio_devid] = 0;
}

static_always_inline u16
oct_virtio_netdev_hdrlen_get (u16 virtio_devid)
{
  struct virtio_net_hdr vnet_hdr;
  u16 virtio_hdr_sz = 0;
  u64 feature_bits = 0;

  feature_bits = dao_virtio_netdev_feature_bits_get (virtio_devid);

  if (feature_bits & DAO_BIT_ULL (VIRTIO_NET_F_HASH_REPORT))
    virtio_hdr_sz = offsetof (struct virtio_net_hdr, padding_reserved) +
		    sizeof (vnet_hdr.padding_reserved);
  else
    virtio_hdr_sz = offsetof (struct virtio_net_hdr, num_buffers) +
		    sizeof (vnet_hdr.num_buffers);
  return virtio_hdr_sz;
}

static_always_inline int
oct_virtio_setup_worker_queue_mapping (u16 virtio_devid, u16 virt_q_count)
{
  u32 cpu_id = 0;
  u16 virt_rx_q, q_id;
  oct_virtio_main_t *ovm = oct_virtio_main;
  u64 wrkr_cpu_mask = ovm->wrkr_cpu_mask;
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;
  u16 virtio_hdr_sz = 0;

  virtio_hdr_sz = oct_virtio_netdev_hdrlen_get (virtio_devid);
  ptd[ptd->service_core].q_map[virtio_devid].virtio_hdr_sz = virtio_hdr_sz;

  virt_rx_q = virt_q_count / 2;
  q_id = 0;
  for (q_id = 0; q_id < virt_rx_q && ovm->wrkr_cpu_mask; q_id++)
    {
      while (!(wrkr_cpu_mask & DAO_BIT_ULL (cpu_id)))
	cpu_id++;

      ptd[cpu_id].q_map[virtio_devid].qmap |= DAO_BIT_ULL (q_id);
      ptd[cpu_id].q_map[virtio_devid].virtio_hdr_sz = virtio_hdr_sz;
      CLIB_MEMORY_BARRIER ();
      ptd[cpu_id].netdev_map |= DAO_BIT (virtio_devid);

      wrkr_cpu_mask &= ~DAO_BIT_ULL (cpu_id);
      cpu_id++;
      if (!wrkr_cpu_mask)
	{
	  cpu_id = 0;
	  wrkr_cpu_mask = ovm->wrkr_cpu_mask;
	}
    }

  ovm->netdev_qp_count[virtio_devid] = virt_q_count / 2;
  CLIB_MEMORY_BARRIER ();
  ovm->netdev_map |= DAO_BIT (virtio_devid);

  return 0;
}

int
oct_virtio_mq_configure (u16 virtio_devid, bool qmap_set)
{
  u16 virt_q_count;

  oct_virtio_clear_lcore_queue_mapping (virtio_devid);
  if (!qmap_set)
    return 0;

  virt_q_count = dao_virtio_netdev_queue_count (virtio_devid);
  log_info ("virtio_dev=%u: virt_q_count=%u\n", virtio_devid, virt_q_count);
  if (virt_q_count <= 0 || virt_q_count & 0x1 ||
      virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1))
    {
      log_err ("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid,
	       virt_q_count);
      return -EIO;
    }

  oct_virtio_setup_worker_queue_mapping (virtio_devid, virt_q_count);

  return 0;
}

int
oct_virito_rss_reta_configure (u16 virtio_devid,
			       struct virtio_net_ctrl_rss *rss)
{
  u16 virt_q_count;

  oct_virtio_clear_lcore_queue_mapping (virtio_devid);

  if (rss == NULL)
    return 0;

  /* Get active virt queue count */
  virt_q_count = dao_virtio_netdev_queue_count (virtio_devid);

  if (virt_q_count <= 0 || virt_q_count & 0x1 ||
      virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1))
    {
      log_err ("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid,
	       virt_q_count);
      return -EIO;
    }

  oct_virtio_setup_worker_queue_mapping (virtio_devid, virt_q_count);

  return 0;
}

int
oct_virtio_dev_status_cb (u16 virtio_devid, u8 status)
{
  u16 virt_q_count;

  log_debug ("[%s] virtio_dev=%d: status=%s\n", __func__, virtio_devid,
	     dao_virtio_dev_status_to_str (status));

  switch (status)
    {
    case VIRTIO_DEV_RESET:
    case VIRTIO_DEV_NEEDS_RESET:
      virtio_port_map[virtio_devid].state = 0;
      CLIB_MEMORY_BARRIER ();
      oct_virtio_clear_lcore_queue_mapping (virtio_devid);
      break;
    case VIRTIO_DEV_DRIVER_OK:

      /* Get active virt queue count */
      virt_q_count = dao_virtio_netdev_queue_count (virtio_devid);

      if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	  virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1))
	{
	  log_err ("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid,
		   virt_q_count);
	  return -EIO;
	}

      oct_virtio_setup_worker_queue_mapping (virtio_devid, virt_q_count);
      virtio_port_map[virtio_devid].state = 1;
      CLIB_MEMORY_BARRIER ();
      break;
    default:
      break;
    }

  return 0;
}

static_always_inline void
oct_virtio_desc_process (u64 netdev_map, u16 *netdev_qp_count)
{
  u16 dev_id = 0;

  while (netdev_map)
    {
      if (!(netdev_map & 0x1))
	{
	  netdev_map >>= 1;
	  dev_id++;
	  continue;
	}
      dao_virtio_net_desc_manage (dev_id, netdev_qp_count[dev_id]);
      netdev_map >>= 1;
      dev_id++;
    }
}

void
virtio_ctrl_thread_fn (void *args)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) args;
  oct_virtio_main_t *ovm = oct_virtio_main;
  oct_virtio_per_thread_data_t *ptd = oct_virt_thread_data;
  u32 cpu_id = clib_get_current_cpu_id ();

  vlib_worker_thread_init (w);
  ovm->wrkr_cpu_mask |= DAO_BIT (cpu_id);
  ptd->service_core = cpu_id;
  /* Wait till Octeon virtio DAO lib init is complete */
  while (!ovm || !ovm->dao_lib_initialized)
    CLIB_PAUSE ();

  /* Assign DMA devices per lcore */
  dao_pal_thread_init (cpu_id);
  ovm->wrkr_cpu_mask &= ~(DAO_BIT (cpu_id));

  while (1)
    {
      /* Process virtio descriptors */
      oct_virtio_desc_process (ovm->netdev_map, ovm->netdev_qp_count);

      /* Flush and submit DMA ops */
      dao_dma_flush_submit ();
    }
}

VLIB_REGISTER_THREAD (virtio_ctrl_thread_reg, static) = {
  .name = "virtio-ctrl",
  .short_name = "virt-ctl",
  .function = virtio_ctrl_thread_fn,
  .no_data_structure_clone = 1,
};
