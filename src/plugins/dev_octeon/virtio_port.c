/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_octeon/oct_virtio.h>

#define VIRTO_NETDEV_SPEED_NUM_UNKNOWN UINT32_MAX /**< Unknown */
#define OCT_VIRTIO_NIX_RSS_KEY_LEN     48

static u64 vchan_bitmap[2] = { 0 };
extern oct_virtio_port_map_t *virtio_port_map;

VLIB_REGISTER_LOG_CLASS (oct_virt_log, static) = {
  .class_name = "octeon",
  .subclass_name = "virtio_port",
};

int
oct_virtio_dma_vchan_id_allocate (void)
{
  int idx;
  int pos;

  for (int i = 0; i < DAO_VIRTIO_DEV_MAX; i++)
    {
      idx = i / 64;
      pos = i % 64;
      if (!(vchan_bitmap[idx] & (1ULL << pos)))
	{
	  vchan_bitmap[idx] |= (1ULL << pos);
	  return i;
	}
    }
  return -1;
}

void
oct_virtio_dma_vchan_id_free (int id)
{
  int idx;
  int pos;

  if (id >= 0 && id < DAO_VIRTIO_DEV_MAX)
    {
      idx = id / 64;
      pos = id % 64;
      vchan_bitmap[idx] &= ~(1ULL << pos);
    }
}

vnet_dev_rv_t
oct_virtio_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  int rrv;
  u16 virtio_devid;
  u8 buffer_pool_index;
  vlib_buffer_pool_t *bp;
  vnet_dev_t *dev = port->dev;
  struct dao_virtio_netdev_conf netdev_conf = { 0 };
  oct_virtio_device_t *ovd = vnet_dev_get_data (dev);
  oct_virtio_port_t *ovp = vnet_dev_get_port_data (port);

  buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  virtio_devid = ovd->virtio_id;

  netdev_conf.pem_devid = ovd->pem_devid;
  netdev_conf.flags |= DAO_VIRTIO_NETDEV_EXTBUF;
  netdev_conf.dataroom_size = bp->data_size;
  netdev_conf.reta_size = VIRTIO_NET_RSS_RETA_SIZE;
  netdev_conf.link_info.status = 0;
  netdev_conf.link_info.speed = VIRTO_NETDEV_SPEED_NUM_UNKNOWN;
  netdev_conf.link_info.duplex = 0xFF;
  netdev_conf.hash_key_size = OCT_VIRTIO_NIX_RSS_KEY_LEN;
  netdev_conf.dma_vchan = oct_virtio_dma_vchan_id_allocate ();
  memcpy (netdev_conf.mac, port->attr.hw_addr.eth_mac,
	  sizeof (netdev_conf.mac));
  log_debug ("port start: port %u, virtio_id %u, vchan_id %d\n", port->port_id,
	     virtio_devid, netdev_conf.dma_vchan);

  dao_pal_dma_vchan_setup (virtio_devid, netdev_conf.dma_vchan, NULL);
  /* Initialize virtio net device */
  rrv = dao_virtio_netdev_init (virtio_devid, &netdev_conf);
  if (rrv)
    {
      log_err ("[%s] dao_virtio_netdev_init failed \n", __func__);
      oct_virtio_dma_vchan_id_free (netdev_conf.dma_vchan);
      return VNET_DEV_ERR_INTERNAL;
    }
  ovp->vchan_id = netdev_conf.dma_vchan;

  return VNET_DEV_OK;
}

void
oct_virtio_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_virtio_device_t *ovd = vnet_dev_get_data (dev);
  oct_virtio_port_t *ovp = vnet_dev_get_port_data (port);

  log_debug ("clear data for virtio id %u\n", ovd->virtio_id);
  dao_virtio_netdev_fini (ovd->virtio_id);
  oct_virtio_dma_vchan_id_free (ovp->vchan_id);
}

void
oct_virt_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_state_changes_t changes = {};
  oct_virtio_device_t *ovd = vnet_dev_get_data (dev);
  u16 virtio_devid = ovd->virtio_id;

  if (ovd->status != virtio_port_map[virtio_devid].state)
    {
      changes.change.link_state = 1;
      changes.link_state = virtio_port_map[virtio_devid].state;
      ovd->status = virtio_port_map[virtio_devid].state;
    }
  else
    return;

  vnet_dev_port_state_change (vm, port, changes);
}

vnet_dev_rv_t
oct_virtio_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_virtio_device_t *ovd = vnet_dev_get_data (dev);
  struct dao_virtio_netdev_link_info link_info = { 0 };

  log_debug ("State up for virtio device %u\n", ovd->virtio_id);
  link_info.status = 0x1;
  link_info.duplex = 0xFF;
  link_info.speed = VIRTO_NETDEV_SPEED_NUM_UNKNOWN;
  dao_virtio_netdev_link_sts_update (ovd->virtio_id, &link_info);

  vnet_dev_poll_port_add (vm, port, 0.5, oct_virt_port_poll);

  return VNET_DEV_OK;
}

void
oct_virtio_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_virtio_device_t *ovd = vnet_dev_get_data (dev);
  struct dao_virtio_netdev_link_info link_info = { 0 };

  log_debug ("[%s] received dev stop port id %d virtio_id %u\n", __func__,
	     port->port_id, ovd->virtio_id);

  link_info.status = 0x0;
  link_info.duplex = 0xFF;
  link_info.speed = VIRTO_NETDEV_SPEED_NUM_UNKNOWN;
  dao_virtio_netdev_link_sts_update (ovd->virtio_id, &link_info);
  vnet_dev_poll_port_remove (vm, port, oct_virt_port_poll);
}
