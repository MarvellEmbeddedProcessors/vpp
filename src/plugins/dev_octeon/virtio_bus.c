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

oct_dev_bus_virtio_device_data_t *
oct_get_bus_virtio_device_data (vnet_dev_t *dev)
{
  return (void *) dev->bus_data;
}

static int
oct_dev_bus_virtio_device_id_to_virtio_id (u32 *addr, char *str)
{
  unformat_input_t input;
  uword rv;
  unformat_init_string (&input, str, strlen (str));

  rv =
    unformat (&input, "virtio" VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "%u", addr);
  unformat_free (&input);
  return rv;
}

static void *
oct_dev_bus_virtio_get_device_info (vlib_main_t *vm, char *device)
{
  oct_dev_bus_virtio_device_info_t *info;
  u32 device_id = 0;

  if (oct_dev_bus_virtio_device_id_to_virtio_id (&device_id, device) == 0)
    return 0;

  info = clib_mem_alloc (sizeof (oct_dev_bus_virtio_device_info_t));
  info->virtio_id = device_id;
  info->vendor_id = 0x177d;
  info->device_id = OCT_VIRTIO_DEVICE_ID;

  return info;
}

static void
oct_dev_bus_virtio_free_device_info (vlib_main_t *vm, void *dev_info)
{
  clib_mem_free (dev_info);
}

static vnet_dev_rv_t
oct_dev_bus_virtio_dev_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_dev_bus_virtio_device_info_t *info;
  oct_dev_bus_virtio_device_data_t *pd = oct_get_bus_virtio_device_data (dev);

  if ((info = oct_dev_bus_virtio_get_device_info (vm, dev->device_id)) == 0)
    return VNET_DEV_ERR_INVALID_DEVICE_ID;

  dev->numa_node = 0;
  dev->va_dma = 1;
  pd->virtio_dev.device_id = info->device_id;
  pd->virtio_dev.vendor_id = info->vendor_id;
  pd->virtio_dev.virtio_id = info->virtio_id;

  clib_mem_free (info);

  return VNET_DEV_OK;
}

static void
oct_bus_virtio_dev_close (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static u8 *
format_oct_virtio_device_info (u8 *s, va_list *args)
{
  va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  oct_dev_bus_virtio_device_data_t *pdd = oct_get_bus_virtio_device_data (dev);

  s = format (s, "Virtio ID is %u", pdd->virtio_dev.device_id);

  return s;
}

static u8 *
format_oct_virtio_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  oct_dev_bus_virtio_device_data_t *pdd;

  pdd = oct_get_bus_virtio_device_data (dev);
  return format (s, "virtio/%u", pdd->virtio_dev.virtio_id);
}

VNET_DEV_REGISTER_BUS (virtio) = {
  .name = "virtio",
  .device_data_size = sizeof (oct_dev_bus_virtio_device_info_t),
  .ops = {
    .device_open = oct_dev_bus_virtio_dev_open,
    .device_close = oct_bus_virtio_dev_close,
    .get_device_info = oct_dev_bus_virtio_get_device_info,
    .free_device_info = oct_dev_bus_virtio_free_device_info,
    .dma_mem_alloc_fn = NULL,
    .dma_mem_free_fn = NULL,
    .format_device_info = format_oct_virtio_device_info,
    .format_device_addr = format_oct_virtio_device_addr,
  },
};
