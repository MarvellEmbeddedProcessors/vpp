/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Marvell.
 */
#ifndef _VIRTIO_BUS_H_
#define _VIRTIO_BUS_H_
#include <vnet/dev/dev.h>

typedef struct
{
  u16 device_id;
  u16 vendor_id;
  u16 virtio_id;
  u16 reserved;
} oct_dev_bus_virtio_device_info_t;

typedef struct
{
  oct_dev_bus_virtio_device_info_t virtio_dev;
} oct_dev_bus_virtio_device_data_t;

oct_dev_bus_virtio_device_data_t *
oct_get_bus_virtio_device_data (vnet_dev_t *dev);

#endif //_VIRTIO_BUS_H
