# Octeon virtio device plugin for VPP  {#dev_octeon_virtio_doc}

## Overview

This plugin is a virtio device plugin for VPP, supporting packet input and output to
and from the HOST virtio interface over PCIe, with the Marvell OCTEON SoC operating
in endpoint mode.

This plugin uses DAO library to communicate with the HOST device. The DAO library
employs a platform device to transmit and receive data to and from the HOST device.
Platform devices aren't situated on standard buses such as PCI or USB, this plugin
enlists a virtual bus with VPP, identifying it as virtio.To enhance performance,
this plugin utilizes a dedicated core to transfer host descriptors to Octeon.

An alternate way for Host-OCTEON communication is using the SDP interface. The
primary difference is that SDP interfaces utilize NIX device bandwidth, thereby
limiting the device to 50Gbps when used in endpoint NIC mode. In contrast, by
using the Virtio plugin, OCTEON can function as a 100Gbps NIC.

## Supported SoC
- OCTEON-10

## Usage
The following steps demonstrate how you may bring up VPP with dev_octeon_virtio, on the
OCTEON platform.

### Setup

#### Configure DMA and NPA devices on OCTEON
-# Determine DMA/DPI device on OCTEON.
```
# lspci -d 177d:a080:0880
 0000:06:00.0 System peripheral: Cavium, Inc. Device a080
```
-# Bind and Create (2 + 2 * number of workers) DMA devices.
```
echo 0000:06:00.0 > /sys/bus/pci/devices/0000:06:00.0/driver/unbind
echo octeontx2-dpi > /sys/bus/pci/devices/0000:06:00.0/driver_override
echo 0000:06:00.0 > /sys/bus/pci/drivers_probe
echo 32 >/sys/bus/pci/devices/0000:06:00.0/sriov_numvfs

```
-# Determine NPA PCI on OCTEON and bind to vfio-pci.
```
#lspci -d 177d:a0fb:0880
0002:17:00.0 System peripheral: Cavium, Inc. Device a0fb (rev 54)

echo 0002:17:00.0 > /sys/bus/pci/devices/0002:17:00.0/driver/unbind
echo 177d a0fb > /sys/bus/pci/drivers/vfio-pci/new_id
echo 0002:17:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
```
-# Bind platform devices pem0-bar4-mem and dpi_sdp_regs to vfio-platform
```
echo "vfio-platform" | sudo tee "/sys/bus/platform/devices/*pem0-bar4-mem/driver_override" > /dev/null
echo "*pem0-bar4-mem" | sudo tee "/sys/bus/platform/drivers/vfio-platform/bind" > /dev/null
echo "vfio-platform" | sudo tee "/sys/bus/platform/devices/*dpi_sdp_regs/driver_override" > /dev/null
echo "*dpi_sdp_regs" | sudo tee "/sys/bus/platform/drivers/vfio-platform/bind" > /dev/null
Note: Replace * with actual runtime address attached with platform device.

```
### Launch VPP
VPP device bringup with dev_octeon_virtio is possible either through vppctl commands or
startup conf.This plugin takes following device arguments for the first device attach.And
arguments passed on next devices are ignored.

nb_virtio - Max number of virtio devices will be configured.
dma - List of all DMA devices.
misc - List of all miscellaneous devices (example NPA device).

DMA devices needed is calculated as:

2 (for control) + 2 (for virtio service thread) + 2 x (number of workers)

#### Device bringup using startup.conf device section
```
cpu {
    main-core 1
    corelist-workers 8-9
    corelist-virtio-ctrl 7
}

devices {
   dev virtio/0
   {
     driver octeon_virtio
     port 0
      {
        name oct_virtio/0
        num-rx-queues 4
        num-tx-queues 4
      }
     args 'nb_virtio=2,dma=\"0000:06:00.1,0000:06:00.2,0000:06:00.3,0000:06:00.4,0000:06:00.5,0000:06:00.6,0000:06:00.7,0000:06:01.1,0000:06:01.2,0000:06:01.3\",misc=\"0002:17:00.0\"'
   }

   dev virtio/1
   {
     driver octeon_virtio
     port 1
      {
        name oct_virtio/1
        num-rx-queues 2
        num-tx-queues 3
      }
   }
}
```

#### Device bringup using vppctl
Launch VPP with startup conf.

```
# vpp -c /etc/vpp/startup.conf
# vppctl -s /run/vpp/cli.sock
      _______    _        _   _____  ___
   __/ __/ _ \  (_)__    | | / / _ \/ _ \
   _/ _// // / / / _ \   | |/ / ___/ ___/
   /_/ /____(_)_/\___/   |___/_/  /_/

   vpp# vppctl device attach virtio/0 driver octeon_virtio args nb_virtio=2,dma=\"0000:06:00.1,0000:06:00.2,0000:06:00.3,0000:06:00.4,0000:06:00.5,0000:06:00.6,0000:06:00.7,0000:06:01.1,0000:06:01.2,0000:06:01.3\",misc=\"0002:17:00.0\"
   vpp# vppctl device create-interface virtio/0  port 0 num-rx-queues 2 num-tx-queues 3
   vpp# vppctl device attach virtio/1 driver octeon_virtio
   vpp# vppctl device create-interface virtio/1  port 1 num-rx-queues 2 num-tx-queues 3
```
