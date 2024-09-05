# OCTEON end point control plain plugin (OCTEP-CP) for VPP  {#octep_cp_plugin_doc}

## Overview
This plugin implements Marvell OCTEON PCIe end point control plane protocol.
Marvell OCTEON firmware provides convenience user library liboctep.so to
setup and interact with the host over mailbox. This octep_cp plugin uses
liboctep.so library to read/send control message from/to host over mailbox.

For the host checksum offload feature, a 24-byte header is added to each
packet. The dev OCTEON plugin’s h2d-input and d2h-output components handle the
checksum computation and verification.

## Supported SoC
- OCTEON CN10KXX

## Usage
The following steps demonstrate how you may bring up VPP with octep_cp, on the
OCTEON connected to host.
1. Enable octep_cp plugin in VPP startup.conf file
2. octep_cp plugin initializes liboctep.so library which initializes SDP firmware.
3. If there are any messages from host firmware puts them into mailbox.
4. octep_cp plugin regularly calls liboctep.so API's to check mailbox.
5. octep_cp plugin applies configuration action requested by host and replies
   success or failure to host.

### Setup
1. OCTEON should be connected to host via SDP interface.
2. Determine SDP interface on OCTEON
   "lspci | grep SDP" OR "dmesg | grep sdp"
	 0002:01:00.1 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Physical Function (rev 51)
	 0002:01:00.2 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Virtual Function (rev 51)
	 0002:01:00.3 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Virtual Function (rev 51)
3. Bind SDP VF to vfio-pci driver
   dpdk-devbind.py -b vfio-pci 0002:01:00.1
4. Modify startup.conf
   - Enable octep_cp plugin
     plugins {
         plugin octep_cp_plugin.so { enable }
     }
   - Device bringup using startup.conf device section
     devices {
        dev pci/0002:01:00.1
        {
          driver octeon
          port 0
           {
             name eth0
             num-rx-queues 4
             num-tx-queues 4
           }
        }
        dev pci/0002:01:00.2
        {
          driver octeon
          port 0
           {
             name eth1
             num-rx-queues 5
             num-tx-queues 5
           }
        }
     }
5. Determine SDP interface on HOST side
   - lspci | grep Cavium
	   17:00.0 Network controller: Cavium, Inc. Device b900
	 - load OCTEON PF and VF driver, insmod octeon_ep.ko octeon_ep_vf.ko
	 - create required VF's with 'echo 1 > /sys/bus/pci/devices/0000\:17\:00.0/sriov_numvfs'

#### Configuration
This plugin uses /usr/bin/cn10kxx.cfg configuration file to configure
PCIe end point.

1. Checksum offload configuration on DPU
   - Enable checksum offload in /usr/bin/cn10kxx.cfg file
     ```
      pkind=1
     ```
   - CLI
     ```
     vppctl set int feature eth1 h2d-input arc  port-rx-eth
     vppctl set int feature eth1 d2h-output arc interface-output
     ```
2. Checksum offload configuration on host
   - Enable checksum offload on SDP VF with ethtool
     ```
     ethtool -K <SDP interface name> rx on tx on
     ```
