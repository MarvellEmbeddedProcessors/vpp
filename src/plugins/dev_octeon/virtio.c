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

#define OCTEON_VIRTIO_DEV "Marvell Octeon virtio network device"

oct_virtio_main_t *oct_virtio_main = NULL;
oct_virtio_port_map_t *virtio_port_map = NULL;
oct_virtio_per_thread_data_t *oct_virt_thread_data = NULL;

VLIB_REGISTER_LOG_CLASS (oct_virt_log, static) = {
  .class_name = "octeon",
  .subclass_name = "virtio_init",
};

enum oct_virtio_dev_args_types
{
  DEV_ARG_VIRT_NB_VIRTIO_DEVICES = 1,
  DEV_ARG_VIRT_DMA_DEVICE_LIST,
  DEV_ARG_VIRT_MISC_DEVICE,
  DEV_ARG_VIRT_END
};

static vnet_dev_arg_t oct_virtio_dev_args[] = {
  {
    .id = DEV_ARG_VIRT_NB_VIRTIO_DEVICES,
    .name = "nb_virtio",
    .desc = "Number of virtio device",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 1,
  },
  {
    .id = DEV_ARG_VIRT_DMA_DEVICE_LIST,
    .name = "dma",
    .desc = "DMA device list",
    .type = VNET_DEV_ARG_TYPE_STRING,
  },
  {
    .id = DEV_ARG_VIRT_MISC_DEVICE,
    .name = "misc",
    .desc = "Miscellaneous device list",
    .type = VNET_DEV_ARG_TYPE_STRING,
  },
  {
    .id = DEV_ARG_VIRT_END,
    .name = "end",
    .desc = "Argument end",
    .type = VNET_DEV_ARG_END,
  },
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t oct_virtio_tx_node_counters[] = {
  foreach_oct_virt_tx_node_counter
};
#undef _

vnet_dev_node_t oct_virtio_rx_node = {
  .format_trace = format_oct_virt_rx_trace,
};

vnet_dev_node_t oct_virtio_tx_node = {
  .format_trace = format_oct_virt_tx_trace,
  .error_counters = oct_virtio_tx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_virtio_tx_node_counters),
};

void
oct_virt_buffer_pool_dma_map (vlib_main_t *vm)
{
  uword i;
  size_t page_sz;
  vlib_physmem_map_t *pm;
  vlib_buffer_pool_t *bp;
  int iova_mode = rte_eal_iova_mode ();

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      if (bp->start)
	{
	  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
	  page_sz = 1ULL << pm->log2_page_size;
	  for (i = 0; i < pm->n_pages; i++)
	    {
	      char *va = ((char *) pm->base) + i * page_sz;
	      uword pa = (iova_mode == RTE_IOVA_VA) ? pointer_to_uword (va) :
							    pm->page_table[i];

	      dao_pal_vfio_dma_map (pointer_to_uword (va), pa, page_sz);
	    }
	}
    }
}

static clib_error_t *
dao_log_read (clib_file_t *uf)
{
  unformat_input_t input;
  u8 *line, *s = 0;
  int n, n_try;

  n = n_try = 4096;
  while (n == n_try)
    {
      uword len = vec_len (s);
      vec_resize (s, len + n_try);

      n = read (uf->file_descriptor, s + len, n_try);
      if (n < 0 && errno != EAGAIN)
	return clib_error_return_unix (0, "read");
      vec_set_len (s, len + (n < 0 ? 0 : n));
    }

  unformat_init_vector (&input, s);

  while (unformat_user (&input, unformat_line, &line))
    {
      vec_add1 (line, 0);
      vec_pop (line);
      clib_warning ("%v", line);
      vec_free (line);
    }

  unformat_free (&input);
  return 0;
}

static void
dao_lib_logging (void)
{
  int log_fds[2] = { 0 };

  if (pipe (log_fds) == 0)
    {
      if (fcntl (log_fds[0], F_SETFL, O_NONBLOCK) == 0 &&
	  fcntl (log_fds[1], F_SETFL, O_NONBLOCK) == 0)
	{
	  FILE *f = fdopen (log_fds[1], "a");
	  if (f && rte_openlog_stream (f) == 0)
	    {
	      clib_file_t t = { 0 };
	      t.read_function = dao_log_read;
	      t.file_descriptor = log_fds[0];
	      t.description = format (0, "DAO logging pipe");
	      clib_file_add (&file_main, &t);
	    }
	}
      else
	{
	  close (log_fds[0]);
	  close (log_fds[1]);
	}
    }
}

static u8 *
oct_virtio_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index,
		  void *dev_info)
{
  oct_dev_bus_virtio_device_info_t *di = dev_info;

  if (di->vendor_id != 0x177d || di->device_id != OCT_VIRTIO_DEVICE_ID)
    return 0;

  return format (0, "%s", OCTEON_VIRTIO_DEV);
}

static char **
oct_populate_dma_device_list (u16 *nb_elem, u8 *dma_list)
{
  char *device = NULL;
  char **vec = NULL;
  char *saveptr;
  u16 count = 0;

  device = strtok_r ((char *) dma_list, ",", &saveptr);
  while (device)
    {
      vec = reallocarray (vec, count + 1, sizeof (vec));
      vec[count] = strdup (device);
      count++;
      device = strtok_r (saveptr, ",", &saveptr);
    }
  *nb_elem = count;
  return vec;
}

static void
oct_virtio_parse_arguments (dao_pal_global_conf_t *conf, vnet_dev_arg_t *args)
{
  int i = 0;
  vnet_dev_arg_t *a = args;

  for (; a < vec_end (args) && a->val_set; a++)
    {
      switch (a->id)
	{
	case DEV_ARG_VIRT_NB_VIRTIO_DEVICES:
	  conf->nb_virtio_devs = a->val.uint32;
	  break;
	case DEV_ARG_VIRT_DMA_DEVICE_LIST:
	  conf->dma_devices =
	    oct_populate_dma_device_list (&conf->nb_dma_devs, a->val.string);
	  break;
	case DEV_ARG_VIRT_MISC_DEVICE:
	  conf->misc_devices = oct_populate_dma_device_list (
	    &conf->nb_misc_devices, a->val.string);
	  break;
	default:
	  log_info ("Invalid virtio device arguments received\n");
	}

      i++;
    }
}

static void
oct_dev_virtio_mac_addr_get (u16 dev_id, u8 mac_addr[])
{
  mac_addr[0] = 0x00;
  mac_addr[1] = 0x0f;
  mac_addr[2] = 0xb7;
  mac_addr[3] = 0x11;
  mac_addr[4] = (dev_id & PEM_PFVF_DEV_ID_VF_MASK) >> PEM_PFVF_DEV_ID_PF_SHIFT;
  mac_addr[5] =
    ((dev_id & PEM_PFVF_DEV_ID_VF_MASK) >> PEM_PFVF_DEV_ID_VF_SHIFT) + 1;
}

static vnet_dev_rv_t
oct_virtio_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  u8 mac_addr[6];
  vnet_dev_rv_t rv;
  uint64_t lcore_mask;
  oct_virtio_port_t ovp = {};
  dao_pal_global_conf_t conf = { 0 };
  struct dao_virtio_netdev_cbs cbs = {};
  oct_dev_bus_virtio_device_data_t *bus_data;
  oct_virtio_device_t *device_data = vnet_dev_get_data (dev);

  bus_data = oct_get_bus_virtio_device_data (dev);

  if (!oct_virtio_main->dao_lib_initialized)
    {
      /**
       * The initialization of the DAO library will be carried out using the
       * arguments provided during the first initialization of the virtio
       * interface. Any arguments provided from the second virtio device
       * onwards will be disregarded.
       */
      oct_virtio_parse_arguments (&conf, dev->args);

      if (dao_pal_global_init (&conf))
	{
	  log_err ("dao_pal_global_init failed\n");
	  return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
	}

      /* Update lcore_mask with main core */
      lcore_mask = DAO_BIT_ULL (vm->cpu_id) | oct_virtio_main->wrkr_cpu_mask;

      log_debug ("lcore_mask %lu\n", lcore_mask);
      if (dao_pal_dma_dev_setup (lcore_mask))
	{
	  log_err ("dao_pal_dma_dev_setup failed\n");
	  rv = VNET_DEV_ERR_UNSUPPORTED_CONFIG;
	  goto finish;
	}

      /* Set main core DMA devices for virtio control */
      if (dao_pal_dma_ctrl_dev_set (vm->cpu_id))
	{
	  log_err ("dao_pal_dma_dev_setup failed\n");
	  rv = VNET_DEV_ERR_UNSUPPORTED_CONFIG;
	  goto finish;
	}

      oct_virt_buffer_pool_dma_map (vm);

      cbs.status_cb = oct_virtio_dev_status_cb;
      cbs.rss_cb = oct_virito_rss_reta_configure;
      cbs.promisc_cb = oct_virtio_configure_promisc;
      cbs.allmulti_cb = oct_virtio_configure_allmulti;
      cbs.mac_set = oct_virtio_mac_addr_set;
      cbs.mac_add = oct_virtio_mac_addr_add;
      cbs.mq_configure = oct_virtio_mq_configure;
      cbs.extbuf_get = oct_virtio_vlib_buffer_alloc;
      cbs.extbuf_put = oct_virtio_vlib_buffer_free;

      dao_virtio_netdev_cb_register (&cbs);

      oct_virtio_main->dao_lib_initialized = 1;
    }

  oct_dev_virtio_mac_addr_get (bus_data->virtio_dev.virtio_id, mac_addr);

  device_data->virtio_id = bus_data->virtio_dev.virtio_id;
  ovp.virtio_id = bus_data->virtio_dev.virtio_id;
  ovp.reta_size = VIRTIO_NET_RSS_RETA_SIZE;

  vnet_dev_port_add_args_t port_add_args = {
	  .port = {
	       .attr = {
		      .type = VNET_DEV_PORT_TYPE_ETHERNET,
		      .max_rx_queues = DAO_VIRTIO_MAX_QUEUES,
		      .max_tx_queues = DAO_VIRTIO_MAX_QUEUES,
		      .max_supported_rx_frame_size = MAX_JUMBO_PKT_LEN,
		      .caps = {
		         .rss = 1,
		       },
		      .rx_offloads = {
		         .ip4_cksum = 1,
		       },
	        },
		.ops = {
			  .init = oct_virtio_port_init,
			  .deinit = oct_virtio_port_deinit,
			  .start = oct_virtio_port_start,
			  .stop = oct_virtio_port_stop,
			  .config_change = NULL,
			  .format_status = format_oct_virt_port_status,
		  },
		.data_size = sizeof (oct_virtio_port_t),
		.initial_data = &ovp,
	  },
	  .rx_node = &oct_virtio_rx_node,
	  .tx_node = &oct_virtio_tx_node,
	  .rx_queue = {
		  .config = {
			  .data_size = 0,
			  .default_size = 1024,
			  .multiplier = 32,
			  .min_size = 256,
			  .max_size = 16384,
		  },
		  .ops = {
			  .alloc = NULL,
			  .free = NULL,
			  .format_info = NULL,
		  },
	  },
	  .tx_queue = {
		  .config = {
			  .data_size = 0,
			  .default_size = 1024,
			  .multiplier = 32,
			  .min_size = 256,
			  .max_size = 16384,
		  },
		  .ops = {
			  .alloc = NULL,
			  .free = NULL,
			  .format_info = NULL,
		  },
	  },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac_addr);

  log_info ("MAC address is %U", format_ethernet_address, mac_addr);

  rv = vnet_dev_port_add (vm, dev, 0, &port_add_args);

  return rv;

finish:
  dao_pal_global_fini ();
  return rv;
}

static clib_error_t *
oct_virtio_worker_init (vlib_main_t *vm)
{
  u16 cpu_id = clib_get_current_cpu_id ();

  oct_virtio_main->wrkr_cpu_mask |= DAO_BIT_ULL (cpu_id);

  return 0;
}

static clib_error_t *
oct_virtio_exit (vlib_main_t *vm)
{
  dao_pal_global_fini ();
  return 0;
}

static clib_error_t *
oct_virtio_plugin_init (vlib_main_t *vm)
{
  dao_lib_logging ();
  vec_validate (virtio_port_map, DAO_VIRTIO_DEV_MAX);
  vec_validate (oct_virt_thread_data, DAO_PAL_MAX_WORKERS);
  vec_validate_aligned (oct_virtio_main, 1, CLIB_CACHE_LINE_BYTES);
  return NULL;
}

static void
oct_virtio_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_info ("Device unlinitialized\n");
}

VLIB_INIT_FUNCTION (oct_virtio_plugin_init);

VLIB_WORKER_INIT_FUNCTION (oct_virtio_worker_init);

VLIB_MAIN_LOOP_EXIT_FUNCTION (oct_virtio_exit);

VNET_DEV_REGISTER_DRIVER (octeon_virtio) = {
  .name = "octeon_virtio",
  .bus = "virtio",
  .device_data_sz = sizeof (oct_virtio_device_t),
  .ops = {
    .init = oct_virtio_init,
    .deinit = oct_virtio_deinit,
    .probe = oct_virtio_probe,
  },
  .args = oct_virtio_dev_args,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_octeon_virtio",
};
