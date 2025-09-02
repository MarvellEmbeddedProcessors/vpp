/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/crypto.h>
#include <dev_octeon/ipsec.h>

#include <base/roc_api.h>
#include <common.h>

struct roc_model oct_model;
oct_main_t oct_main;
extern oct_inl_dev_main_t oct_inl_dev_main;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "init",
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t oct_rx_node_counters[] = {
  /* clang-format off */
  foreach_octeon_ipsec_ucc
  foreach_oct_rx_node_counter
  /* clang-format on */
};

vlib_error_desc_t oct_tx_node_counters[] = { foreach_oct_tx_node_counter };
#undef _

vnet_dev_node_t oct_rx_node = {
  .format_trace = format_oct_rx_trace,
  .error_counters = oct_rx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_rx_node_counters),
};

vnet_dev_node_t oct_o20_rx_node = {
  .format_trace = format_oct_rx_trace,
  .error_counters = oct_rx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_rx_node_counters),
};

vnet_dev_node_t oct_tx_node = {
  .format_trace = format_oct_tx_trace,
  .error_counters = oct_tx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_tx_node_counters),
};

vnet_dev_node_t oct_tx_ipsec_tm_node = {
  .format_trace = format_oct_tx_trace,
  .error_counters = oct_tx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_tx_node_counters),
};

static struct
{
  u16 device_id;
  oct_device_type_t type;
  char *description;
} oct_dev_types[] = {

#define _(id, device_type, desc)                                              \
  {                                                                           \
    .device_id = (id), .type = OCT_DEVICE_TYPE_##device_type,                 \
    .description = (desc)                                                     \
  }

  _ (0xa063, RVU_PF, "Marvell Octeon Resource Virtualization Unit PF"),
  _ (0xa064, RVU_VF, "Marvell Octeon Resource Virtualization Unit VF"),
  _ (0xa0f8, LBK_VF, "Marvell Octeon Loopback Unit VF"),
  _ (0xa0f7, SDP_VF, "Marvell Octeon System DPI Packet Interface Unit VF"),
  _ (0xa0f3, O10K_CPT_VF,
     "Marvell Octeon-10 Cryptographic Accelerator Unit VF"),
  _ (0xa0fe, O9K_CPT_VF, "Marvell Octeon-9 Cryptographic Accelerator Unit VF"),
  _ (0xa0f0, RVU_INL_PF,
     "Marvell Octeon Resource Virtualization Unit Inline Device PF"),
  _ (0xa0f1, RVU_INL_VF,
     "Marvell Octeon Resource Virtualization Unit Inline Device VF"),
#undef _
};

static vnet_dev_arg_t oct_drv_args[] = {
  {
    .id = OCT_DRV_ARG_NPA_MAX_POOLS,
    .name = "npa_max_pools",
    .desc = "Max NPA pools",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 128,
  },
  {
    .id = OCT_DRV_ARG_USE_SINGLE_RX_AURA,
    .name = "use_single_rx_aura",
    .desc = "Use single rx aura",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = true,
  },
  {
    .id = OCT_DRV_ARG_IPSEC_IN_MIN_SPI,
    .name = "ipsec_in_min_spi",
    .desc = "Inline IPsec inbound minimum spi value",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 0,
  },
  {
    .id = OCT_DRV_ARG_IPSEC_IN_MAX_SPI,
    .name = "ipsec_in_max_spi",
    .desc = "Inline IPsec inbound maximum spi value",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 8192,
  },
  {
    .id = OCT_DRV_ARG_IPSEC_OUT_MAX_SA,
    .name = "ipsec_out_max_sa",
    .desc = "Inline IPsec outbound maximum sa",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 8192,
  },
  {
    .id = OCT_DRV_ARG_END,
    .name = "end",
    .desc = "Argument end",
    .type = VNET_DEV_ARG_END,
  },
};

static vnet_dev_arg_t oct_port_args[] = {
  {
    .id = OCT_PORT_ARG_ALLMULTI_MODE,
    .name = "allmulti",
    .desc = "Set allmulti mode, applicable to network devices only",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = OCT_PORT_ARG_EN_ETH_PAUSE_FRAME,
    .name = "eth_pause_frame",
    .desc = "Enable ethernet pause frame (flow control) support, "
	    "applicable to network devices only",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = OCT_PORT_ARG_SWITCH_HDR_TYPE,
    .name = "switch_header",
    .desc = "Enable switch header and set specific switch header type, "
	    "applicable to network devices only",
    .type = VNET_DEV_ARG_TYPE_STRING,
  },
  {
    .id = OCT_PORT_ARG_END,
    .name = "end",
    .desc = "Argument end",
    .type = VNET_DEV_ARG_END,
  },
};

static vnet_dev_arg_t oct_dev_args[] = {
  {
    .id = OCT_DEV_ARG_CRYPTO_N_DESC,
    .name = "n_desc",
    .desc = "number of cpt descriptors, applicable to cpt devices only",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = OCT_CPT_LF_DEF_NB_DESC,
  },
  {
    .id = OCT_DEV_ARG_END,
    .name = "end",
    .desc = "Argument end",
    .type = VNET_DEV_ARG_END,
  },
};

clib_error_t *
oct_inl_inb_ipsec_flow_enable (void)
{
  oct_inl_dev_main_t *inl_main = &oct_inl_dev_main;
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t flow = { 0 };
  u32 flow_index = ~0, hw_if_index;

  if (inl_main->is_inl_ipsec_flow_enabled)
    return NULL;

  pool_foreach_pointer (di, dm->dev_instances)
    {
      hw_if_index = di.port->interfaces->primary_interface.hw_if_index;
      clib_memset (&flow, 0, sizeof (vnet_flow_t));

      flow.index = ~0;
      flow.actions = VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
      flow.type = VNET_FLOW_TYPE_IP4_IPSEC_ESP;
      flow.ip4_ipsec_esp.spi = 0;
      flow.redirect_queue = ~0;

      vnet_flow_add (vnm, &flow, &flow_index);
      vnet_flow_enable (vnm, flow_index, hw_if_index);
    }

  inl_main->is_inl_ipsec_flow_enabled = 1;
  return NULL;
}

static u8 *
oct_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x177d) /* Cavium */
    return 0;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

vnet_dev_rv_t
cnx_return_roc_err (vnet_dev_t *dev, int rrv, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  u8 *s = va_format (0, fmt, &va);
  va_end (va);

  log_err (dev, "%v: %s [%d]", s, roc_error_msg_get (rrv), rrv);
  vec_free (s);

  return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
}

static vnet_dev_rv_t
oct_config_args (vlib_main_t *vm, vnet_dev_driver_t *drv)
{
  if (!oct_main.is_config_done)
    {
      foreach_vnet_dev_port_args (arg, drv)
	{
	  if (!arg->val_set)
	    continue;

	  if (arg->id == OCT_DRV_ARG_NPA_MAX_POOLS)
	    {
	      oct_main.npa_max_pools = vnet_dev_arg_get_uint32 (arg);

	      if (oct_main.npa_max_pools < 128 ||
		  (oct_main.npa_max_pools > BIT_ULL (20)))
		{
		  log_err (
		    NULL,
		    "Invalid max-pools value (%u), should be in range of "
		    "(128 - %u)\n",
		    oct_main.npa_max_pools, BIT_ULL (20));
		  return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
		}
	    }

	  if (arg->id == OCT_DRV_ARG_USE_SINGLE_RX_AURA)
	    oct_main.use_single_rx_aura = vnet_dev_arg_get_bool (arg);

	  if (arg->id == OCT_DRV_ARG_IPSEC_IN_MIN_SPI)
	    oct_inl_dev_main.in_min_spi = vnet_dev_arg_get_uint32 (arg);

	  if (arg->id == OCT_DRV_ARG_IPSEC_IN_MAX_SPI)
	    oct_inl_dev_main.in_max_spi = vnet_dev_arg_get_uint32 (arg);

	  if (arg->id == OCT_DRV_ARG_IPSEC_OUT_MAX_SA)
	    oct_inl_dev_main.out_max_sa = vnet_dev_arg_get_uint32 (arg);
	}
      oct_main.is_config_done = 1;
    }
  else
    {
      log_err (NULL, "Driver config arguments are already initialized or "
		     "devices are already initialized");
      return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
    }

  return 0;
}

static vnet_dev_rv_t
oct_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  cd->nix =
    clib_mem_alloc_aligned (sizeof (struct roc_nix), CLIB_CACHE_LINE_BYTES);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
oct_init_nix (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_main_t *om = &oct_main;
  oct_ipsec_main_t *oim = &oct_ipsec_main;
  oct_inl_dev_main_t *oidm = &oct_inl_dev_main;
  u8 bp_index = vlib_buffer_pool_get_default_for_numa (vm, 0);
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, bp_index);
  struct npa_aura_s aura = {};
  struct npa_pool_s npapool = { .nat_align = 1,
				.buf_offset = OCT_EXT_HDR_SIZE / ROC_ALIGN };
  oct_device_t *cd = vnet_dev_get_data (dev), **oct_dev = 0;
  u8 mac_addr[6];
  int rrv;
  oct_port_t oct_port = {};
  vnet_dev_rv_t rv;

  *cd->nix = (struct roc_nix){
    .reta_sz = ROC_NIX_RSS_RETA_SZ_256,
    .max_sqb_count = 512,
    .pci_dev = &cd->plt_pci_dev,
    .hw_vlan_ins = true,
  };

  if (roc_feature_nix_has_own_meta_aura () &&
      !roc_feature_nix_has_second_pass_drop ())
    cd->nix->local_meta_aura_ena = true;

  if ((rrv = roc_nix_dev_init (cd->nix)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_dev_init");

  if ((rrv = roc_nix_npc_mac_addr_get (cd->nix, mac_addr)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_npc_mac_addr_get");

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 64,
        .max_tx_queues = 64,
        .max_supported_rx_frame_size = roc_nix_max_pkt_len (cd->nix),
	.caps = {
	  .rss = 1,
	},
	.rx_offloads = {
	  .ip4_cksum = 1,
	},
	.tx_offloads = {
	  .ip4_cksum = 1,
	},
      },
      .ops = {
        .init = oct_port_init,
        .deinit = oct_port_deinit,
        .start = oct_port_start,
        .stop = oct_port_stop,
        .config_change = oct_port_cfg_change,
        .config_change_validate = oct_port_cfg_change_validate,
        .format_status = format_oct_port_status,
        .format_flow = format_oct_port_flow,
        .clear_counters = oct_port_clear_counters,
      },
      .data_size = sizeof (oct_port_t),
      .initial_data = &oct_port,
      .args = oct_port_args,
    },
    .rx_node = &oct_rx_node,
    .tx_node = &oct_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (oct_rxq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = oct_rx_queue_alloc,
        .free = oct_rx_queue_free,
	.format_info = format_oct_rxq_info,
        .clear_counters = oct_rxq_clear_counters,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (oct_txq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = oct_tx_queue_alloc,
        .free = oct_tx_queue_free,
	.format_info = format_oct_txq_info,
        .clear_counters = oct_txq_clear_counters,
      },
    },
  };

  if (om->use_single_rx_aura && !om->rx_aura_handle)
    {
      if ((rrv = roc_npa_pool_create (&om->rx_aura_handle, bp->alloc_size,
				      bp->n_buffers, &aura, &npapool, 0)))
	return cnx_return_roc_err (dev, rrv, "roc_npa_pool_create");
    }

  if (oidm->inl_dev)
    {
      if (oim->inline_ipsec_sessions)
	{
	  log_err (dev,
		   "device attach not allowed after any IPsec SA addition");
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
      if ((rv = oct_init_nix_inline_ipsec (vm, oidm->vdev, dev)))
	return rv;
      port_add_args.tx_node = &oct_tx_ipsec_tm_node;
    }

  if (roc_model_is_cn20k ())
    port_add_args.rx_node = &oct_o20_rx_node;

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address, mac_addr);

  if ((rv = vnet_dev_port_add (vm, dev, 0, &port_add_args)))
    return rv;

  pool_get (om->oct_dev, oct_dev);
  oct_dev[0] = vnet_dev_get_data (dev);
  oct_dev[0]->nix_idx = oct_dev - om->oct_dev;

  return VNET_DEV_OK;
}

static int
oct_conf_cpt (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd,
	      int nb_lf)
{
  struct roc_cpt *roc_cpt = ocd->roc_cpt;
  int rrv;

  if ((rrv = roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_SE)) < 0)
    {
      log_err (dev, "Could not add CPT SE engines");
      return cnx_return_roc_err (dev, rrv, "roc_cpt_eng_grp_add");
    }
  if (!roc_model_is_cn20k ())
    {
      if ((rrv = roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_IE)) < 0)
	{
	  log_err (dev, "Could not add CPT IE engines");
	  return cnx_return_roc_err (dev, rrv, "roc_cpt_eng_grp_add");
	}
      if (roc_cpt->eng_grp[CPT_ENG_TYPE_IE] !=
	  ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE)
	{
	  log_err (dev, "Invalid CPT IE engine group configuration");
	  return -1;
	}
    }
  if (roc_cpt->eng_grp[CPT_ENG_TYPE_SE] != ROC_LEGACY_CPT_DFLT_ENG_GRP_SE)
    {
      log_err (dev, "Invalid CPT SE engine group configuration");
      return -1;
    }
  if ((rrv = roc_cpt_dev_configure (roc_cpt, nb_lf, false, 0)) < 0)
    {
      log_err (dev, "could not configure crypto device %U",
	       format_vlib_pci_addr, roc_cpt->pci_dev->addr);
      return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_configure");
    }
  return 0;
}

static vnet_dev_rv_t
oct_conf_cpt_queue (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd)
{
  struct roc_cpt *roc_cpt = ocd->roc_cpt;
  struct roc_cpt_lmtline *cpt_lmtline;
  struct roc_cpt_lf *cpt_lf;
  int rrv;

  cpt_lf = &ocd->lf;
  cpt_lmtline = &ocd->lmtline;

  cpt_lf->nb_desc = ocd->n_desc;
  cpt_lf->lf_id = 0;
  if ((rrv = roc_cpt_lf_init (roc_cpt, cpt_lf)) < 0)
    return cnx_return_roc_err (dev, rrv, "roc_cpt_lf_init");

  roc_cpt_iq_enable (cpt_lf);

  if ((rrv = roc_cpt_lmtline_init (roc_cpt, cpt_lmtline, 0, false) < 0))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_lmtline_init");

  return 0;
}

static vnet_dev_rv_t
oct_init_inl_dev (vlib_main_t *vm, vnet_dev_t *dev)
{
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_device_t *od = vnet_dev_get_data (dev);
  oct_inl_dev_main_t *oidm = &oct_inl_dev_main;
  vnet_dev_rv_t rv;

  if ((STRUCT_SIZE_OF (vlib_buffer_t, pre_data) < 128) ||
      (STRUCT_OFFSET_OF (vlib_buffer_t, pre_data) % ROC_ALIGN))
    {
      log_err (dev, "Failed to initalize inline device: pre_data size should "
		    "be minimum 128 Bytes and offset of pre_data in vlib "
		    "should be 128 bytes aligned");
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  oidm->inl_dev = oct_plt_init_param.oct_plt_zmalloc (
    sizeof (struct roc_nix_inl_dev), CLIB_CACHE_LINE_BYTES);
  oidm->inl_dev->pci_dev = &od->plt_pci_dev;
  oidm->vdev = dev;

  if ((rv = oct_early_init_inline_ipsec (vm, dev)))
    return rv;

  if ((rv = oct_init_ipsec_backend (vm, dev)))
    return rv;

  oct_main.use_single_rx_aura = 1;
  oct_main.inl_dev_initialized = 1;

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
oct_init_cpt (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_crypto_dev_t *ocd = NULL;
  u32 n_desc;
  int rrv;

  if (ocm->n_cpt == OCT_MAX_N_CPT_DEV || ocm->started)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  ocd = oct_plt_init_param.oct_plt_zmalloc (sizeof (oct_crypto_dev_t),
					    CLIB_CACHE_LINE_BYTES);

  ocd->roc_cpt = oct_plt_init_param.oct_plt_zmalloc (sizeof (struct roc_cpt),
						     CLIB_CACHE_LINE_BYTES);
  ocd->roc_cpt->pci_dev = &cd->plt_pci_dev;

  ocd->dev = dev;
  ocd->n_desc = OCT_CPT_LF_DEF_NB_DESC;

  foreach_vnet_dev_args (arg, dev)
    {
      if (arg->id == OCT_DEV_ARG_CRYPTO_N_DESC &&
	  vnet_dev_arg_get_uint32 (arg))
	{
	  n_desc = vnet_dev_arg_get_uint32 (arg);
	  if (n_desc < OCT_CPT_LF_MIN_NB_DESC ||
	      n_desc > OCT_CPT_LF_MAX_NB_DESC)
	    {
	      log_err (dev,
		       "number of cpt descriptors should be within range "
		       "of %u and %u",
		       OCT_CPT_LF_MIN_NB_DESC, OCT_CPT_LF_MAX_NB_DESC);
	      return VNET_DEV_ERR_NOT_SUPPORTED;
	    }

	  ocd->n_desc = vnet_dev_arg_get_uint32 (arg);
	}
    }

  if ((rrv = roc_cpt_dev_init (ocd->roc_cpt)))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_init");

  if ((rrv = oct_conf_cpt (vm, dev, ocd, 1)))
    return rrv;

  if ((rrv = oct_conf_cpt_queue (vm, dev, ocd)))
    return rrv;

  if (!ocm->n_cpt)
    {
      /*
       * Initialize s/w queues, which are common across multiple
       * crypto devices
       */
      oct_conf_sw_queue (vm, dev, ocd);

      ocm->crypto_dev[0] = ocd;
      /* Initialize counters */
#define _(i, s, str)                                                          \
  ocm->s##_counter.name = str;                                                \
  ocm->s##_counter.stat_segment_name = "/octeon/" str "_counters";            \
  vlib_validate_simple_counter (&ocm->s##_counter, 0);                        \
  vlib_zero_simple_counter (&ocm->s##_counter, 0);
      foreach_crypto_counter;
#undef _
    }

  ocm->crypto_dev[1] = ocd;

  oct_init_crypto_engine_handlers (vm, dev);

  ocm->n_cpt++;

  return VNET_DEV_OK;
}

static bool
oct_is_nix_bar_mappable (vnet_dev_t *dev, u32 bar)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  /* Device-BARs mapping table
   * +-----+-------+-------+--------+
   * |     | cn9k  | cn10k | cn20k  |
   * +-----+-------+-------+--------+
   * |  PF | BAR2  | BAR2  | BAR2   |
   * |     | BAR4  | BAR4  |        |
   * +-----+-------+-------+--------+
   * |  VF | BAR2  | BAR2  | BAR2   |
   * |     | BAR4  |       |        |
   * +-----+-------+-------+--------+
   */

  if (bar == 2)
    return true;

  if (roc_model_is_cn20k ())
    return false;

  if (roc_model_is_cn10k () && OCT_DEVTYPE_IS_VF (cd->type))
    return false;

  return true;
}

static vnet_dev_rv_t
oct_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;

  /*
   * Drivers config arguments should be initialized by this time
   * otherwise don't allow to set after device init
   */
  if (!oct_main.is_config_done)
    oct_main.is_config_done = 1;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x177d)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
    {
      if (dt->device_id == pci_hdr.device_id)
	cd->type = dt->type;
    }

  if (cd->type == OCT_DEVICE_TYPE_UNKNOWN)
    return rv;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  cd->plt_pci_dev = (struct plt_pci_device){
    .id.vendor_id = pci_hdr.vendor_id,
    .id.device_id = pci_hdr.device_id,
    .id.class_id = pci_hdr.class << 16 | pci_hdr.subclass,
    .pci_handle = vnet_dev_get_pci_handle (dev),
  };
  cd->msix_handler = NULL;

  foreach_int (i, 2, 4)
    {
      if (oct_is_nix_bar_mappable (dev, i))
	{
	  rv = vnet_dev_pci_map_region (vm, dev, i,
					&cd->plt_pci_dev.mem_resource[i].addr);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }

  STATIC_ASSERT (sizeof (cd->plt_pci_dev.name) == sizeof (dev->device_id), "");

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  strncpy ((char *) cd->plt_pci_dev.name, dev->device_id,
	   sizeof (dev->device_id));

  cd->plt_pci_dev.intr_handle = malloc (sizeof (struct oct_pci_intr_handle));
  if (!cd->plt_pci_dev.intr_handle)
    return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
  memset (cd->plt_pci_dev.intr_handle, 0x0,
	  sizeof (struct oct_pci_intr_handle));
  cd->plt_pci_dev.intr_handle->pci_handle = cd->plt_pci_dev.pci_handle;

  switch (cd->type)
    {
    case OCT_DEVICE_TYPE_RVU_PF:
    case OCT_DEVICE_TYPE_RVU_VF:
    case OCT_DEVICE_TYPE_LBK_VF:
    case OCT_DEVICE_TYPE_SDP_VF:
      return oct_init_nix (vm, dev);

    case OCT_DEVICE_TYPE_O10K_CPT_VF:
    case OCT_DEVICE_TYPE_O9K_CPT_VF:
      return oct_init_cpt (vm, dev);

    case OCT_DEVICE_TYPE_RVU_INL_PF:
    case OCT_DEVICE_TYPE_RVU_INL_VF:
      return oct_init_inl_dev (vm, dev);

    default:
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  return 0;
}

static void
oct_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

static void
oct_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

VNET_DEV_REGISTER_DRIVER (octeon) = {
  .name = "octeon",
  .bus = "pci",
  .device_data_sz = sizeof (oct_device_t),
  .ops = {
    .config_args = oct_config_args,
    .alloc = oct_alloc,
    .init = oct_init,
    .deinit = oct_deinit,
    .free = oct_free,
    .probe = oct_probe,
  },
  .args = oct_dev_args,
  .drv_args = oct_drv_args,
};

static int
oct_npa_max_pools_set_cb (struct plt_pci_device *pci_dev)
{
  roc_idev_npa_maxpools_set (oct_main.npa_max_pools);
  return 0;
}

static clib_error_t *
oct_plugin_init (vlib_main_t *vm)
{
  int rv;
  extern oct_plt_init_param_t oct_plt_init_param;

  rv = oct_plt_init (&oct_plt_init_param);
  if (rv)
    return clib_error_return (0, "oct_plt_init failed");

  rv = roc_model_init (&oct_model);
  if (rv)
    return clib_error_return (0, "roc_model_init failed");

#ifdef PLATFORM_OCTEON9
  if (!roc_model_is_cn9k ())
    return clib_error_return (0, "OCTEON model is not OCTEON9");
#else
  if (!roc_model_is_cn10k ())
    return clib_error_return (0, "OCTEON model is not OCTEON10");
#endif

  roc_npa_lf_init_cb_register (oct_npa_max_pools_set_cb);

  /* set default values in oct_main */
  oct_main.npa_max_pools = OCT_NPA_MAX_POOLS;
  oct_main.use_single_rx_aura = 1;
  oct_inl_dev_main.in_min_spi = 0;
  oct_inl_dev_main.in_max_spi = 8192;
  oct_inl_dev_main.out_max_sa = 8192;

  roc_npa_lf_init_cb_register (oct_npa_max_pools_set_cb);

  return 0;
}

VLIB_INIT_FUNCTION (oct_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_octeon",
};

VLIB_BUFFER_SET_EXT_HDR_SIZE (OCT_EXT_HDR_SIZE);
