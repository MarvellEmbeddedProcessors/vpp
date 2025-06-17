/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON CLI implementation.
 */

#include <dev_octeon/octeon.h>
#include <dev_octeon/crypto.h>
#include <base/roc_api.h>
#include <common.h>

static const char *ul = "====================================================="
			"=========================";

static void
oct_print_global_counters (vlib_main_t *vm, u64 **stat, u32 n_threads)
{
  u64 global_stat[OCT_MAX_CRYPTO_COUNTERS] = { 0 };
  oct_crypto_main_t *ocm = &oct_crypto_main;
  unsigned int n_global_stats = 0;
  vlib_simple_counter_main_t *cm;
  u32 cnt_idx, thread_idx = 0;

  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      for (cnt_idx = 0; cnt_idx < OCT_MAX_CRYPTO_COUNTERS; cnt_idx++)
	{
	  if (stat[cnt_idx][thread_idx])
	    {
	      global_stat[cnt_idx] += stat[cnt_idx][thread_idx];
	      n_global_stats++;
	    }
	}
    }

  if (!n_global_stats)
    return;

  /* Display cumulative counters */
  vlib_cli_output (vm, "%-16s %-40s %-20s", "", "Global counter", "Value");
  vlib_cli_output (vm, "%-16s %-.40s %-.20s", "", ul, ul);

#define _(i, s, d)                                                            \
  cm = &ocm->s##_counter;                                                     \
  if (global_stat[i])                                                         \
    vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name, global_stat[i]);
  foreach_crypto_counter;
#undef _
}

unsigned int
oct_get_per_thread_stats (u64 **stat, u32 n_threads, u64 *threads_with_stats)
{
  unsigned int cnt_idx, thread_idx = 0, n_threads_with_stats = 0;

  /* Identify threads that have non-zero Octeon crypto counters */
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      for (cnt_idx = 0; cnt_idx < OCT_MAX_CRYPTO_COUNTERS; cnt_idx++)
	{
	  if (stat[cnt_idx][thread_idx])
	    {
	      threads_with_stats[n_threads_with_stats++] = thread_idx;
	      break;
	    }
	}
    }

  return n_threads_with_stats;
}

static void
oct_print_per_thread_counters (vlib_main_t *vm, u64 **stat, u32 n_threads)
{
  unsigned int idx, thread_idx = 0, n_threads_with_stats = 0;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  u64 threads_with_stats[n_threads];
  vlib_simple_counter_main_t *cm;

  n_threads_with_stats =
    oct_get_per_thread_stats (stat, n_threads, threads_with_stats);

  if (!n_threads_with_stats)
    return;

  vlib_cli_output (vm, "%-16s %-40s %-20s", "Thread", "Per-thread counter",
		   "Value");
  vlib_cli_output (vm, "%-.16s %-.40s %-.20s", ul, ul, ul);

  for (idx = 0; idx < n_threads_with_stats; idx++)
    {
      thread_idx = threads_with_stats[idx];

      vlib_cli_output (vm, "%-16s", vlib_worker_threads[thread_idx].name);

      /* clang-format off */
#define _(i, s, d)                                                       \
      cm = &ocm->s##_counter;                                  \
      if (stat[i][thread_idx])                               \
        vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name,             \
                         stat[i][thread_idx]);
      foreach_crypto_counter;
#undef _
      /* clang-format on */
    }

  vlib_cli_output (vm, "\n");

  return;
}

static clib_error_t *
oct_crypto_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unsigned int cnt_idx = 0, thread_idx = 0;
  oct_crypto_main_t *ocm = &oct_crypto_main;
  vlib_simple_counter_main_t *cm;
  u64 *stat[OCT_MAX_CRYPTO_COUNTERS] = { 0 };
  counter_t *counters = NULL;
  u32 n_threads = vlib_get_n_threads ();

  if (!ocm->n_cpt)
    return clib_error_create (
      "No Crypto device attached to dev-octeon plugin");

#define _(i, s, d)                                                            \
  cm = &ocm->s##_counter;                                                     \
  vec_validate_init_empty (stat[i], n_threads, 0);                            \
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)                  \
    {                                                                         \
      counters = cm->counters[thread_idx];                                    \
      stat[i][thread_idx] = counters[0];                                      \
    }
  foreach_crypto_counter;
#undef _

  oct_print_per_thread_counters (vm, stat, n_threads);

  oct_print_global_counters (vm, stat, n_threads);

  for (cnt_idx = 0; cnt_idx < OCT_MAX_CRYPTO_COUNTERS; cnt_idx++)
    vec_free (stat[cnt_idx]);

  return 0;
}

/*?
 * This command displays Octeon crypto counters
 *
 * @cliexpar
 * Example of how to display Octeon crypto counters:
 * @cliexstart{show octeon crypto counters}
 * Per-thread counter                       Value
 * ======================================== ====================
 *
 * crypto-inflight-operations                                  8
 * crypto-success-packets                                      8
 *
 * Global counter                           Value
 * ======================================== ====================
 * crypto-inflight-operations                                  8
 * crypto-success-packets                                      8
 * @cliexend
?*/
VLIB_CLI_COMMAND (oct_crypto_counters_command, static) = {
  .path = "show octeon crypto counters",
  .short_help = "show octeon crypto counters",
  .function = oct_crypto_counters_command_fn,
};

static clib_error_t *
oct_crypto_counters_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  vlib_simple_counter_main_t *cm;
  oct_crypto_main_t *ocm = &oct_crypto_main;

  if (!ocm->n_cpt)
    return clib_error_create (
      "No Crypto device attached to dev-octeon plugin");

#define _(i, s, d)                                                            \
  cm = &ocm->s##_counter;                                                     \
  vlib_clear_simple_counters (cm);
  foreach_crypto_counter;
#undef _

  return 0;
}

/*?
 * This command clears Octeon crypto counters
 *
 * @cliexpar
 * @cliexstart{clear octeon crypto counters}
 * @cliexend
?*/
VLIB_CLI_COMMAND (oct_crypto_counters_clear_command, static) = {
  .path = "clear octeon crypto counters",
  .short_help = "clear octeon crypto counters",
  .function = oct_crypto_counters_clear_command_fn,
};

static clib_error_t *
oct_ipsec_inline_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  struct roc_nix_stats stats;
  oct_inl_dev_main_t *oim = &oct_inl_dev_main;

  if (!oim->inl_dev)
    {
      return clib_error_create (
	"No Inline device attached to dev-octeon plugin");
    }

  roc_nix_inl_dev_stats_get (&stats);

  vlib_cli_output (vm, "%-40s %20Ld", "rx_ucast", stats.rx_ucast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_bcast", stats.rx_bcast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_mcast", stats.rx_mcast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_drop", stats.rx_drop);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_fcs", stats.rx_fcs);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_err", stats.rx_err);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_drop_bcast", stats.rx_drop_bcast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_drop_mcast", stats.rx_drop_mcast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_drop_l3_bcast",
		   stats.rx_drop_l3_bcast);
  vlib_cli_output (vm, "%-40s %20Ld", "rx_drop_l3_bcast",
		   stats.rx_drop_l3_mcast);

  return 0;
}

/*?
 * This command displays OCTEON IPsec inline device counters
 *
 * @cliexpar
 * Example of how to display OCTEON IPsec inline device counters:
 * @cliexstart{show octeon ipsec inline counters}
 * rx_ucast                                                    10
 * rx_bcast                                                    0
 * rx_mcast                                                    0
 * rx_drop                                                     0
 * rx_fcs                                                      0
 * rx_err                                                      0
 * rx_drop_bcast                                               0
 * rx_drop_mcast                                               0
 * rx_drop_l3_bcast                                            0
 * rx_drop_l3_bcast                                            0
 * @cliexend
?*/

VLIB_CLI_COMMAND (oct_ipsec_inline_counters_command, static) = {
  .path = "show octeon ipsec inline counters",
  .short_help = "show ipsec inline counters",
  .function = oct_ipsec_inline_counters_command_fn,
};

static clib_error_t *
oct_ipsec_inline_counters_clear_command_fn (vlib_main_t *vm,
					    unformat_input_t *input,
					    vlib_cli_command_t *cmd)
{
  roc_nix_inl_dev_stats_reset ();

  return 0;
}

/*?
 * This command clears OCTEON IPsec inline device counters
 *
 * @cliexpar
 * @cliexstart{clear octeon ipsec inline counters}
 * @cliexend
?*/
VLIB_CLI_COMMAND (oct_ipsec_inline_counters_clear_command, static) = {
  .path = "clear octeon ipsec inline counters",
  .short_help = "clear ipsec inline counters",
  .function = oct_ipsec_inline_counters_clear_command_fn,
};

static clib_error_t *
oct_aura_available_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  oct_rxq_t *crq;
  int i;

  if (oct_main.use_single_rx_aura && oct_main.rx_aura_handle)
    vlib_cli_output (vm, "rx queue aura 0x%llx avl_count %llu\n\n",
		     oct_main.rx_aura_handle,
		     roc_npa_aura_op_available (oct_main.rx_aura_handle));

  pool_foreach_pointer (dev, dm->devices)
    {
      oct_device_t *od = vnet_dev_get_data (dev);

      if (od->type == OCT_DEVICE_TYPE_RVU_PF ||
	  od->type == OCT_DEVICE_TYPE_RVU_VF ||
	  od->type == OCT_DEVICE_TYPE_SDP_VF ||
	  od->type == OCT_DEVICE_TYPE_LBK_VF)
	{
	  vlib_cli_output (vm, "Interface: %U", format_vnet_dev_log, dev, 0);
	  vlib_cli_output (vm, "%-.25s", ul);
	  if (!oct_main.use_single_rx_aura)
	    {
	      for (i = 0; i < dev->ports[0]->intf.num_rx_queues; i++)
		{
		  crq =
		    vnet_dev_get_rx_queue_data (dev->ports[0]->rx_queues[i]);
		  vlib_cli_output (
		    vm, "rx queue %d aura 0x%llx avl_count %llu\n", i,
		    crq->aura_handle,
		    roc_npa_aura_op_available (crq->aura_handle));
		}
	    }
	  for (i = 0; i < dev->ports[0]->intf.num_tx_queues; i++)
	    {
	      vlib_cli_output (
		vm, "tx queue %d aura %x avl_count %d\n", i,
		od->ctqs[i]->aura_handle,
		roc_npa_aura_op_available (od->ctqs[i]->aura_handle));
	    }
	  if (oct_main.inl_dev_initialized && roc_model_is_cn10k ())
	    {
	      crq = vnet_dev_get_rx_queue_data (dev->ports[0]->rx_queues[0]);
	      vlib_cli_output (
		vm, "meta_aura_handle %x avl_count %d\n",
		crq->rq.meta_aura_handle,
		roc_npa_aura_op_available (crq->rq.meta_aura_handle));
	    }
	  vlib_cli_output (vm, "\n");
	}
    }
  return 0;
}

/*?
 * This command displays OCTEON aura avaialbe counts
 *
 * @cliexpar
 * @cliexstart{show octeon aura available}
 * @cliexend
?*/
VLIB_CLI_COMMAND (oct_aura_available_command, static) = {
  .path = "show octeon aura available",
  .short_help = "show octeon aura available",
  .function = oct_aura_available_command_fn,
};
