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

  roc_nix_inl_dev_stats_get (&stats);

  vlib_cli_output (vm, "rx_ucast %u", stats.rx_ucast);
  vlib_cli_output (vm, "rx_bcast %u", stats.rx_bcast);
  vlib_cli_output (vm, "rx_mcast %u", stats.rx_mcast);
  vlib_cli_output (vm, "rx_drop %u", stats.rx_drop);
  vlib_cli_output (vm, "rx_fcs %u", stats.rx_fcs);
  vlib_cli_output (vm, "rx_err %u", stats.rx_err);
  vlib_cli_output (vm, "rx_drop_bcast %u", stats.rx_drop_bcast);
  vlib_cli_output (vm, "rx_drop_mcast %u", stats.rx_drop_mcast);
  vlib_cli_output (vm, "rx_drop_l3_bcast %u", stats.rx_drop_l3_bcast);
  vlib_cli_output (vm, "rx_drop_l3_bcast %u", stats.rx_drop_l3_mcast);

  return 0;
}

VLIB_CLI_COMMAND (oct_ipsec_inline_counters_command, static) = {
  .path = "show octeon ipsec inline counters",
  .short_help = "show ipsec inline counters",
  .function = oct_ipsec_inline_counters_command_fn,
};
