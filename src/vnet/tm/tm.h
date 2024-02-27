/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _TM_H_
#define _TM_H_

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/dev/types.h>

typedef struct tm_node_params_
{
  /* Shaper profile for the node. */
  u32 shaper_profile_id;

  union
  {
    struct
    {
      /* The ingress queue buffer length */
      u32 ingress_q_len;
    } leaf;

    struct
    {
      /** Number of SP priorities. */
      u32 num_sp_priorities;
      /* Is scheduling done with pkt mode(1) or byte mode(0). defined per sp
       * priority */
      u8 *sched_pkt_mode;
    } nonleaf;
  };

  /** Level Identifier of the node in the tm hierarchy */
  u32 level;

  /** Store Node specific data */
  void *data;

  /** TM Node id */
  u32 id;
} tm_node_params_t;

typedef struct tm_shaper_params_
{
  struct
  {
    /** Committed Information Rate. */
    u64 rate;
    /** Max burst size for Committed information rate*/
    u64 burst_size;
  } commit;

  struct
  {
    /** Peak Information Rate. */
    u64 rate;
    /** Max burst size for Peak information rate. */
    u64 burst_size;
  } peak;

  /** Value to be added to the length of each packet for the
   * purpose of shaping. */
  i32 pkt_len_adj;

  /** Byte mode of Packet mode */
  u8 pkt_mode;

  /** Shaper profile ID */
  u32 shaper_id;
} tm_shaper_params_t;

typedef enum
{
  TM_BYTE_BASED_WEIGHTS,
  TM_FRAME_BASED_WEIGHTS
} tm_sched_mode_t;

/**
 * TM Color
 */
enum tm_color
{
  TM_COLOR_GREEN = 0, /**< Green */
  TM_COLOR_YELLOW,    /**< Yellow */
  TM_COLOR_RED,	      /**< Red */
  TM_COLORS	      /**< Number of colors */
};

/**
 * The tm_node_stats_type enumeration lists possible packet or octet
 * statistics at a tm node.
 */
typedef enum tm_node_stats_type_t
{
  /** Packets dropped by this node after scheduling/shaping at this node */
  TM_NODE_STATS_PKTS_DROPPED,
  /** Octets dropped after scheduling/shaping at this node */
  TM_NODE_STATS_OCTETS_DROPPED,
  /** Green packets that are sent through this tm node */
  TM_NODE_STATS_GREEN_PKTS,
  /** Green octets that are sent through this tm node */
  TM_NODE_STATS_GREEN_OCTETS,
  /** Yellow packets that are sent through this tm node */
  TM_NODE_STATS_YELLOW_PKTS,
  /** Yellow octets that are sent through this tm node */
  TM_NODE_STATS_YELLOW_OCTETS,
  /** Red packets that are sent through this tm node */
  TM_NODE_STATS_RED_PKTS,
  /** Red octets that are sent through this tm node */
  TM_NODE_STATS_RED_OCTETS,
  /** Node stats max */
  TM_NODE_STATS_MAX,
} tm_node_stats_type_t;

/**
 * Node statistics counters
 */
typedef struct tm_stats_params_
{
  /** Number of packets scheduled from current node. */
  uint64_t n_pkts;

  /** Number of bytes scheduled from current node. */
  uint64_t n_bytes;

  /** Statistics counters for leaf nodes only. */
  struct
  {
    /** Number of packets dropped by current leaf node per each
     * color.
     */
    uint64_t n_pkts_dropped[TM_COLORS];

    /** Number of bytes dropped by current leaf node per each
     * color.
     */
    uint64_t n_bytes_dropped[TM_COLORS];

    /** Number of packets currently waiting in the packet queue of
     * current leaf node.
     */
    uint64_t n_pkts_queued;
    /** Number of bytes currently waiting in the packet queue of
     * current leaf node.
     */
    uint64_t n_bytes_queued;
  } leaf;
} tm_stats_params_t;

typedef struct tm_system_t_
{
  u32 hw_if_idx;
  int (*node_add) (u32 hw_if_idx, u32 node_id, u32 parent_node_id,
		   u32 priority, u32 weight, u32 lvl,
		   tm_node_params_t *params);

  int (*node_suspend) (u32 hw_if_idx, u32 node_idx);
  int (*node_resume) (u32 hw_if_idx, u32 node_idx);
  int (*node_delete) (u32 hw_if_idx, u32 node_idx);
  int (*shaper_profile_create) (u32 hw_if_idx, tm_shaper_params_t *param);
  int (*shaper_profile_delete) (u32 hw_if_idx, u32 shaper_id);
  int (*node_shaper_update) (u32 hw_if_idx, u32 node_id,
			     u32 shaper_profile_id);
  int (*node_read_stats) (u32 hw_if_idx, u32 node_idx,
			  tm_stats_params_t *param);
  int (*start_tm) (u32 hw_if_idx);
  int (*stop_tm) (u32 hw_if_idx);
} tm_system_t;

/**
 * @brief Add a new traffic management node and connect it to an
 * existing parent node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_id - Identifier for the new TM node to be created.
 * @param parent_node_id - Identifier of the existing parent node.
 * @param priority - Priority level of the new node.
 * @param weight - Weight assigned to the new node.
 * @param lvl - Level of the new node in the hierarchy.
 * @param params - Pointer to the structure containing additional parameters
 * for the TM node.
 *
 * @return 0 on success.
 */
int tm_sys_node_add (u32 hw_if_idx, u32 node_id, u32 parent_node_id,
		     u32 priority, u32 weight, u32 lvl,
		     tm_node_params_t *params);

/**
 * @brief Suspend an existing traffic management node.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be suspended.
 *
 * @return 0 on success.
 */
int tm_sys_node_suspend (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Resume a suspended traffic management node.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be resumed.
 *
 * @return 0 on success.
 */
int tm_sys_node_resume (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Delete an existing traffic management node.
 * A node can only be deleted if it has no child nodes
 * connected to it.
 *
 * @param hw_if_idx - Hardware interface index
 * @param node_idx - Index of the TM node to be deleted.
 *
 * @return 0 on success.
 */
int tm_sys_node_delete (u32 hw_if_idx, u32 node_idx);

/**
 * @brief Create a new shaper profile for traffic management.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param param - Pointer to the structure containing the shaper parameters.
 *
 * @return 0 on success.
 */
int tm_sys_shaper_profile_create (u32 hw_if_idx, tm_shaper_params_t *param);

/**
 * @brief Update the shaper profile id of a TM node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_id - Identifier of the TM node to be updated.
 * @param shaper_profile_id - Identifier of the new shaper profile to be
 * applied.
 *
 * @return 0 on success.
 */
int tm_sys_node_shaper_update (u32 hw_if_idx, u32 node_id,
			       u32 shaper_profile_id);

/**
 * @brief Delete an existing shaper profile.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param shaper_id - Identifier of the shaper profile to be deleted.
 *
 * @return 0 on success.
 */
int tm_sys_shaper_profile_delete (u32 hw_if_idx, u32 shaper_id);

/**
 * @brief Read statistics for a specific traffic management node.
 *
 * @param hw_if_idx - Hardware interface index.
 * @param node_idx - Index of the TM node whose statistics are to be read.
 * @param param - Pointer to the structure where the statistics will be stored.
 *
 * @return 0 on success.
 */
int tm_sys_node_read_stats (u32 hw_if_idx, u32 node_idx,
			    tm_stats_params_t *param);

/**
 * @brief Start the traffic management system.
 *
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_sys_start_tm (u32 hw_if_idx);

/**
 * @brief Stop the traffic management system.
 *
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_sys_stop_tm (u32 hw_if_idx);

/**
 * @brief Register the traffic management (TM) system.
 *
 * @param tm_sys - Pointer to the TM system structure to be registered.
 * @param hw_if_idx - Hardware interface index.
 *
 * @return 0 on success.
 */
int tm_system_register (tm_system_t *tm_sys, u32 hw_if_idx);
#endif
