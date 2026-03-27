/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _DPU_H_
#define _DPU_H_

/**
 * HOST to DPU meta data
 */
typedef struct oct_h2d_meta
{
  u64 as_u64[3];
} oct_h2d_meta_t;

#define OCT_H2D_META_SIZE (sizeof (oct_h2d_meta_t))

/**
 * DPU to HOST meta data
 */
typedef union oct_d2h_meta
{
  u64 as_u64;
  struct
  {
    u64 request_id : 16;
    u64 reserved : 2;
    u64 csum_verified : 2;
    u64 destqport : 22;
    u64 sport : 6;
    u64 opcode : 16;
  };
} oct_d2h_meta_t;

#define OCT_D2H_META_SIZE (sizeof (oct_d2h_meta_t))

#define OCT_D2H_CSUM_FAILED    0x0
#define OCT_D2H_L4SUM_VERIFIED 0x1
#define OCT_D2H_IPSUM_VERIFIED 0x2
#define OCT_D2H_CSUM_VERIFIED  (OCT_D2H_L4SUM_VERIFIED | OCT_D2H_IPSUM_VERIFIED)

#endif /* _DPU_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
