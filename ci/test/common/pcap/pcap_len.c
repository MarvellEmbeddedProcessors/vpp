/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  unsigned int total_len = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  const u_char *packet;
  pcap_t *handle;

  if (argc < 2)
    return -1;

  handle = pcap_open_offline (argv[1], errbuf);

  if (handle == NULL)
    return -2;

  while ((packet = pcap_next (handle, &header)))
    total_len += header.len;

  pcap_close (handle);

  printf ("%u\n", total_len);
  return 0;
}
