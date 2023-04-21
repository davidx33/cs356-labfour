/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"
#include <string.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t arp_thread;

  pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);

  srand(time(NULL));
  pthread_mutexattr_init(&(sr->rt_lock_attr));
  pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

  pthread_attr_init(&(sr->rt_attr));
  pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t rt_thread;
  pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

uint16_t checksum(const uint16_t *data, size_t length)
{
  uint32_t sum = 0;

  while (length > 1)
  {
    sum += *data++;
    length -= 2;
  }

  if (length > 0)
  {
    sum += *((const uint8_t *)data);
  }

  while (sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

struct sr_if *sr_get_interface_by_ip(struct sr_instance *sr, uint32_t ip)
{
  struct sr_if *current_if = sr->if_list;

  while (current_if)
  {
    if (current_if->ip == ip)
    {
      return current_if;
    }
    current_if = current_if->next;
  }

  return NULL;
}

struct sr_rt *sr_find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_ip)
{
  struct sr_rt *current_route = sr->routing_table;
  struct sr_rt *best_match = NULL;
  unsigned int longest_prefix = 0;

  while (current_route)
  {
    uint32_t masked_ip = dest_ip & current_route->mask.s_addr;

    if (masked_ip == current_route->dest.s_addr)
    {
      unsigned int prefix_length = __builtin_popcount(current_route->mask.s_addr);

      if (!best_match || prefix_length > longest_prefix)
      {
        longest_prefix = prefix_length;
        best_match = current_route;
      }
    }

    current_route = current_route->next;
  }

  return best_match;
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

  if (ntohs(eth_hdr->ether_type) == ethertype_arp)
  {
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* If packet is an ARP request */
    if (ntohs(arp_hdr->ar_op) == arp_op_request)
    {

      struct sr_arpcache *cache = &sr->cache;
      sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

      uint8_t *arp_response_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

      sr_ethernet_hdr_t *response_eth_hdr = (sr_ethernet_hdr_t *)arp_response_packet;
      sr_arp_hdr_t *response_arp_hdr = (sr_arp_hdr_t *)(arp_response_packet + sizeof(sr_ethernet_hdr_t));

      response_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
      response_arp_hdr->ar_pro = arp_hdr->ar_pro;
      response_arp_hdr->ar_hln = arp_hdr->ar_hln;
      response_arp_hdr->ar_pln = arp_hdr->ar_pln;
      response_arp_hdr->ar_op = htons(arp_op_reply);
      response_arp_hdr->ar_sip = arp_hdr->ar_tip;
      response_arp_hdr->ar_tip = arp_hdr->ar_sip;
      memcpy(response_arp_hdr->ar_sha, arp_hdr->ar_tha, ETHER_ADDR_LEN);
      memcpy(response_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

      struct sr_if *outgoing_if = sr_get_interface(sr, interface);

      memcpy(response_eth_hdr->ether_shost, outgoing_if->addr, ETHER_ADDR_LEN);
      memcpy(response_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
      response_eth_hdr->ether_type = htons(ethertype_arp);

      unsigned int response_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      sr_send_packet(sr, arp_response_packet, response_len, interface);

      free(arp_response_packet);
    }
  }

  if (ntohs(eth_hdr->ether_type) == ethertype_ip)
  {
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));

    uint16_t received_checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    size_t ip_hdr_size = ip_hdr->ip_hl * 4;
    uint16_t *ip_hdr_aligned = malloc(ip_hdr_size);
    memcpy(ip_hdr_aligned, ip_hdr, ip_hdr_size);
    uint16_t calculated_checksum = checksum(ip_hdr_aligned, ip_hdr_size);
    free(ip_hdr_aligned);

    if (received_checksum != calculated_checksum)
    {
      printf("Invalid IP header checksum. Ignoring packet.\n");
      return;
    }
    else
    {
      printf("Valid IP header checksum.\n");
    }

    struct sr_if *dest_if = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    if (dest_if != NULL)
    {
      uint8_t ip_proto_icmp = 0x01;
      if (ip_hdr->ip_p == ip_proto_icmp)
      {
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

        if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0)
        {
          uint8_t *icmp_reply_packet = (uint8_t *)malloc(len);

          memcpy(icmp_reply_packet, packet, len);

          sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)icmp_reply_packet;
          sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_reply_packet + sizeof(struct sr_ethernet_hdr));
          sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(icmp_reply_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

          reply_icmp_hdr->icmp_type = 0;
          reply_icmp_hdr->icmp_code = 0;
          reply_icmp_hdr->icmp_sum = 0;
          uint16_t len_icmp = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr);
          uint8_t buffer[len_icmp];
          memcpy(buffer, reply_icmp_hdr, len_icmp);
          reply_icmp_hdr->icmp_sum = htons(checksum((uint16_t *)buffer, len_icmp));

          uint32_t temp_ip = reply_ip_hdr->ip_src;
          reply_ip_hdr->ip_src = reply_ip_hdr->ip_dst;
          reply_ip_hdr->ip_dst = temp_ip;
          reply_ip_hdr->ip_ttl = 64;
          reply_ip_hdr->ip_sum = 0;

          uint8_t *payload = ((uint8_t *)icmp_hdr) + sizeof(struct sr_icmp_hdr);
          memcpy(((uint8_t *)reply_icmp_hdr) + sizeof(struct sr_icmp_hdr), payload, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr) - sizeof(struct sr_icmp_hdr));

          memcpy(reply_eth_hdr->ether_dhost, reply_eth_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(reply_eth_hdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, icmp_reply_packet, len, interface);

          free(icmp_reply_packet);
        }
      }
      else
      {

        uint8_t icmp_dest_unreachable_type = 3;
        uint8_t icmp_net_unreachable_code = 0;

        unsigned int icmp_dest_unreachable_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

        uint8_t *icmp_dest_unreachable_packet = (uint8_t *)malloc(icmp_dest_unreachable_len);

        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)icmp_dest_unreachable_packet;
        sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_dest_unreachable_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_dest_unreachable_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        reply_icmp_hdr->icmp_type = icmp_dest_unreachable_type;
        reply_icmp_hdr->icmp_code = icmp_net_unreachable_code;
        reply_icmp_hdr->icmp_sum = 0;
        reply_icmp_hdr->unused = 0;
        memcpy(reply_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        uint8_t *ip_packet = ((uint8_t *)ip_hdr) - sizeof(struct sr_ethernet_hdr);
        memcpy(((uint8_t *)reply_icmp_hdr) + sizeof(struct sr_icmp_hdr), ip_packet, sizeof(struct sr_ip_hdr) + 8);

        struct sr_if *src_if = sr_get_interface(sr, interface);
        reply_ip_hdr->ip_src = src_if->ip;
        reply_ip_hdr->ip_dst = ip_hdr->ip_src;
        reply_ip_hdr->ip_ttl = 64;
        reply_ip_hdr->ip_p = IPPROTO_ICMP;
        reply_ip_hdr->ip_v = 4;
        reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        reply_ip_hdr->ip_id = 0;
        reply_ip_hdr->ip_off = htons(IP_DF);
        reply_ip_hdr->ip_sum = 0;

        sr_ip_hdr_t tmp_reply_ip_hdr;
        memcpy(&tmp_reply_ip_hdr, reply_ip_hdr, sizeof(sr_ip_hdr_t));
        uint8_t tmp_reply_ip_hdr_buffer[sizeof(sr_ip_hdr_t)];
        memcpy(tmp_reply_ip_hdr_buffer, &tmp_reply_ip_hdr, sizeof(sr_ip_hdr_t));
        tmp_reply_ip_hdr.ip_sum = htons(checksum((uint16_t *)tmp_reply_ip_hdr_buffer, sizeof(sr_ip_hdr_t)));
        memcpy(&tmp_reply_ip_hdr, tmp_reply_ip_hdr_buffer, sizeof(sr_ip_hdr_t));

        memcpy(reply_ip_hdr, &tmp_reply_ip_hdr, sizeof(sr_ip_hdr_t));

        memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr->ether_shost, src_if->addr, ETHER_ADDR_LEN);
        reply_eth_hdr->ether_type = htons(ethertype_ip);

        sr_send_packet(sr, icmp_dest_unreachable_packet, icmp_dest_unreachable_len, interface);

        free(icmp_dest_unreachable_packet);
      }
    }
    else
    {
      if (ip_hdr->ip_ttl == 1)
      {

        uint8_t icmp_time_exceeded_type = 11;
        uint8_t icmp_ttl_exceeded_code = 0;

        unsigned int icmp_time_exceeded_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

        uint8_t *icmp_time_exceeded_packet = (uint8_t *)malloc(icmp_time_exceeded_len);

        sr_ethernet_hdr_t *te_eth_hdr = (sr_ethernet_hdr_t *)icmp_time_exceeded_packet;
        sr_ip_hdr_t *te_ip_hdr = (sr_ip_hdr_t *)(icmp_time_exceeded_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *te_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_time_exceeded_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        te_icmp_hdr->icmp_type = icmp_time_exceeded_type;
        te_icmp_hdr->icmp_code = icmp_ttl_exceeded_code;
        te_icmp_hdr->icmp_sum = 0;
        te_icmp_hdr->unused = 0;
        uint8_t tmp_icmp_hdr_buffer[sizeof(sr_icmp_t3_hdr_t)];
        memcpy(tmp_icmp_hdr_buffer, &te_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        te_icmp_hdr->icmp_sum = htons(checksum((uint16_t *)tmp_icmp_hdr_buffer, sizeof(sr_icmp_t3_hdr_t)));
        memcpy(&te_icmp_hdr, tmp_icmp_hdr_buffer, sizeof(sr_icmp_t3_hdr_t));

        sr_icmp_t3_hdr_t tmp_te_icmp_hdr;
        memcpy(&tmp_te_icmp_hdr, te_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        uint8_t tmp_te_icmp_hdr_buffer[sizeof(sr_icmp_t3_hdr_t)];
        memcpy(tmp_te_icmp_hdr_buffer, &tmp_te_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        tmp_te_icmp_hdr.icmp_sum = htons(checksum((uint16_t *)tmp_te_icmp_hdr_buffer, sizeof(sr_icmp_t3_hdr_t)));
        memcpy(&tmp_te_icmp_hdr, tmp_te_icmp_hdr_buffer, sizeof(sr_icmp_t3_hdr_t));

        memcpy(te_icmp_hdr, &tmp_te_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        struct sr_if *src_if = sr_get_interface(sr, interface);
        te_ip_hdr->ip_src = src_if->ip;
        te_ip_hdr->ip_dst = ip_hdr->ip_src;
        te_ip_hdr->ip_ttl = 64;
        te_ip_hdr->ip_p = IPPROTO_ICMP;
        te_ip_hdr->ip_v = 4;
        te_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        te_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        te_ip_hdr->ip_id = 0;
        te_ip_hdr->ip_off = htons(IP_DF);
        uint8_t tmp_te_ip_hdr_buffer[sizeof(sr_ip_hdr_t)];
        memcpy(tmp_te_ip_hdr_buffer, te_ip_hdr, sizeof(sr_ip_hdr_t));
        te_ip_hdr->ip_sum = htons(checksum((uint16_t *)tmp_te_ip_hdr_buffer, sizeof(sr_ip_hdr_t)));
        memcpy(te_ip_hdr, tmp_te_ip_hdr_buffer, sizeof(sr_ip_hdr_t));

        sr_ip_hdr_t tmp_te_ip_hdr;
        memcpy(&tmp_te_ip_hdr, te_ip_hdr, sizeof(sr_ip_hdr_t));
        tmp_te_ip_hdr.ip_sum = htons(checksum((uint16_t *)&tmp_te_ip_hdr, sizeof(sr_ip_hdr_t)));
        memcpy(te_ip_hdr, &tmp_te_ip_hdr, sizeof(sr_ip_hdr_t));

        memcpy(te_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(te_eth_hdr->ether_shost, src_if->addr, ETHER_ADDR_LEN);
        te_eth_hdr->ether_type = htons(ethertype_ip);

        sr_send_packet(sr, icmp_time_exceeded_packet, icmp_time_exceeded_len, interface);

        free(icmp_time_exceeded_packet);
      }
      else
      {
        struct sr_rt *route_entry = sr_find_longest_prefix_match(sr, ip_hdr->ip_dst);
        if (!route_entry)
        {

          uint8_t icmp_dest_unreachable_type = 3;
          uint8_t icmp_net_unreachable_code = 0;
          unsigned int icmp_dest_unreachable_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

          uint8_t *icmp_dest_unreachable_packet = (uint8_t *)malloc(icmp_dest_unreachable_len);

          sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)icmp_dest_unreachable_packet;
          sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_dest_unreachable_packet + sizeof(sr_ethernet_hdr_t));
          sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_dest_unreachable_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          reply_icmp_hdr->icmp_type = icmp_dest_unreachable_type;
          reply_icmp_hdr->icmp_code = icmp_net_unreachable_code;
          reply_icmp_hdr->icmp_sum = 0;
          reply_icmp_hdr->unused = 0;
          memcpy(reply_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

          sr_icmp_t3_hdr_t tmp_reply_icmp_hdr;
          memcpy(&tmp_reply_icmp_hdr, reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
          tmp_reply_icmp_hdr.icmp_sum = htons(checksum((uint16_t *)&tmp_reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t)));
          memcpy(reply_icmp_hdr, &tmp_reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

          struct sr_if *src_if = sr_get_interface(sr, interface);
          reply_ip_hdr->ip_src = src_if->ip;
          reply_ip_hdr->ip_dst = ip_hdr->ip_src;
          reply_ip_hdr->ip_ttl = 64;
          reply_ip_hdr->ip_p = IPPROTO_ICMP;
          reply_ip_hdr->ip_v = 4;
          reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
          reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          reply_ip_hdr->ip_id = 0;
          reply_ip_hdr->ip_off = htons(IP_DF);
          reply_ip_hdr->ip_sum = 0;

          sr_ip_hdr_t tmp_reply_ip_hdr_387;
          memcpy(&tmp_reply_ip_hdr_387, reply_ip_hdr, sizeof(sr_ip_hdr_t));
          tmp_reply_ip_hdr_387.ip_sum = htons(checksum((uint16_t *)&tmp_reply_ip_hdr_387, sizeof(sr_ip_hdr_t)));
          memcpy(reply_ip_hdr, &tmp_reply_ip_hdr_387, sizeof(sr_ip_hdr_t));

          memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(reply_eth_hdr->ether_shost, src_if->addr, ETHER_ADDR_LEN);
          reply_eth_hdr->ether_type = htons(ethertype_ip);

          sr_send_packet(sr, icmp_dest_unreachable_packet, icmp_dest_unreachable_len, interface);

          free(icmp_dest_unreachable_packet);
        }
      }
    }
  }
}
