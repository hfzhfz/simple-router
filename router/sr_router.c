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
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *) packet;

  uint16_t ether_type = ntohs(ether_hdr->ether_type);
  printf("*** -> ether_type %04X \n",ether_type);
  if (ethertype_arp == ether_type)
  {
    printf("*** -> Is Arp \n");
    sr_handle_arp_packet(sr, ether_hdr, packet + sizeof(sr_ethernet_hdr_t), len, interface);
  }
  else if (ethertype_ip == ntohs(ether_hdr->ether_type))
  {
    printf("*** -> Is Ip \n");
    sr_handle_ip_packet(sr, ether_hdr, packet + sizeof(sr_ethernet_hdr_t), len, interface);
  }
  else{
    printf("Neither ip packet, nor arp packet?\n");
    fprintf(stderr, "Neither ip packet, nor arp packet?\n");
  }
}/* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * ether_payload/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ether_payload;

  /* Check crc. */
  /* https://tools.ietf.org/html/rfc1071 */
  uint16_t orig_sum = ip_hdr->ip_sum;
  uint32_t ip_hdr_len =ip_hdr->ip_hl * sizeof(uint32_t);
  ip_hdr->ip_sum = 0;
  uint16_t new_sum = cksum(ether_payload, ip_hdr_len); /* Already in network byte order. */
  
  if (new_sum != orig_sum) /*TODO!!!*/
  {
    fprintf(stderr, "IP header checksum missmatch! orig: %d, new: %d\n", orig_sum, new_sum);
    return;
  }  

  uint8_t *to_send = NULL; unsigned int to_send_len = -1;
  /* Check dest IP. */
  uint32_t ip = ip_hdr->ip_dst;
  if (sr_contains_ip(sr, ip)) 
  {
    fprintf(stderr, "IP addr sent to me (router): %d\n", ip);
    /* Get IP payload protocol. */
    uint8_t protocol = ip_hdr->ip_p;
    if (protocol == ip_protocol_icmp) 
    {
      /* The second field (4 bits) is the Internet Header Length (IHL), which is the number of 32-bit words in the header. */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ether_payload + ip_hdr_len);
      
      if (8 == icmp_hdr->icmp_type) {
       /*TODO check cksum! */ 
        /* Send ICMP echo reply, type = 0, code = 0*/
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, ECHO_REPLY, &to_send, &to_send_len);
        goto send_icmp;
      } 

      fprintf(stderr, "[FATAL] Unhandled icmp type: %d\n", icmp_hdr->icmp_type);
      return;

    }
    else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) 
    {
      /* Send ICMP port unreachable, type = 3, code = 3*/
      sr_create_icmp_packet(sr, ether_hdr, ip_hdr, PORT_UNREACHABLE, &to_send, &to_send_len);
      goto send_icmp;
    } 
    else 
    {
      fprintf(stderr, "[FATAL] Unhandled ip protocl type: %d\n", protocol);
      return;
    }
  }
 
  /* Check the TTL */
  uint8_t ttl = ip_hdr->ip_ttl;
  if (1 >= ttl) 
  {
    fprintf(stderr, "TTL expired.\n");
    /* Send ICMP time exceeded, type = 11, code = 1*/
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, TIME_EXCEEDED, &to_send, &to_send_len);
    goto send_icmp;

  } 

  /* Prepare to send the packet to the next hop. */

  /* perform the longest prefix match */
  uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
  if (0 != longest_prefix_match(sr, ip_hdr->ip_dst, &next_hop_addr, &if_name)) /* TODO confirm byte order*/
  {
    fprintf(stderr, "Dest IP not found: %d\n", ip);
    /* Send ICMP network unrechable, type = 3, code = 0 */
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
    goto send_icmp;
  }

  sr_create_ip_packet(sr, len, ip_hdr, &to_send, &to_send_len);      
  goto arq_lookup_and_send;

  send_icmp: 
  {
    sr_ip_hdr_t *to_send_ip_hdr = (sr_ip_hdr_t *)(to_send + ETHER_HDR_LEN);
    if (0 != longest_prefix_match(sr, to_send_ip_hdr->ip_dst, &next_hop_addr, &if_name)) /* TODO confirm byte order*/
    {
      fprintf(stderr, "[FATAL] Dest IP not found, cannot send ICMP message!\n");
      return;
    }
  }

  arq_lookup_and_send:
    sr_arq_lookup_and_send(sr, to_send, to_send_len, next_hop_addr, if_name);
}

void sr_arq_lookup_and_send(struct sr_instance *sr, uint8_t *to_send, unsigned int to_send_len, uint32_t next_hop_addr, char *if_name) 
{
  struct sr_arpentry *arp = sr_arpcache_lookup(&sr->cache, next_hop_addr); 
  if (NULL != arp) 
  {
             /* TODO send sr_get_interface(sr, if_name)->addr, arp->mac, ip_hdr);*/      
    sr_send_packet_wrapper(sr, to_send, to_send_len, if_name, sr_get_interface(sr, if_name)->addr, arp->mac, true);
    free(arp);
  } 
  else 
  {
    struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, next_hop_addr, (uint8_t *)to_send, to_send_len, if_name); /*TODO which len, where to start?*/ 
    handle_arpreq(req, sr);
  }
}

void sr_handle_arp_packet(
        struct sr_instance *sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * packet/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{
  
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) packet;
  struct sr_if *sr_interface;
  /*check if the arp packet is for me*/
  for (sr_interface = sr->if_list; sr_interface != NULL; sr_interface = sr_interface->next){
    if (arp_hdr->ar_tip == sr_interface->ip){ /* interface IPs are in network order! */
      if(arp_op_request == ntohs(arp_hdr->ar_op)){
        send_arp_reply(sr, ether_hdr, packet, sr_interface);
        return;
      }
      else if (arp_op_reply == ntohs(arp_hdr->ar_op)){
        sr_handle_arp_reply(sr, packet);
        return;
      }
      else{
        fprintf(stderr, "It's an arp packet for me but neither a request nor reply\n");
        return;
      }
    }
  }
  fprintf(stderr, "This arp packet is not for me\n");
}

void sr_create_ip_packet(
        struct sr_instance *sr,
        unsigned int len,
        sr_ip_hdr_t *ip_hdr,
        uint8_t **new_ip_pkt,
        unsigned int *new_len) 

{

  sr_ethernet_hdr_t new_ether_hdr;
  /*memcpy(new_ether_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);*/
  /* memcpy(new_ether_hdr.ether_dhost, dst_mac, ETHER_ADDR_LEN); */
  new_ether_hdr.ether_type = htons(ethertype_ip);  

  /* Directly operate on old ip header */
  
  uint8_t *buf = malloc(len); /*TODO free later!*/
  uint8_t *offset = buf;
  memcpy(offset, &new_ether_hdr, ETHER_HDR_LEN);
  offset += ETHER_HDR_LEN;

  uint32_t ip_len = ntohs(ip_hdr->ip_len) ;
  uint32_t ip_hdr_len =ip_hdr->ip_hl * sizeof(uint32_t);

  memcpy(offset, (uint8_t *)ip_hdr, ip_len);
  uint8_t ttl = ip_hdr->ip_ttl;
  ((sr_ip_hdr_t *)offset)->ip_ttl = ttl - 1;
  ((sr_ip_hdr_t *)offset)->ip_sum = 0;
  ((sr_ip_hdr_t *)offset)->ip_sum = cksum(offset, ip_hdr_len);
  *new_ip_pkt = buf;
  *new_len = len;
  /* sr_send_packet(sr, buf, len, sr_get_if_name(sr, new_ether_hdr.ether_shost)); */
  /*total size is the size including the ethernet header*/
  /* free(buf); */
}

static void cpy_hdrs(
                uint8_t **dest, 
                sr_ethernet_hdr_t * ether_hdr, 
                sr_ip_hdr_t * ip_hdr, 
                sr_icmp_hdr_t * icmp_hdr) 
{
      memcpy(*dest, ether_hdr, sizeof(sr_ethernet_hdr_t));
      (*dest) += sizeof(sr_ethernet_hdr_t);
      memcpy(*dest, ip_hdr, sizeof(sr_ip_hdr_t));
      (*dest) += sizeof(sr_ip_hdr_t);
      memcpy(*dest, icmp_hdr, sizeof(sr_icmp_hdr_t));
      (*dest) += sizeof(sr_icmp_hdr_t);
}

void sr_create_icmp_packet(
        struct sr_instance *sr,
        sr_ethernet_hdr_t *ether_hdr,
        sr_ip_hdr_t *ip_hdr,
        icmp_kind_t icmp_kind,
        uint8_t **new_icmp_pkt,
        unsigned int *new_len) 
{
  sr_ethernet_hdr_t new_ether_hdr;
  
  /*memcpy(new_ether_hdr.ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);*/
  /*memcpy(new_ether_hdr.ether_shost, ether_hdr->ether_dhost, ETHER_ADDR_LEN);*/
  new_ether_hdr.ether_type = htons(ethertype_ip);  

  sr_ip_hdr_t new_ip_hdr;
  /* https://en.wikipedia.org/wiki/IPv4 */
  /* https://en.wikipedia.org/wiki/Time_to_live#cite_note-1 */
  new_ip_hdr.ip_hl = 5; /* default 5 words. TODO */
  new_ip_hdr.ip_v = 4; /* 4 for ipv4. */
  new_ip_hdr.ip_tos = 0; /* 0 for ICMP */
  new_ip_hdr.ip_len = 0; /* TODO, to complete later, Length of entire packet */
  new_ip_hdr.ip_id = 0;  /* htons(0) not used, give a random value. https://tools.ietf.org/html/rfc6864 */
  new_ip_hdr.ip_off = htons(0b0100000000000000); /*TODO http://stackoverflow.com/questions/15999739/ip-fragmentation-and-reassembly */
  new_ip_hdr.ip_ttl = 100; /* Recommended default is 64 */	    
  new_ip_hdr.ip_p = 1; /* 1 for ICMP */	    
  new_ip_hdr.ip_sum = 0;	   /*TODO, to complete later*/ 
  new_ip_hdr.ip_src = sr_get_if_ip(sr, ether_hdr->ether_dhost);
  new_ip_hdr.ip_dst = ip_hdr->ip_src;

  /* https://tools.ietf.org/html/rfc792 */
  sr_icmp_hdr_t new_icmp_hdr;
  switch (icmp_kind) {
    case ECHO_REPLY: 
      new_icmp_hdr.icmp_type = 0;
      new_icmp_hdr.icmp_code = 0;  
      new_ip_hdr.ip_id = ip_hdr->ip_id;  /* htons(0) not used, give a random value. https://tools.ietf.org/html/rfc6864 */
      new_ip_hdr.ip_src = ip_hdr->ip_dst;
      break; 
    case TIME_EXCEEDED: 
      new_icmp_hdr.icmp_type = 11;
      new_icmp_hdr.icmp_code = 0;  
      break;
    case PORT_UNREACHABLE: 
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 3;  
      new_ip_hdr.ip_src = ip_hdr->ip_dst;
      break;
    case NETWORK_UNREACHABLE: 
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 0;  
      break;
    case HOST_UNREACHABLE:
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 1;
      uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
      if (0 != longest_prefix_match(sr, ip_hdr->ip_dst, &next_hop_addr, &if_name)) /* TODO confirm byte order*/
      {
        fprintf(stderr, "Dest IP not found for host unreachable\n");
      }
       
      new_ip_hdr.ip_src = sr_get_interface(sr, if_name)->ip;
      break;
  }
  new_icmp_hdr.icmp_sum = 0; /*cksum(&new_icmp_hdr, 2);*/

  uint8_t *buf, *offset;
  int new_ether_frame_len, new_ip_datagram_len, new_icmp_payload_len;
  int ip_datagram_len = ntohs(ip_hdr->ip_len),
      ip_hdr_len      = ip_hdr->ip_hl * sizeof(uint32_t);
  switch (icmp_kind) {
    case ECHO_REPLY: {
 
      /* This 16-bit field defines the entire packet size, including header and data, in bytes. */
      new_ether_frame_len = ETHER_HDR_LEN + ip_datagram_len;
      offset = buf = malloc(new_ether_frame_len); 
      cpy_hdrs(&offset, &new_ether_hdr, &new_ip_hdr, &new_icmp_hdr);

      /* The second field (4 bits) is the Internet Header Length (IHL), which is the number of 32-bit words in the header. */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(((uint8_t *)ip_hdr) + ip_hdr_len); /* Point arith! */

      /*if (0 == icmp_hdr->icmp_code) */
      /*  memset(offset, 0, sizeof(uint32_t)); */
      /* else */ 
      memcpy(offset, ((uint8_t *)icmp_hdr) + ICMP_HDR_LEN, sizeof(uint32_t));
      offset += sizeof(uint32_t);

      uint32_t new_icmp_payload_len = ip_datagram_len - ip_hdr_len - ICMP_HDR_LEN - sizeof(uint32_t);
      memcpy(offset, ((uint8_t *)icmp_hdr) + ICMP_HDR_LEN + sizeof(uint32_t), new_icmp_payload_len);
      break; 
    }  
    case TIME_EXCEEDED: 
    case PORT_UNREACHABLE:
    case HOST_UNREACHABLE: 
    case NETWORK_UNREACHABLE: {

      new_ether_frame_len =   ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + sizeof(uint32_t);
      new_icmp_payload_len = ip_hdr_len + 8;
      new_ether_frame_len += new_icmp_payload_len;
      offset = buf = malloc(new_ether_frame_len); /*TODO free later!*/
      cpy_hdrs(&offset, &new_ether_hdr, &new_ip_hdr, &new_icmp_hdr);

      memset(offset, 0, sizeof(uint32_t));
      offset += sizeof(uint32_t);
      ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);
      memcpy(offset, ip_hdr, new_icmp_payload_len);
    
      break;
    }
  }
  
  new_ip_datagram_len = new_ether_frame_len - ETHER_HDR_LEN;

  /* fill in IP datagram length */
  sr_ip_hdr_t *new_ip_hdr_cpy = (sr_ip_hdr_t *)(buf + ETHER_HDR_LEN);
  new_ip_hdr_cpy->ip_len = htons(new_ip_datagram_len);

  /* create checksum for ICMP */
  sr_icmp_hdr_t *new_icmp_hdr_cpy = (sr_icmp_hdr_t *)(buf + ETHER_HDR_LEN + IP_HDR_LEN);
  new_icmp_hdr_cpy->icmp_sum = cksum(new_icmp_hdr_cpy, new_ip_datagram_len - IP_HDR_LEN);

  /* create checksum for IP */
  new_ip_hdr_cpy->ip_sum = cksum(new_ip_hdr_cpy, IP_HDR_LEN);

  *new_icmp_pkt = buf;
  *new_len = new_ether_frame_len;
  /* TODO, pass in source mac because in sending packet they make sure the interface is included in iflist*/
  /* sr_send_packet(sr, buf, new_ether_frame_len, sr_get_if_name(sr, new_ether_hdr.ether_shost)); */
  /*total size is the size including the ethernet header*/
  /* free(buf); */
}


void sr_send_packet_wrapper(struct sr_instance* sr, uint8_t* buf, unsigned int len, const char* ifname, unsigned char src_mac[ETHER_ADDR_LEN], unsigned char dst_mac[ETHER_ADDR_LEN], bool should_free) 
{
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)buf;
  memcpy(ether_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  sr_send_packet(sr, buf, len, (ifname == NULL) ? sr_get_if_name(sr, ether_hdr->ether_shost) : ifname); 
  if (should_free) free(buf); 
}
