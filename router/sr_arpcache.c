#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include <assert.h>

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    
    assert(sr);
    struct sr_arpreq *req;
    for (req = sr->cache.requests; req != NULL; req = req->next){
        handle_arpreq(req, sr);
    }

}

void handle_arpreq(
        struct sr_arpreq *req, 
        struct sr_instance *sr)
{
    assert(req);

    time_t curtime = time(NULL);
    struct sr_packet *temp_pkt;

    if (difftime(curtime, req->sent) >= 1.0){
        if(req->times_sent >= 5){
            /*already 5 times, send icmp host unreachable to sender*/
            for (temp_pkt = req->packets; temp_pkt != NULL; temp_pkt = temp_pkt->next){
                /*send icmp for each packet? or for every host?*/
                uint8_t *packet = temp_pkt->buf;
                /* sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *) packet; */
                uint8_t *offset = packet;
                offset += sizeof(sr_ethernet_hdr_t);                
                sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) offset;

                uint8_t *to_send; unsigned int to_send_len;
                sr_create_icmp_packet(sr, (sr_ethernet_hdr_t *)packet, ip_hdr, HOST_UNREACHABLE, &to_send, &to_send_len);

                uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
                sr_ip_hdr_t *to_send_ip_hdr = (sr_ip_hdr_t *)(to_send + ETHER_HDR_LEN);
                if (0 != longest_prefix_match(sr, to_send_ip_hdr->ip_dst, &next_hop_addr, &if_name)) /* TODO confirm byte order*/
                {
                  fprintf(stderr, "[FATAL] Dest IP not found, cannot send ICMP message!\n");
                  return;
                }
                sr_arq_lookup_and_send(sr, to_send, to_send_len, next_hop_addr, if_name);
            }
            sr_arpreq_destroy(&(sr->cache), req); /*borrowed to destroy?*/
        }
        else{
            /*One second, send arp request*/
            send_arp_request(req, sr);
            curtime = time(NULL);
            req->sent = curtime;
            req->times_sent++;
        }
    }
}

int send_arp_request(
        struct sr_arpreq *req, 
        struct sr_instance *sr)
{
    sr_ethernet_hdr_t arp_req_eth_hdr;
    sr_arp_hdr_t arp_req_arp_hdr;
    
    uint8_t broadcast_ether_dhost[ETHER_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    memcpy(arp_req_eth_hdr.ether_dhost, broadcast_ether_dhost, ETHER_ADDR_LEN*sizeof(uint8_t));
    memcpy(arp_req_arp_hdr.ar_tha, broadcast_ether_dhost, ETHER_ADDR_LEN*sizeof(uint8_t));

    struct sr_if *sr_interface;
    bool found = false;
    for (sr_interface = sr->if_list;sr_interface != NULL; sr_interface = sr_interface->next){
        /* printf("req if: %s, curr if: %s\n",req->packets->iface, sr_interface->name); */
        if (strcmp(req->packets->iface, sr_interface->name) == 0){
            found = true;
            memcpy(arp_req_eth_hdr.ether_shost, sr_interface->addr, ETHER_ADDR_LEN*sizeof(uint8_t));
            memcpy(arp_req_arp_hdr.ar_sha, sr_interface->addr, ETHER_ADDR_LEN*sizeof(uint8_t));
            arp_req_arp_hdr.ar_sip = sr_interface->ip; /*??need to convert?? NO*/

        }
    }
    if (!found) {
        fprintf( stderr, "*** Error: source mac address not found\n");
        return -1;
    }

    arp_req_eth_hdr.ether_type = htons(ethertype_arp);
    arp_req_arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
    arp_req_arp_hdr.ar_pro = htons(ethertype_ip);
    arp_req_arp_hdr.ar_hln = 6;
    arp_req_arp_hdr.ar_pln = 4;
    arp_req_arp_hdr.ar_op = htons(arp_op_request);
    arp_req_arp_hdr.ar_tip = req->ip; /*??need to convert?? NO*/

    int new_ether_frame_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buff = (uint8_t *)malloc(new_ether_frame_len);
    uint8_t *offset = buff;

    memcpy(offset, &arp_req_eth_hdr, sizeof(sr_ethernet_hdr_t));
    offset += sizeof(sr_ethernet_hdr_t);
    memcpy(offset, &arp_req_arp_hdr, sizeof(sr_arp_hdr_t));

    sr_send_packet(sr, buff, new_ether_frame_len, sr_get_if_name(sr, arp_req_eth_hdr.ether_shost));
    printf("Arp Request Sent\n");

    free(buff);
    return 0;
}

int send_arp_reply( 
        struct sr_instance *sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * packet,
        struct sr_if *sr_interface)
{
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) packet;
    sr_ethernet_hdr_t arp_rep_eth_hdr;
    sr_arp_hdr_t arp_rep_arp_hdr;
    
    memcpy(arp_rep_eth_hdr.ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(arp_rep_eth_hdr.ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
    arp_rep_eth_hdr.ether_type = htons(ethertype_arp);

    arp_rep_arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
    arp_rep_arp_hdr.ar_pro = htons(ethertype_ip);
    arp_rep_arp_hdr.ar_hln = 6;
    arp_rep_arp_hdr.ar_pln = 4;
    arp_rep_arp_hdr.ar_op = htons(arp_op_reply);

    memcpy(arp_rep_arp_hdr.ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
    memcpy(arp_rep_arp_hdr.ar_tha, ether_hdr->ether_shost, ETHER_ADDR_LEN);

    arp_rep_arp_hdr.ar_sip = arp_hdr->ar_tip;
    arp_rep_arp_hdr.ar_tip = arp_hdr->ar_sip;


    int new_ether_frame_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buff = (uint8_t *)malloc(new_ether_frame_len);
    uint8_t *offset = buff;

    memcpy(offset, &arp_rep_eth_hdr, sizeof(sr_ethernet_hdr_t));
    offset += sizeof(sr_ethernet_hdr_t);
    memcpy(offset, &arp_rep_arp_hdr, sizeof(sr_arp_hdr_t));

    sr_send_packet(sr, buff, new_ether_frame_len, sr_interface->name);
    printf("Arp Reply Sent\n");

    free(buff);
    return 0;
}

void sr_handle_arp_reply(
      struct sr_instance *sr,
      uint8_t * packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) packet;
  struct sr_arpcache *cache = &(sr->cache);
  struct sr_arpreq *req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
  
  if (req!=NULL){
    struct sr_packet *packet_tmp;
    for(packet_tmp = req->packets; packet_tmp != NULL; packet_tmp = packet_tmp->next){
      uint8_t *buf = packet_tmp->buf;
      /* sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf; */

      struct sr_if *out_if = sr_get_interface(sr, packet_tmp->iface);

      sr_send_packet_wrapper(sr, buf, packet_tmp->len, out_if->name,
                        out_if->addr, arp_hdr->ar_sha, false);
    }
    sr_arpreq_destroy(cache, req);
  }
  else{
    fprintf(stderr, "Received ARP reply but no request ?");
  }
}
/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}
