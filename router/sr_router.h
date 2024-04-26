/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H
 
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include <stdbool.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"

void sr_handlearp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
struct sr_if *sr_longest_prefix_match_iface(struct sr_instance *sr, uint32_t ip);
void send_arp_request(struct sr_instance *sr, uint32_t tip, unsigned int len);
void handle_arp_reply(struct sr_instance *sr, struct sr_if *iface, sr_arp_hdr_t *arp);
void send_arp_reply(struct sr_instance *sr, sr_ethernet_hdr_t *eth, sr_arp_hdr_t *arp, struct sr_if *iface);
void handle_arp_request(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hdr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */);
void send_icmp11_message(struct sr_instance * sr, sr_ip_hdr_t * ip, struct sr_if* interface, uint8_t icmp_type, uint8_t icmp_code);
void icmp_unreachable(struct sr_instance * sr, uint8_t code, sr_ip_hdr_t * ip, char* interface);
struct sr_rt *prefix_match(struct sr_instance *sr, uint32_t addr);
void sr_handleip(struct sr_instance *sr, uint8_t *buf, unsigned int len, char *interface);
void sr_icmp_send_message(struct sr_instance *sr, uint8_t type, uint8_t code, sr_ip_hdr_t *ip, char *interface);

#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                        \
  do                                       \
  {                                        \
    int ivyl;                              \
    for (ivyl = 0; ivyl < 5; ivyl++)       \
      printf("%02x:",                      \
             (unsigned char)(x[ivyl]));    \
    printf("%02x", (unsigned char)(x[5])); \
  } while (0)
#else
#define Debug(x, args...) \
  do                      \
  {                       \
  } while (0)
#define DebugMAC(x) \
  do                \
  {                 \
  } while (0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
  int sockfd;        /* socket to server */
  char user[32];     /* user name */
  char host[32];     /* host name */
  char template[30]; /* template name if any */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;          /* address to server */
  struct sr_if *if_list;               /* list of interfaces */
  struct sr_rt *routing_table;         /* routing table */
  struct sr_if_status_cache *if_cache; /* interfaces' status cache*/
  pthread_mutex_t rt_lock;
  pthread_mutexattr_t rt_lock_attr;
  pthread_mutex_t rt_locker;
  pthread_mutexattr_t rt_locker_attr;
  struct sr_arpcache cache; /* ARP cache */
  pthread_attr_t attr;
  pthread_attr_t rt_attr;
  FILE *logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

void send_arp_reply(struct sr_instance *sr, sr_ethernet_hdr_t *eth, sr_arp_hdr_t *arp, struct sr_if *iface);
void send_arp_request(struct sr_instance *sr, uint32_t tip, unsigned int len);

#endif /* SR_ROUTER_H */
