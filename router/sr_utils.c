#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"

uint16_t cksum(const void *_data, int len)
{
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0; len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons(~sum);
  return sum ? sum : 0xffff;
}

uint16_t ethertype(uint8_t *buf)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf)
{
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr)
{
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++)
  {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address)
{
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr, "inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip)
{
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf)
{
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf)
{
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length)
{

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength)
  {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip)
  { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength)
    {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp)
    { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp)
  { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else
  {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

int sr_send_nonecho_icmp(struct sr_instance *sr, uint8_t *received_packet, struct sr_if *rec_iface, uint8_t icmp_type, uint8_t icmp_code)
{
  /* allocate space for the outgoing packet*/
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *out_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  bzero(out_packet, len);

  /* construct ethernet header*/
  sr_ethernet_hdr_t *outgoing_ehdr = (sr_ethernet_hdr_t *)out_packet;
  sr_ethernet_hdr_t *received_ehdr = (sr_ethernet_hdr_t *)received_packet;
  sr_ip_hdr_t *outgoing_iphdr = (sr_ip_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *received_iphdr = (sr_ip_hdr_t *)(received_packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *out_iface = NULL;
  struct sr_rt *walker = sr->routing_table;
  while (walker != NULL)
  {
    if ((walker->mask.s_addr & received_iphdr->ip_src) == walker->dest.s_addr)
    {
      out_iface = sr_get_interface(sr, walker->interface);
    }
    walker = walker->next;
  }
  memcpy(outgoing_ehdr->ether_dhost, received_ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(outgoing_ehdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  outgoing_ehdr->ether_type = htons(ethertype_ip);

  /* construct IP header */
  outgoing_iphdr->ip_tos = received_iphdr->ip_tos;                 /* type of service */
  outgoing_iphdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t)); /* total length */
  outgoing_iphdr->ip_id = 0;                                       /* identification */
  outgoing_iphdr->ip_off = htons(IP_DF);                           /* fragment offset field */
  outgoing_iphdr->ip_ttl = INIT_TTL;                               /* time to live */
  outgoing_iphdr->ip_p = ip_protocol_icmp;                         /* protocol */
  outgoing_iphdr->ip_src = rec_iface->ip;
  outgoing_iphdr->ip_dst = received_iphdr->ip_src;
  outgoing_iphdr->ip_hl = received_iphdr->ip_hl;
  outgoing_iphdr->ip_v = received_iphdr->ip_v;
  outgoing_iphdr->ip_sum = 0;
  outgoing_iphdr->ip_sum = cksum(outgoing_iphdr, sizeof(sr_ip_hdr_t)); /* checksum */

  /* construct ICMP header */
  /* ICMP header */
  if (icmp_type == 0)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else
  {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->next_mtu = 0;
    icmp_hdr->unused = 0;
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;

    memcpy(icmp_hdr->data, received_packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    memcpy(icmp_hdr->data + sizeof(sr_ip_hdr_t), received_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  }

  int res = sr_send_packet(sr, out_packet, len, out_iface->name);
  return res;
}

uint8_t verify_icmp_checksum(uint16_t len, sr_icmp_hdr_t *icmp_hdr)
{
  uint16_t tmp_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;

  if (cksum((uint8_t *)icmp_hdr, ntohs(len) - sizeof(sr_ip_hdr_t)) == tmp_sum)
  {
    icmp_hdr->icmp_sum = tmp_sum;
    return 1;
  }
  else
  {
    icmp_hdr->icmp_sum = tmp_sum;
    return 0;
  }
}

int check_if_ip(struct sr_instance *sr, sr_ip_hdr_t *current) {
  bool if_checked = false;
  struct sr_if *interface = sr->if_list;

  while (interface) {
    if (current->ip_dst == interface->ip) {
      if (sr_obtain_interface_status(sr, interface->name) != 0) {
        return 1;
      } else if (sr_obtain_interface_status(sr, interface->name) == 0) {
        if_checked = true;
      }
    }
    interface = interface->next;
  }

  if (if_checked)
    return 2;
  return 0;
}