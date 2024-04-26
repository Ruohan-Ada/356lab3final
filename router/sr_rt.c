/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance *sr, const char *filename)
{
    FILE *fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if (access(filename, R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");

    while (fgets(line, BUFSIZ, fp) != 0)
    {
        sscanf(line, "%s %s %s %s", dest, gw, mask, iface);
        if (inet_aton(dest, &dest_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1;
        }
        if (clear_routing_table == 0)
        {
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance *sr)
{
    struct sr_if *interface = sr->if_list;
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface)
    {
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance *sr, struct in_addr dest,
                     struct in_addr gw, struct in_addr mask, uint32_t metric, char *if_name)
{
    struct sr_rt *rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_locker));
    /* -- empty list special case -- */
    if (sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt *)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface, if_name, sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
    }

    rt_walker->next = (struct sr_rt *)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface, if_name, sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;

    pthread_mutex_unlock(&(sr->rt_locker));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance *sr)
{
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_rt *rt_walker = 0;

    if (sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;

    while (rt_walker)
    {
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_locker));

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt *entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    char buff[20];
    struct tm *timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t", inet_ntoa(entry->dest));
    printf("%s\t", inet_ntoa(entry->gw));
    printf("%s\t", inet_ntoa(entry->mask));
    printf("%s\t", entry->interface);
    printf("%d\t", entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1)
    {
        /*printf("rip timeout\n");*/
        sleep(5);
        pthread_mutex_lock(&(sr->rt_locker));
        /* Fill your code here */

        /*check if any entry has expired - instruction 1 */
        struct sr_rt *rt_walker = sr->routing_table;
        while (rt_walker) {
            double time_diff = difftime(time(NULL), rt_walker->updated_time);
            if (time_diff > 20) {
                /*as in instruction, set metric to infinity*/
                rt_walker->metric = INFINITY;
            }
            rt_walker = rt_walker->next;
        }
        
        /*checking status of the router's own interfaces - instruction 2 */
        struct sr_if* interface = sr->if_list;
        while (interface) {
            uint32_t interface_status = sr_obtain_interface_status(sr, interface->name);
            if (interface_status == 0) {
                /*if an interface is down - instruction 2a */
                struct sr_rt *rt_w = sr->routing_table;
                while (rt_w) {
                    if (strcmp(interface->name, rt_w->interface) == 0) {
                        /*delete as setting metric to infinity as instruction*/
                        rt_w->metric = INFINITY;
                    }
                    rt_w = rt_w->next;
                }
            } else {/*if an interface is up - instruction 2b */
                struct sr_rt *rt_w2 = sr->routing_table;
                bool if_contains = false;

                while (rt_w2) {
                    /* ??? may need to check*/
                    if ((rt_w2->dest.s_addr & rt_w2->mask.s_addr) == (interface->ip & interface->mask) && (rt_w2->mask.s_addr == interface->mask)) {
                        /*update the updated time*/
                        rt_w2->updated_time = time(NULL); /*curr time*/
                        rt_w2->gw.s_addr = 0;
                        strcpy(rt_w2->interface, interface->name);
                        rt_w2->metric = 0;
                        if_contains = true;
                    }
                    rt_w2 = rt_w2->next;
                }

                if (if_contains == false) {
                    /*add the subnet to routing table*/
                    struct in_addr dest_addr;
                    struct in_addr gw_addr;
                    struct in_addr mask_addr;
                    dest_addr.s_addr = interface->ip;
                    gw_addr.s_addr = 0x0;
                    mask_addr.s_addr = interface->mask;
                    sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, 0, interface->name);
                }
            }
            interface = interface->next;
        }

        /*send out the RIP response - instruction 3*/
        send_rip_response(sr);

        pthread_mutex_unlock(&(sr->rt_locker));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr) {
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;
    while(if_walker) {
        unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
        uint8_t *packet = (uint8_t *) malloc(len);
        memset(packet, 0, sizeof(uint8_t) * len);
        
        sr_ethernet_hdr_t *pac_eth_hdr = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *pac_ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t *pac_udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t *pac_rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

        pac_eth_hdr->ether_type = htons(ethertype_ip);
        memcpy(pac_eth_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
        memset(pac_eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);

        pac_ip_hdr->ip_hl = 0x5; /* assuming no option, header length is 5 (20 bytes)*/
        pac_ip_hdr->ip_v  = 0x4; /* IPv4 */
        pac_ip_hdr->ip_tos = 0;
        pac_ip_hdr->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)));
        pac_ip_hdr->ip_id = 0;
        pac_ip_hdr->ip_off = 0;
        pac_ip_hdr->ip_ttl = 100;
        pac_ip_hdr->ip_p = ip_protocol_udp;
        pac_ip_hdr->ip_sum = 0;
        pac_ip_hdr->ip_src = if_walker->ip;
        pac_ip_hdr->ip_dst = htonl(0xffffffff); /* convert IP address to network byte order*/
        pac_ip_hdr->ip_sum = cksum(pac_ip_hdr, sizeof(sr_ip_hdr_t));

        pac_udp_hdr->port_dst = 520;
        pac_udp_hdr->port_src = 520;
        pac_udp_hdr->udp_len = htons((uint16_t) (sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)));
        pac_udp_hdr->udp_sum = 0;
        pac_udp_hdr->udp_sum = cksum(pac_udp_hdr, sizeof(sr_udp_hdr_t));

        pac_rip_hdr->command = 1; /* request */
        pac_rip_hdr->version = 2; /* RIP version 2*/
        pac_rip_hdr->unused = 0;
        pac_rip_hdr->entries[0].metric = INFINITY;

        sr_send_packet(sr, packet, len, if_walker->name);
        free(packet);
        if_walker = if_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

void send_rip_response(struct sr_instance *sr) {
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;
    while(if_walker) {
        unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
        uint8_t *packet = (uint8_t *) malloc(len);
        memset(packet, 0, sizeof(uint8_t) * len);
        
        sr_ethernet_hdr_t *pac_eth_hdr = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *pac_ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t *pac_udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t *pac_rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

        pac_eth_hdr->ether_type = htons(ethertype_ip);
        memcpy(pac_eth_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
        memset(pac_eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);

        pac_ip_hdr->ip_hl = 0x5; /* assuming no option, header length is 5 (20 bytes)*/
        pac_ip_hdr->ip_v  = 0x4; /* IPv4 */
        pac_ip_hdr->ip_tos = 0;
        pac_ip_hdr->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)));
        pac_ip_hdr->ip_id = 0;
        pac_ip_hdr->ip_off = 0;
        pac_ip_hdr->ip_ttl = 100;
        pac_ip_hdr->ip_p = ip_protocol_udp;
        pac_ip_hdr->ip_sum = 0;
        pac_ip_hdr->ip_src = if_walker->ip;
        pac_ip_hdr->ip_dst = htonl(0xffffffff); /* convert IP address to network byte order*/
        pac_ip_hdr->ip_sum = cksum(pac_ip_hdr, sizeof(sr_ip_hdr_t));

        pac_udp_hdr->port_dst = 520;
        pac_udp_hdr->port_src = 520;
        pac_udp_hdr->udp_len = htons((uint16_t) (sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)));
        pac_udp_hdr->udp_sum = 0;
        pac_udp_hdr->udp_sum = cksum(pac_udp_hdr, sizeof(sr_udp_hdr_t));
        
        pac_rip_hdr->command = 2; /* response */
        pac_rip_hdr->version = 2; /* RIP version 2*/
        pac_rip_hdr->unused = 0;

        struct sr_rt *rt_entry = sr->routing_table;
        memset(&pac_rip_hdr->entries, 0, MAX_NUM_ENTRIES * sizeof(struct entry));

        int i = 0;
        while (rt_entry) {
            if (strcmp(rt_entry->interface, if_walker->name) != 0) {
                pac_rip_hdr->entries[i].afi = htons(2);
                pac_rip_hdr->entries[i].address = rt_entry->dest.s_addr;
                pac_rip_hdr->entries[i].mask = rt_entry->mask.s_addr;
                pac_rip_hdr->entries[i].next_hop = rt_entry->gw.s_addr;
                pac_rip_hdr->entries[i].metric = rt_entry->metric;
                i ++;
            }
            rt_entry = rt_entry->next;
        }

        sr_send_packet(sr, packet, len, if_walker->name);
        free(packet);
        if_walker = if_walker->next;
    }

    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, uint8_t *ip_packet, char *interface) {
    pthread_mutex_lock(&(sr->rt_locker));
    /* Fill your code here */
    sr_rip_pkt_t *pac_rip_hdr = (sr_rip_pkt_t *) (ip_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));    
    sr_ip_hdr_t *pac_ip_hdr = (sr_ip_hdr_t *) (ip_packet + sizeof(sr_ethernet_hdr_t));

    int i = 0;
    bool if_changed = false;
    for(i = 0; i < MAX_NUM_ENTRIES; i++){
        struct entry rip_e = pac_rip_hdr->entries[i];

        if(rip_e.afi != 0){
            rip_e.metric = (rip_e.metric+1 < INFINITY) ? (rip_e.metric+1) : (INFINITY);

            struct sr_rt *rt_walker = sr->routing_table;
            bool if_contains = false;
            while(rt_walker){
                /*check if your routing table contains the routing entry - instruction 1*/
                if((rip_e.address & rip_e.mask) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)){
                    /*check if the packet is from the same router as the existing entry - instruction 1b*/
                    if(strcmp(rt_walker->interface, interface) == 0){
                        /*upate time and metric - instruction 1b i*/
                        rt_walker->updated_time = time(0);
                        if((rt_walker->metric != INFINITY) && (rip_e.metric == INFINITY)){
                            rt_walker->metric = INFINITY;
                            if_changed = true;
                        }
                        
                    }
                    else{
                        /*instruction 1b ii*/
                        if(rip_e.metric < rt_walker->metric){
                            /*updating all the information in the routing entry*/
                            rt_walker->dest.s_addr = rip_e.address;
                            rt_walker->gw.s_addr = pac_ip_hdr->ip_src;
                            rt_walker->mask.s_addr = rip_e.mask;
                            rt_walker->metric = rip_e.metric;
                            rt_walker->updated_time  = time(0);
                            memcpy(rt_walker->interface, interface, sizeof(unsigned char) * sr_IFACE_NAMELEN);
                            if_changed = true;
                        }
                    }
                    if_contains = true;
                }
                rt_walker = rt_walker->next;
            }

            /*add the routing entry to routing table - instruction 1a*/
            if(if_contains == false){
                struct in_addr dest_addr;
                struct in_addr gw_addr;
                struct in_addr mask_addr;
                dest_addr.s_addr = rip_e.address;
                gw_addr.s_addr = pac_ip_hdr->ip_src;
                mask_addr.s_addr = rip_e.mask;
                sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, rip_e.metric, interface);
                if_changed = true;
            }
        }
    }

    /*send out the RIP response  if the routing table has changed - instruction 2*/
    if(if_changed){
        send_rip_response(sr);
    }

    pthread_mutex_unlock(&(sr->rt_locker));
}