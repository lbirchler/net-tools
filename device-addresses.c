/* devices.c
  
   display list of network devices and addresses
*/
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>       // inet_ntop
#include <netinet/in.h>      // struct sockaddr_in and struct sockaddr_in6
#include <linux/if_packet.h> // sockaddr_ll


int list_addresses(struct pcap_addr *address)
{
    if (address->addr == NULL)
    {
        return 1;
    }

    char ntopbuf[256];

    // inet
    if (address->addr->sa_family == AF_INET)
    {
        // treated as struct sockaddr_in
        printf("\tinet   %s\n", inet_ntop(
                                AF_INET, 
                                &((struct sockaddr_in *)address->addr)->sin_addr, 
                                ntopbuf, 
                                sizeof(ntopbuf)));
    }
    // inet6
    else if (address->addr->sa_family == AF_INET6)
    {
        // treated as struct sockaddr_in6
        printf("\tinet6  %s\n", inet_ntop(
                                AF_INET6, 
                                &((struct sockaddr_in6 *)address->addr)->sin6_addr, 
                                ntopbuf, 
                                sizeof(ntopbuf)));
    } 
    // link/ether 
    else if (address->addr->sa_family == AF_PACKET)
    {
        struct sockaddr_ll *s = (struct sockaddr_ll *)address->addr;

        printf("\teth    %02x:%02x:%02x:%02x%02x:%02x\n", 
                                s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                                s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
    }

    return 0;
}

int main()
{
    pcap_if_t *devices; // head of link device list
    pcap_if_t *device; // iterate through device list
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devices, errbuf) == 1)
    {
        return 1;
    }

    for (device = devices; device; device = device->next)
    {
        // name
        if (device->flags) {
            // if up and running
            if ((device->flags & PCAP_IF_UP) == PCAP_IF_UP && (device->flags & PCAP_IF_RUNNING) == PCAP_IF_RUNNING)
                printf("[+] %s\n", device->name);
            // if down
            else
                printf("[-] %s\n", device->name);
        }

        // addresses
        for (struct pcap_addr *address = device->addresses; address; address = address->next)
        {
            if (list_addresses(address) == 1)
            {
                printf("error with: parse_addresses()\n");
            }
        }
    }
    pcap_freealldevs(devices);

    return 0;
}
