#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include <pcap.h>
#include <net/if.h>
#include <netinet/if_ether.h> // ether_header and ether_arp

static char errbuf[PCAP_ERRBUF_SIZE];

char *device = "enp3s0";
char *filter = "arp";
pcap_t *handle;

static int snaplen = 65535;    // snapshot length
static int timeout = 1000;     // buffer timeout in milliseconds (set to -1 for no timeout effect)
static int buffer_size = 2048; // buffer size in bytes
static int promisc = 0;        // promiscuous mode on/off
static int packet_count = -1;  // number of packets that will be processed (-1 and 0 are both equal to infinity)

int i;

void cntrl_c() {
    printf("exiting\n");
    pcap_breakloop(handle);
    pcap_close(handle);
    exit(0);
}

void capture_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void process_arp(const u_char * packet);

int main()  
{
    struct bpf_program fp; // filter program
    bpf_u_int32 netmask;   // device netmask if available
    bpf_u_int32 addr;      // device ip address
    int processes_packets;

    // cntrl_c gracefull quit
    signal(SIGINT, cntrl_c);

    // create capture handle 
    handle = pcap_create(device, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_create(): %s\n", errbuf);
        exit(1);
    }

    // set handle options
    if (pcap_set_snaplen(handle, snaplen) != 0 || pcap_set_timeout(handle, timeout) != 0 || pcap_set_buffer_size(handle, buffer_size) != 0 || pcap_set_promisc(handle, promisc) != 0) {
        printf("error setting handle options\n");
        pcap_close(handle);
        exit(1);
    }

    // activate capture handle
    if (pcap_activate(handle) != 0) {
        printf("error with: pcap_activate()\n");
        exit(1);
    }

    // compile capture filter
    if (pcap_lookupnet(device, &addr, &netmask, errbuf) == PCAP_ERROR) {
        // first determine if netmask exists
        netmask = PCAP_NETMASK_UNKNOWN; 
    }

    if (pcap_compile(handle, &fp, filter, 0, netmask) != 0) {
        fprintf (stderr, "%s", pcap_geterr(handle));
        exit(1);
    };

    // apply capture filter
    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf (stderr, "%s", pcap_geterr(handle));
        exit(1);
    }

    pcap_freecode(&fp);

    // start packet capture
    processes_packets = pcap_loop(handle, packet_count, capture_callback, NULL);
    if (processes_packets < 0) {
        fprintf (stderr, "pcap_loop(): %s", pcap_geterr(handle));
        exit (1);
    }

    // close handle 
    pcap_close(handle);

    return 0;
}

void capture_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // timestamp
    time_t pkt_time = header->ts.tv_sec;
    struct tm ts;
    char buf[16];

    ts = *localtime(&pkt_time);
    strftime(buf, sizeof(buf), "%H:%M:%S", &ts);
    printf("%3d. %s\t", ++i, buf);

    process_arp(packet);
}

void process_arp(const u_char *packet)
{
  struct ether_header *eth_header = (struct ether_header *) packet; 
  struct ether_arp *arp_packet = (struct ether_arp *) (packet + ETH_HLEN);

  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
      printf ("src: %d.%d.%d.%d\tdst: %d.%d.%d.%d\n",
        arp_packet->arp_spa[0],
        arp_packet->arp_spa[1],
        arp_packet->arp_spa[2],
        arp_packet->arp_spa[3],
        arp_packet->arp_tpa[0],
        arp_packet->arp_tpa[1],
        arp_packet->arp_tpa[2],
        arp_packet->arp_tpa[3]);
    }
}
