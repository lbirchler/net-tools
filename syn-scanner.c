// syn-scanner.c
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <pcap.h>
#include <libnet.h>

#include <netinet/tcp.h>

static int snaplen = 65535;    // snapshot length
static int timeout = 1000;     // buffer timeout in milliseconds (set to -1 for no timeout effect)
static int buffer_size = 2048; // buffer size in bytes
static int promisc = 0;        // promiscuous mode on/off
static int packet_count = -1;  // number of packets that will be processed (-1 and 0 are both equal to infinity)

int target_ports[] = {22, 443, 80, 0};
char *filter = "(tcp[13] == 0x02) || (tcp[13] == 0x14) || (tcp[13] == 0x12) || (tcp[13] == 0x04)";
// char *filter = "(host 192.168.1.80 or host 192.168.1.85) and (tcp[13] == 0x02) or (tcp[13] == 0x14) or (tcp[13] == 0x12) or (tcp[13] == 0x04)";

int status = 0;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

void usage(char *name)
{
    fprintf(stderr, "[+] usage: %s -i ip address\n", name);
    exit(1);
}

int main(int argc, char *argv[])
{
    char *device = "enp3s0";

    // libnet
    uint32_t src_ip;
    uint32_t dst_ip;
    libnet_t *lnet;
    libnet_ptag_t tcp = 0, ip_header = 0;
    int src_prt;
    char lnet_errbuf[LIBNET_ERRBUF_SIZE];
    int i;

    size_t total_ports = sizeof target_ports / sizeof *target_ports;
    printf("total_ports %ld\n", total_ports-1);

    // libpcap
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 netmask;
    bpf_u_int32 addr;
    char lpcap_errbuf[PCAP_ERRBUF_SIZE];

    char c;
    if (argc != 3)
        usage(argv[0]);

    //  create libnet environment
    lnet = libnet_init(LIBNET_RAW4, device, lnet_errbuf);
    if (lnet == NULL)
    {
        fprintf(stderr, "error creating libnet env: libnet_init() %s\n", lnet_errbuf);
        exit(1);
    }

    while ((c = getopt(argc, argv, "i:")) != EOF)
    {
        switch (c)
        {
        case 'i':
            // set dst ip address
            if ((dst_ip = libnet_name2addr4(lnet, optarg, LIBNET_RESOLVE)) == -1)
            {
                fprintf(stderr, "error creating libnet env: libnet_init() %s\n", lnet_errbuf);
                exit(1);
            }
            break;
        default:
            usage(argv[0]);
            break;
        }
    }

    // set src ip address
    if ((src_ip = libnet_get_ipaddr4(lnet)) == -1)
    {
        fprintf(stderr, "error gathering src ip: libnet_get_ipaddr4() %s\n", libnet_geterror(lnet));
        exit(1);
    }

    // create capture handle
    handle = pcap_create(device, lpcap_errbuf);
    if (!handle)
    {
        fprintf(stderr, "error creating capture handle: pcap_create(): %s\n", lpcap_errbuf);
        exit(1);
    }

    // set handle options
    if (pcap_set_snaplen(handle, snaplen) != 0 || pcap_set_timeout(handle, timeout) != 0 || pcap_set_buffer_size(handle, buffer_size) != 0 || pcap_set_promisc(handle, promisc) != 0)
    {
        printf("error setting handle options\n");
        pcap_close(handle);
        exit(1);
    }

    // activate capture handle
    if (pcap_activate(handle) != 0)
    {
        printf("error with: pcap_activate()\n");
        exit(1);
    }

    if (pcap_setnonblock(handle, 1, lnet_errbuf) == -1)
    {
        fprintf(stderr, "error with: pcap_setnoblock() %s\n", lpcap_errbuf);
        exit(1);
    }

    // compile capture filter
    if (pcap_lookupnet(device, &addr, &netmask, lpcap_errbuf) == PCAP_ERROR)
    {
        // first determine if netmask exists
        netmask = PCAP_NETMASK_UNKNOWN;
    }

    if (pcap_compile(handle, &fp, filter, 0, netmask) != 0)
    {
        fprintf(stderr, "%s", pcap_geterr(handle));
        exit(1);
    };

    // apply capture filter
    if (pcap_setfilter(handle, &fp) != 0)
    {
        fprintf(stderr, "%s", pcap_geterr(handle));
        exit(1);
    }

    pcap_freecode(&fp);

    // set pseudo rng
    libnet_seed_prand(lnet);

    for (i = 0; target_ports[i] != 0; i++)
    {
        // target_port = target_ports[i];

        // create tcp header
        tcp = libnet_build_tcp(
            src_prt = libnet_get_prand(LIBNET_PRu16), // src port
            target_ports[i],                          // dst port
            libnet_get_prand(LIBNET_PR32),            // seq no
            0,                                        // ack no
            TH_SYN,                                   // flags
            libnet_get_prand(LIBNET_PRu16),           // win size
            0,                                        // checksum
            0,                                        // ugt ptr
            LIBNET_TCP_H,                             // hdr len
            NULL,                                     // payload
            0,                                        // payload size
            lnet,                                     // libnet context
            tcp                                       // protocol tag
        );

        if (tcp == -1)
        {
            fprintf(stderr, "error building tcp packet: libnet_build_tcp() %s\n", lnet_errbuf);
            exit(1);
        }

        // create ip header
        ip_header = libnet_build_ipv4(
            LIBNET_TCP_H + LIBNET_IPV4_H,   // ip_len
            0,                              // tos
            libnet_get_prand(LIBNET_PRu16), // id
            0,                              // frag
            libnet_get_prand(LIBNET_PR8),   // ttl
            IPPROTO_TCP,                    // prot
            0,                              // sum
            src_ip,                         // src ip
            dst_ip,                         // dst ip
            NULL,                           // payload
            0,                              // payload size
            lnet,                           // libnet context
            ip_header                       // protocol tag
        );

        if ((libnet_write(lnet)) == -1)
        {
            fprintf(stderr, "error building ip packet: libnet_ipv4() %s\n", libnet_geterror(lnet));
            exit(1);
        }

        // target port
        printf("port: %-5d", target_ports[i]);

        // source and destingation ip addresses and ports
        printf("%15s:%-5d ------> %15s:%-5d",
               libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE),
               ntohs(src_prt),
               libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE),
               target_ports[i]);

        // start packet capture
        int response = 1;

        while (response == 1)
        {
            pcap_dispatch(handle, -1, packet_handler, NULL);
            if (status == 1)
            {
                pcap_breakloop(handle);
                response = 0;
                status = 0;
            }
        }
    }

    pcap_close(handle);

    exit(0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((unsigned char *)ip + (ip->ip_hl << 2));

    uint8_t flags = tcp->th_flags;

    switch (flags)
    {
    case 0x12:
        printf("SYN ACK    status: open\n");
        status = 1;
        break;
    case 0x14:
        printf("SYN RST    status: closed\n");
        status = 1;
        break;
    default:
        break;
    }
}
