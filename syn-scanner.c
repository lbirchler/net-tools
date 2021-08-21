// syn-scanner.c
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <pcap.h>
#include <libnet.h>

#include <netinet/tcp.h>

// static int snaplen = 65535;    // snapshot length
// static int timeout = 1000;     // buffer timeout in milliseconds (set to -1 for no timeout effect)
// static int buffer_size = 2048; // buffer size in bytes
// static int promisc = 0;        // promiscuous mode on/off
// static int packet_count = -1;  // number of packets that will be processed (-1 and 0 are both equal to infinity)

int response = 0;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

void usage(char *name)
{
    fprintf(stderr, "[+] usage: %s -i ip address\n", name);
}

int main(int argc, char *argv[])
{
    char *device = "enp3s0";

    // libnet
    libnet_t *lnet;
    libnet_ptag_t tcp, ip;
    u_long src_ip = 0;
    u_long dst_ip = 0;
    int src_prt = 0;
    int target_ports[] = {21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 0};
    char lnet_errbuf[LIBNET_ERRBUF_SIZE];

    // libpcap
    pcap_t *handle;
    char *filter = "(tcp[13] == 0x14) || (tcp[13] == 0x12)";
    struct bpf_program fp;
    bpf_u_int32 netmask;
    bpf_u_int32 addr;
    char lpcap_errbuf[PCAP_ERRBUF_SIZE];

    int c;

    //  create libnet environment
    lnet = libnet_init(LIBNET_RAW4, "192.168.1.79", lnet_errbuf);
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
            exit(1);
        }
    }

    // set src ip address
    if ((src_ip = libnet_get_ipaddr4(lnet)) == -1)
    {
        fprintf(stderr, "error gathering src ip: libnet_get_ipaddr4() %s\n", libnet_geterror(lnet));
        exit(1);
    }

    // set src device
    // device = libnet_getdevice(lnet);
    // if (!device) {
    //     fprintf(stderr, "error gathering src device: libnet_getdevice() %s\n", lnet_errbuf);
    //     exit(1);
    // }

    // create capture handle
    handle = pcap_create(device, lpcap_errbuf);
    if (!handle)
    {
        fprintf(stderr, "error creating capture handle: pcap_create(): %s\n", lpcap_errbuf);
        exit(1);
    }

    // set handle options
    // if (pcap_set_snaplen(handle, snaplen) != 0 || pcap_set_timeout(handle, timeout) != 0 || pcap_set_buffer_size(handle, buffer_size) != 0 || pcap_set_promisc(handle, promisc) != 0) {
    //     printf("error setting handle options\n");
    //     pcap_close(handle);
    //     exit(1);
    // }

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

    int packets_per_scan = 10;
    int scan_count = 1;
    int i, j;

    for (tcp = LIBNET_PTAG_INITIALIZER, ip = 1; scan_count--;)
    {

        for (i = 0, j = 0; target_ports[i] != 0 && j < packets_per_scan; i++, j++)
        {

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

            // if (tcp == -1)
            // {
            //     fprintf(stderr, "error building tcp packet: libnet_build_tcp() %s\n", lnet_errbuf);
            //     exit(1);
            // }

            // create ip header
            if (ip)
            {
                ip = 0;
                libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H,   // ip_len
                    0,                              // tos
                    libnet_get_prand(LIBNET_PRu16), // id
                    0,                              // frag
                    // libnet_get_prand(LIBNET_PR8),   // ttl
                    125,         // ttl
                    IPPROTO_TCP, // prot
                    0,           // sum
                    src_ip,      // src ip
                    dst_ip,      // dst ip
                    NULL,        // payload
                    0,           // payload size
                    lnet,        // libnet context
                    ip           // protocol tag
                );
            }

            // if (ip == -1)
            // {
            //     fprintf(stderr, "error building ip packet: libnet_ipv4() %s\n", lnet_errbuf);
            //     exit(1);
            // }

            if ((libnet_write(lnet)) == -1)
            {
                fprintf(stderr, "error building ip packet: libnet_ipv4() %s\n", libnet_geterror(lnet));
                exit(1);
            }

            printf("%15s:%5d ------> %15s:%5d \tpackets sent: %d\n",
                   libnet_addr2name4(src_ip, 1),
                   ntohs(src_prt),
                   libnet_addr2name4(dst_ip, 1),
                   target_ports[i],
                   j);

            printf(" == processing packet ==\n");
            response = 1;
            // time_t tv;
            // tv = time(NULL);

            while (response)
            {
                if ((pcap_loop(handle, -1, packet_handler, NULL) < 0)) {
                    printf("error with port %d\n", target_ports[i]);
                    response = 0;
                }
                // pcap_dispatch(handle, -1, packet_handler, NULL);
                // if ((time(NULL) - tv) > 2)
                // {
                //     response = 0;
                //     printf("-- port %d timed out -- appears to be filtered\n", target_ports[i]);
                // }
            }
        }
    }
    pcap_close(handle);

    exit(0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct tcphdr *tcp = (struct tcphdr *)(packet + LIBNET_IPV4_H + LIBNET_ETH_H);

    if (tcp->th_flags == 0x14)
    {
        printf("-- port %d appears to be closed\n", (unsigned int)ntohs(tcp->th_sport));
        response = 0;
    }
    else if (tcp->th_flags == 0x12)
    {
        printf("-- port %d appears to be open\n", (unsigned int)ntohs(tcp->th_sport));
        response = 0;
    }
}