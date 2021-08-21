/* devices.c
  
   display list of network devices
*/
#include <stdio.h>
#include <pcap.h>

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
    }

    pcap_freealldevs(devices);

    return 0;
}