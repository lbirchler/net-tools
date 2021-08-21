/* device-header-types.c

   list all link-layer header types provided by a device
*/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

char errbuf[PCAP_ERRBUF_SIZE];

void get_header_types(char *interface) {

    // create capture handle 
    pcap_t *handle = NULL;
    handle = pcap_create(interface, errbuf);
    if (!handle) {
        printf("unable to create handle for: %s\n", interface);
        return;
    }

    // activate capture handle
    if (pcap_activate(handle) != 0) {
        printf("unable to activate handle\n");
        pcap_close(handle);
        return;
    }
    
    int *dlt_buf;
    int header_types;
    int i;

    header_types = pcap_list_datalinks(handle, &dlt_buf);

    for (i = 0; i < header_types; i++) {
        printf("\t%-3d   %-10s   %s\n", dlt_buf[i], pcap_datalink_val_to_name(dlt_buf[i]), pcap_datalink_val_to_description(dlt_buf[i]));
    }

    pcap_free_datalinks(dlt_buf);

    pcap_close(handle);

}

int main()
{
    pcap_if_t *devices; // head of link device list
    pcap_if_t *device; // iterate through device list

    if (pcap_findalldevs(&devices, errbuf) == 1)
    {
        return 1;
    }

    for (device = devices; device; device = device->next)
    {
        // name
        if (device->flags) {
            // if up and running
            if ((device->flags & PCAP_IF_UP) == PCAP_IF_UP && (device->flags & PCAP_IF_RUNNING) == PCAP_IF_RUNNING) {
                printf("[+] %s\n", device->name);
                get_header_types(device->name);
            }
            // if down
            else {
                printf("[-] %s\n", device->name);
                get_header_types(device->name);
            }
        }

    }
    pcap_freealldevs(devices);

    return 0;
}
