#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string.h>

err_t validate_interface();

void on_packet(
    unsigned char *user,
    const struct pcap_pkthdr *pkthdr,
    const unsigned char *packet
);

err_t sniff();

#endif
