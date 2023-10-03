#include "../include/config.h"
#include "../include/sniffer.h"

err_t validate_interface() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *ifaces = NULL;
  
  int ok = pcap_findalldevs(&ifaces, errbuf);
  if (ok == -1) {
    seterr("failed to list pcap devices!");
    return ERR_GENERIC;
  }
  
  // check whether interface exists
  pcap_if_t *ifc = ifaces;
  while(1) {
    if (ifc == NULL) {
      seterr("specified interface [%s] not found!", config->interface);
      return ERR;
    }
    if (!strcmp(ifc->name, config->interface)) {
      break;
    };
    ifc = ifc->next;
  }

  // check whether interface in monitor mode
  char command[100];
  char result[100];
  snprintf(command, sizeof(command), "iwconfig %s | grep Mode", config->interface);

  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    seterr("failed to execute command: [%s]", command);
    return ERR;
  }

  if (fgets(result, sizeof(result), fp) != NULL) {
    if (strstr(result, "Mode:Monitor") != NULL) {
      return OK;
    } else {
      seterr("interface [%s] not in monitor mode!", config->interface);
      // XXX TODO return ERR;
      return OK;
    }
  } else {
    seterr("failed to read output of command [%s]", command);
    return ERR;
  }
}

void on_packet(unsigned char *conn, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    const unsigned char *wlan_packet = packet;    

    // for(int i =0; i <pkthdr->len; i++) {
    //   printf("%d ", packet[i]);
    // }
    // printf("\n\n");
    // exit(0);

    err_t err = send_data( (conn_t *) conn, wlan_packet+8, pkthdr->len-8);
    if (err != OK) {
      errmsg(err);
    }
}

err_t sniff(conn_t *conn) {
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_live(config->interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    seterr("failed to open live interface %s", config->interface);
    return ERR;
  }

  pcap_loop(handle, -1, on_packet, (unsigned char *)conn);
  pcap_close(handle);

  return OK;
}


