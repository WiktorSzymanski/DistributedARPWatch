#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <zmq.h>

#include <errno.h>

struct arp_d {
  u_int8_t mac_addr[6];
  u_int8_t ip_addr[4];
};

struct arphdr {
  u_int16_t ftype;
  u_int16_t ptype;
  u_int8_t flen;
  u_int8_t plen;
  u_int16_t opcode;
  u_int8_t sender_mac_addr[6];
  u_int8_t sender_ip_addr[4];
  u_int8_t target_mac_addr[6];
  u_int8_t target_ip_addr[4];
};

char* errbuf;
pcap_t* handle;
struct ethhdr* fhead;
struct arphdr* arphead;
int sfd, rc;
struct sockaddr_in saddr;
struct hostent* addrent;

void cleanup() {
  pcap_close(handle);
  free(errbuf);
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  arphead = (struct arphdr*)(bytes + sizeof(struct ethhdr));

  struct arp_d* arp_data = malloc(sizeof(struct arp_d));

  memcpy(arp_data->mac_addr, arphead->sender_mac_addr, sizeof(arphead->sender_mac_addr));
  memcpy(arp_data->ip_addr, arphead->sender_ip_addr, sizeof(arphead->sender_ip_addr));

  printf("\tMAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    arp_data->mac_addr[0], arp_data->mac_addr[1], arp_data->mac_addr[2],
    arp_data->mac_addr[3], arp_data->mac_addr[4], arp_data->mac_addr[5]);
  printf("\tIP: %u.%u.%u.%u\n", arp_data->ip_addr[0], arp_data->ip_addr[1], arp_data->ip_addr[2], arp_data->ip_addr[3]);   
  

  sfd = socket(PF_INET, SOCK_STREAM, 0);
  if (connect(sfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
    perror("Connect error");
    exit(EXIT_FAILURE);
  }

  rc = write(sfd, arp_data, sizeof(struct arp_d));
  close(sfd);

  printf("write: %d\n", rc);
  if (rc == -1) {
    fprintf(stderr, "write error: %s\n", strerror(errno));
  }
  free(arp_data);
}


int main(int argc, char** argv) {
  // addrent = gethostbyname("localhost");
  addrent = gethostbyname(argv[2]);
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  // saddr.sin_port = htons(atoi("1234"));
  saddr.sin_port = htons(atoi(argv[3]));
  memcpy(&saddr.sin_addr.s_addr, addrent->h_addr, addrent->h_length);

  bpf_u_int32 netp, maskp;
  struct bpf_program fp;

  atexit(cleanup);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(argv[1], errbuf);
  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);
  pcap_activate(handle);
  pcap_lookupnet(argv[1], &netp, &maskp, errbuf);
  pcap_compile(handle, &fp, "arp", 0, maskp);
  if (pcap_setfilter(handle, &fp) < 0) {
    pcap_perror(handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }
  pcap_loop(handle, -1, trap, NULL);
}
