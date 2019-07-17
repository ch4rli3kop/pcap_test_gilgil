#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

struct ethernet_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct ip_header{
    uint8_t vesion_and_length;
    uint8_t type;
    uint16_t length;
    uint16_t identification;
    uint16_t flag_and_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct tcp_header{
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_p;
};


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t* eth){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
}

uint16_t view_ethernet(struct ethernet_header eth){
    printf("######## MAC ##########\n");
    printf("Destination MAC: ");
    print_mac(&eth.dst_mac[0]);
    printf("Source MAC : ");
    print_mac(&eth.src_mac[0]);
    return (eth.type[0] << 8) | eth.type[1];
}

void print_ip(uint8_t* ip){
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

uint8_t view_ip(struct ip_header ip){
    printf("====== IP ======\n");
    printf("Protocol : 0x%x\n", ip.protocol);
    printf("Source IP : ");
    print_ip(&ip.src_ip[0]);
    printf("Destination IP : ");
    print_ip(&ip.dst_ip[0]);
    return ip.protocol;
}

void print_port(uint8_t* port){
    printf("%d\n", port[0] << 8 | port[1]);
}

void view_tcp(struct tcp_header tcp, bpf_u_int32 len, const u_char* p){
    uint8_t header_length = 0;

    printf("============= TCP =============\n");
    printf("Source Port : ");
    print_port(&tcp.src_port[0]);
    printf("Destination Port : ");
    print_port(&tcp.dst_port[0]);

    // print tcp data...*
    header_length = 4 * ((tcp.data_offset & 0xf0) >> 4);
    printf("TCP header length : %d\n", header_length);
    u_char data[10] = "";
    uint8_t data_offset = 0x22 + header_length;
    uint32_t remain = len-data_offset;
    printf("TCP data length : %d\n", remain);
    if (remain == 0) {
        printf("None TCP data\n");
    } else if (remain < 10) {
        memcpy(data, &p[data_offset], remain);
        printf("TCP data : ");
        for (uint32_t i=0; i<remain; i++) printf("%X ", data[i]);
        printf("\n");
    } else {
        memcpy(data, &p[data_offset], 10);
        printf("TCP data : %X %X %X %X %X %X %X %X %X %X\n", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
    }
}

void print_packet_data (const u_char* p, bpf_u_int32 len){
    struct ethernet_header ethernet;
    memcpy(&ethernet, p, 14);
    uint16_t etype = view_ethernet(ethernet);
    printf("Type : 0x%04X\n", etype);

    if (etype == 0x0800){
        struct ip_header ip;
        memcpy(&ip, &p[14], 20);
        uint8_t protocol;
        protocol = view_ip(ip);

        if (protocol == 6){
            struct tcp_header tcp;
            memcpy(&tcp, &p[0x22], 20);
            view_tcp(tcp, len, p);
        }
    }
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    print_packet_data(packet, header->caplen);
  }

  pcap_close(handle);
  return 0;
}
