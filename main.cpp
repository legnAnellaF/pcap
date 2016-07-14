#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header.h"

void pcap_fatal(const char *, const char *);
void decode_ethernet(const unsigned char *);
void decode_ip(const unsigned char *);
unsigned int decode_tcp(const unsigned char *);
void caught_packet(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

int main()
{

    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *pcap_handle;

    device = pcap_lookupdev(errbuf);
    if(device == NULL)
        pcap_fatal("pcap_lookupdev", errbuf);

    printf("device %s sniffing\n", device);

    pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
    if(pcap_handle == NULL)
        pcap_fatal("pcap_open_live", errbuf);

    pcap_loop(pcap_handle, -1, caught_packet, NULL);

    pcap_close(pcap_handle);
}

void caught_packet(unsigned char *user_args, const pcap_pkthdr *cap_header, const unsigned char *packet)
{
    int tcp_header_length, total_header_size, pkt_data_len;

    printf("==== %dByte packets receive ====\n", cap_header->len);

    decode_ethernet(packet);
    decode_ip(packet + ETHER_HDR_LEN);
    tcp_header_length = decode_tcp(packet + ETHER_HDR_LEN + sizeof(struct ip_header));

    total_header_size = ETHER_HDR_LEN + sizeof(struct ip_header) + tcp_header_length;
    pkt_data_len = cap_header->len - total_header_size;
    if(pkt_data_len > 0)
    {
        printf("\t\t\t%uByte packet data\n", pkt_data_len);
    }
    else
        printf("\t\t\tNo packet data\n");
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
    printf("Fatal Error in %s: %s\n", failed_in, errbuf);
    exit(1);
}

void decode_ethernet(const unsigned char *header_start)
{
    int i;
    const struct ether_header *ether_hdr;

    ether_hdr = (const struct ether_header *)header_start;
    printf("[[ Layer 2 :: Ethernet Header ]]\n");
    printf("[ Source: %02x", ether_hdr->ether_src_addr[0]);
    for(i=1; i< ETHER_ADDR_LEN; i++)
        printf(":%02x", ether_hdr->ether_src_addr[i]);
    printf("\tDestination: %02x", ether_hdr->ether_des_addr[0]);
    for(i=1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", ether_hdr->ether_des_addr[i]);
    printf(" ]\n");
}

char * ip_to_str(unsigned int addr)
{
    struct in_addr ip_struct;
    ip_struct.s_addr = addr;
    return inet_ntoa(ip_struct);
}

void decode_ip(const unsigned char *header_start)
{
    const struct ip_header *ip_hdr;

    ip_hdr = (const struct ip_header *)header_start;

    printf("\t(( Layer 3 ::: IP Header ))\n");
    printf("\t( Source: %s\t", ip_to_str(ip_hdr->ip_src_addr));
    printf("Destination: %s )\n", ip_to_str(ip_hdr->ip_des_addr));
}

unsigned int decode_tcp(const unsigned char *header_start)
{
    unsigned int header_size;
    const struct tcp_header *tcp_hdr;

    tcp_hdr = (const struct tcp_header *)header_start;
    header_size = 4 * tcp_hdr->tcp_offset;

    printf("\t\t{{ Layer 4 :::: TCP Header }}\n");
    printf("\t\t{ Source Port: %hu\t", ntohs(tcp_hdr->tcp_src_port));
    printf("Destination Port: %hu }\n", ntohs(tcp_hdr->tcp_des_port));

    return header_size;
}
