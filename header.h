#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_header{
    unsigned char ether_des_addr[ETHER_ADDR_LEN];
    unsigned char ether_src_addr[ETHER_HDR_LEN];
    unsigned short ether_type;
};

struct ip_header{
    unsigned char ip_ver_and_header_length;
    unsigned char ip_service_type;
    unsigned short ip_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_checksum;
    unsigned int ip_src_addr;
    unsigned int ip_des_addr;
};

struct tcp_header{
    unsigned short tcp_src_port;
    unsigned short tcp_des_port;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char reserved:4;
    unsigned char tcp_offset:4;
    unsigned char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x03
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;
};
