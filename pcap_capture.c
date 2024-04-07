
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host addsocs */
  u_char  ether_shost[6]; /* source host addsocs */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};  

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_tcp_offx2:13; //Flags tcp_offx2
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  u_char   iph_sourceip[4]; //Source IP addsocs
  u_char   iph_destip[4];   //Destination IP addsocs
};

struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data tcp_offx2, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
    u_char data[10];
};



void mac(struct ethheader *p) {
	 u_char *smac = p->ether_shost;
	 u_char *dmac = p->ether_dhost;
	
	printf("source mac : %02x:%02x:%02x:%02x:%02x:%02x\n", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	printf("destination mac : %02x:%02x:%02x:%02x:%02x:%02x\n", dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
}

void ip(struct ipheader *p) {
	u_char *src_ip = p->iph_sourceip;
	u_char *dst_ip = p->iph_destip;

	printf("source ip : %u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
	printf("destination ip : %u.%u.%u.%u\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
}

void port(struct tcpheader *p) {
	u_char tcp_sport = p->tcp_sport;
	u_char tcp_dport = p->tcp_dport;

	printf("source port : %d\n", htons(tcp_sport));
	printf("destination port : %d\n", htons(tcp_dport));
}

void data(struct tcpheader *p, u_char len) {
	u_char data = *p->data;

	printf("data(%d) : \"", len);
	if (len > 10) len = 10;
	for (u_char i = 0; i < len; ++i) {
		printf("\\x%02x", p->data[i]);
	}
	printf("\"\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
  char* dev;
  dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }  
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

  while (1) {
   	struct pcap_pkthdr* header;
   	const u_char* packet;
   	int soc = pcap_next_ex(handle, &header, &packet);

    u_char eth_len;
    u_char ip_len;
    u_char tcp_len;

	
		struct ethheader* eth_ptr = (struct ethheader*)packet;
	

		struct ipheader* ip_ptr = (struct ipheader*)(packet + sizeof(struct ethheader*));
	

		struct tcpheader* tcp_ptr = (struct tcpheader*)(packet + sizeof(struct ethheader*) + sizeof(struct ipheader*));
		

		printf("\n\n%u bytes captured\n", header->caplen);
		mac(eth_ptr);
		ip(ip_ptr);
		port(tcp_ptr);
		
		u_char data_len = header->caplen - (sizeof(struct ethheader) + sizeof(struct ipheader) + tcp_ptr->tcp_offx2 * 4);

		data(packet+sizeof(struct ethheader) + sizeof(struct ipheader) + tcp_ptr->tcp_offx2 * 4, data_len);
	}

    pcap_close(handle);
    return 0;
}

