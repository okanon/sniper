
#include <stdlib.h>
#include <netinet/in.h>

/*
 * sphirewalld pcaket.h 
 * http://sphirewall.sourceforge.net/data/docs/packet_8h_source.html
 *
 */


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

#define NULLHDRSIZE 4
#define IPHDRSIZE sizeof(struct iphdr)
#define TCPHDRSIZE sizeof(struct tcphdr)
#define IPTCPHDRSIZE IPHDRSIZE + TCPHDRSIZE


/* Ethernet header */
struct sniff_ethernet {
   u_char ether_dhost[ETHER_ADDR_LEN];
   u_char ether_Shost[ETHER_ADDR_LEN];
   u_short ether_type;
};


/*
 * k.okamoto C1CMP icmp.h
 * https://gitlab.com/accelia-ne2020/c1cmp/-/blob/master/src/icmp.h
 */


/* IP header */
struct iphdr {
   u_char  ip_vhl;
   u_char  ip_tos;
   u_short ip_len;
   u_short ip_id;
   u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char  ip_ttl;
	u_char  ip_p;
	u_short ip_sum;
	struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)   (((ip)->ip_vhl) >> 4)


/* TCP header */
typedef u_int tcp_seq;

struct tcphdr {
   u_short th_sport;
   u_short th_dport;
   tcp_seq th_seq;
   tcp_seq th_ack;
   u_char  th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
   u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS   (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win;
   u_short th_sum;
   u_short th_urp;
};


struct pseudohdr {
   u_int32_t src;
   u_int32_t dst;
   u_char zero;
   u_char protocol;
   u_int16_t tcp_len;
};
