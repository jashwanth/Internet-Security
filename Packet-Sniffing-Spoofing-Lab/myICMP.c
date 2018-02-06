#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "myheader.h"

#define SRC_PORT 80
#define DEST_PORT 9090
#define SRC_IP "10.0.2.6" 
#define DEST_IP "10.0.2.8"

/*****************************************************
  Given a buffer of data, calculate the checksum
 *****************************************************/
unsigned short in_cksum(unsigned short *buf,int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all the
    * carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)  {
     sum += *w++;
     nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
       *(u_char *)(&temp) = *(u_char *)w ;
       sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     // add hi 16 to low 16 
    sum += (sum >> 16);                     // add carry 
    return (unsigned short)(~sum);
}






/*************************************************************
  Given an IP packet, send it out using a raw socket. 
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,  &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, ip, ntohs(ip->iph_len), 0, 
		(struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}


int main()
{
  char buffer[1500];
  int sd;
  struct sockaddr_in sin;
  /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
   * tells the sytem that the IP header is already included;
   * this prevents the OS from adding another IP header.
   */ 
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sd < 0) {
    perror("socket() error");
    exit(-1);
  }

  /*  This data structure is needed when sending the packets
   *  using sockets. Normally, we need to fill out several
   *  fields, but for raw sockets, we only need to fill out
   *  this one field */
  sin.sin_family = AF_INET;

  // Here you can construct the IP packet using buffer[]
  // - construct the IP header ...
  // - construct the TCP/UDP/ICMP header ...
  // - fill in the data part if needed ...
  // Note: you should pay attention to the network/host byte order.
  memset(buffer, 0, sizeof(buffer));
  struct ipheader *ip = (struct ipheader *)buffer;
  struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
  
  /***********************************************
    Step 1: Fill in the ICMP Header
  ***********************************************/
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; // ICMP: Type 8 is request, 0 is reply
  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));  

  /***********************************************
    Step 2: Fill in the IP Header
  ************************************************/
  ip = (struct ipheader *)buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
  ip->iph_destip.s_addr = inet_addr(DEST_IP);
  ip->iph_protocol = 1; // IPPROTO_ICMP is 1, representing ICMP
  ip->iph_len = htons(sizeof(struct ipheader) +  sizeof(struct icmpheader));
  
  /**********************************************
    Step 3: Finally, send the spoofed packet
  **********************************************/
  send_raw_ip_packet(ip); 

  return 0;
}
