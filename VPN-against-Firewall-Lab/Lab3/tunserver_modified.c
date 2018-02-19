#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

struct sockaddr_in peerAddr;

char *progname;

int createTunDevice(char* dev, int flags) {
   int tunfd, err;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
   /*Ideally we have to set this field to flags argument passed
    but this is modified code of simptun.c and hence ignore */
   
   if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0 ) {
     perror("Opening /dev/net/tun");
     return tunfd;
   }

   if ((err = ioctl(tunfd, TUNSETIFF, (void *)&ifr)) < 0 ) {
     perror("ioctl(TUNSETIFF)");
     close(tunfd);
     return err;
   }
   
   strcpy(dev, ifr.ifr_name);
   return tunfd;
}

int initUDPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;                 
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);        

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr*) &server, sizeof(server)); 

    // Wait for the VPN client to "connect".
    bzero(buff, 100);
    int peerAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sockfd, buff, 100, 0,                  
                (struct sockaddr *) &peerAddr, &peerAddrLen);

    printf("Connected with the client: %s\n", buff);
    return sockfd;
}

void tunSelected(int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    sizeof(peerAddr));
}

void socketSelected (int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len);

}


/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> \n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}



int main (int argc, char * argv[]) {
   int tunfd, sockfd,option;
   int flags = IFF_TUN;
   char if_name[IFNAMSIZ] = "";
   progname = argv[0]; 
    
   /* Check command line options */
   while ((option = getopt(argc, argv, "i:uahd")) > 0) {
     switch(option) {
        case 'i':
          strncpy(if_name,optarg,IFNAMSIZ-1);
          break;
        case 'h':
          usage();
          break;
        case 'u':
          flags = IFF_TUN;
          break;
        case 'a':
          flags = IFF_TAP;
         // header_len = ETH_HDR_LEN;
          break;
        default:
          my_err("Unknown option %c\n", option);
          usage();
      }
   }
   if(*if_name == '\0'){
     my_err("Must specify interface name!\n");
     usage();
   }
    
   tunfd  = createTunDevice((char *)&if_name, flags);
   sockfd = initUDPServer();

   // Enter the main loop
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd);
  }
}
 
