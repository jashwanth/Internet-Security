#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "192.168.56.101"
struct sockaddr_in peerAddr;

int createTunDevice(char *dev) {
   int tunfd, err;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

 //  tunfd = open("/dev/net/tun", O_RDWR);
   if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0 ) {
     perror("Opening /dev/net/tun");
     return tunfd;
   }

   if ((err = ioctl(tunfd, TUNSETIFF, (void *)&ifr)) < 0 ) {
     perror("ioctl(TUNSETIFF)");
     close(tunfd);
     return err;
   }


//   ioctl(tunfd, TUNSETIFF, &ifr);       
   strcpy(dev, ifr.ifr_name);
   return tunfd;
}

int connectToUDPServer() {
    int sockfd;
    char *hello="Hello";

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Send a hello message to "connect" with the VPN server
    if (sendto(sockfd, hello, strlen(hello), 0,
              (struct sockaddr *)&peerAddr, sizeof(peerAddr))  < 0) {
      perror("sendto()");
      exit(1); 
    }

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

int main (int argc, char * argv[]) {
   int tunfd, sockfd;
   char if_name[IFNAMSIZ] = "";
   tunfd  = createTunDevice((char *)&if_name);
   printf("Successfully connected to the interface %s\n", if_name);
   sockfd = connectToUDPServer();

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


