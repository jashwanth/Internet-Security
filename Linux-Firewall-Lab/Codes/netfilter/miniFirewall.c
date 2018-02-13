#include <linux/kernel.h>  // We need this for macro expansion for the printk() loglevel
#include <linux/module.h>  // Every Kernle module must include this header
#include <linux/netfilter.h> // Contains options to register our function with nf_hook_ops struct
#include <linux/netfilter_ipv4.h>  //Contain IPv4 specific definitions for the netfilter
#include <linux/ip.h> // An implementation of TCP/IP protocol suite for LINUX operating system
#include <linux/tcp.h> // TCP headers definitions in the kernel
#include <linux/string.h> // Handlings strings
#include <linux/types.h> // To define kernel level types unsigned int, long int etc.. for kernel level files

// static struct nf_hook_ops telnetFilterHook;
static struct nf_hook_ops netfilter_ops_in;  /* NF_IP_PRE_ROUTING */
static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */

/**********************************************************************
  The below listed signature for hook function in the book example 14.2 
  by professor Du was for Ubuntu 12.04 
  Now the signature is changed as in the below method for 16.04 version

  unsigned int genericOutFilter(unsigned int hooknum, struct sk_buff *skb,
            const struct net_device *in, const struct net_device *out,
                          int (*okfn)(struct sk_buff *)) 
**********************************************************************/
unsigned int genericOutFilter(void *priv, struct sk_buff *skb, 
                              const struct nf_hook_state *state)
{
  /* Return if the packet is empty */
  if (!skb) {
    return NF_ACCEPT;
  }
  struct iphdr *iph;
  iph = ip_hdr(skb);
   
  //unsigned int src_ip = (unsigned int)iph->saddr;
  //unsigned int dst_ip = (unsigned int)iph->daddr;

  char source_ip[16], destination_ip[16];
  snprintf(source_ip, 16, "%pI4", &iph->saddr);
  snprintf(destination_ip, 16, "%pI4", &iph->daddr);

  /* Drop the ping packets to the destination of www.syracuse.edu */
  if (strcmp(destination_ip, "128.230.18.198") == 0) {
     if (iph->protocol == IPPROTO_ICMP) {
       printk(KERN_INFO "Dropping ping packets to the destination www.syracuse.edu");
       return NF_DROP;
     } else {
       return NF_ACCEPT;
     }
  }
  if (strcmp(destination_ip, "10.0.2.8") == 0) {
     if (iph->protocol == IPPROTO_ICMP) { 
       printk(KERN_INFO "Dropping ping request/echo packets to the Virtual Machine with IP 10.0.2.8");
       return NF_DROP;
     } else {
       return NF_ACCEPT;
     }
  }
  if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        tcph = (void *)iph+iph->ihl*4;
        if (tcph->dest == htons(23)) {
           printk(KERN_INFO "Dropping telnet packet to destination: %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], 
               ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]); 
           return NF_DROP;
        } else {
           return NF_ACCEPT;
        } 
  }
  else {
    return NF_ACCEPT;
  }
}

unsigned int genericInFilter(void *priv, struct sk_buff *skb, 
                            const struct nf_hook_state *state) {
  /* Return if the packet is empty */
  if (!skb) {
    return NF_ACCEPT;
  }
  
  struct iphdr *iph;
  struct tcphdr *tcph;
  iph =  ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;
  
  char source_ip[16], destination_ip[16];
  snprintf(source_ip, 16, "%pI4", &iph->saddr);
  snprintf(destination_ip, 16, "%pI4", &iph->daddr);
  
  if (strcmp(source_ip, "10.0.2.8") == 0) {
     if (iph->protocol == IPPROTO_ICMP) { 
       printk(KERN_INFO "Dropping ping request/echo packets from the Virtual Machine with IP 10.0.2.8");
       return NF_DROP;
     } else {
       return NF_ACCEPT;
     }  
  } 
  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)) {
      printk(KERN_INFO "Dropping Incoming telnet packet from Source: %d.%d.%d.%d\n",
           ((unsigned char *)&iph->saddr)[0], ((unsigned char *)&iph->saddr)[1], 
           ((unsigned char *)&iph->saddr)[2], ((unsigned char *)&iph->saddr)[3]); 
      return NF_DROP;
  }
  
  return NF_ACCEPT;
}

int setUpFilter(void) {
  printk(KERN_INFO "Registering genericIngress and genericEgress filter");
/*  telnetFilterHook.hook = telnetFilter;
  telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
  telnetFilterHook.pf = PF_INET;
  telnetFilterHook.priority = NF_IP_PRI_FIRST;*/
  
  netfilter_ops_out.hook = genericOutFilter;
  netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
  netfilter_ops_out.pf = PF_INET;
  netfilter_ops_out.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &netfilter_ops_out); 

  netfilter_ops_in.hook = genericInFilter;
  netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
  netfilter_ops_in.pf = PF_INET;
  netfilter_ops_in.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &netfilter_ops_in);
  
  /******************************************
  nf_register_hook(&telnetFilterHook);
   Need to change this as listed in the book
   for 12.04 version. The latest changes in 16.04
   are as below.
   nf_register_net_hook(&init_net, &telnetFilterHook); 
  *******************************************/
  return 0;
}

void removeFilter(void) {
  printk(KERN_INFO "Generic Ingress and Egress Filters are being removed");
  /**************************************************
  nf_unregister_hook(&telnetFilterHook);
   Need to change this signature as listed in the book
   for 12.04 version. The latest changes in 16.04 
   are as below
  nf_unregister_net_hook(&init_net, &telnetFilterHook);
  ***************************************************/
  // unregister hook function on Ubuntu 16.04 No need to define init_net 
  // structure as it is already in the netfilter.h header 
  nf_unregister_net_hook(&init_net, &netfilter_ops_in);
  nf_unregister_net_hook(&init_net, &netfilter_ops_out);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

